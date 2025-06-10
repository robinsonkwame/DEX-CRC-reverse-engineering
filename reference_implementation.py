import serial
import time
import logging
from crc_calculator import CrcCalculator, Crc16

# --- Constants for DEX/UCS Protocol ---
# These control characters govern the communication flow.
# Sourced from EVA DTS 6.1.2, page 107.
ENQ = b'\x05'  # Enquire - Master uses this to request a response
EOT = b'\x04'  # End of Transmission - Indicates the end of a session
DLE = b'\x10'  # Data Link Escape - Used to frame data and acknowledge
STX = b'\x02'  # Start of Text - Marks the beginning of a data block
ETX = b'\x03'  # End of Text - Marks the end of the final data block
ETB = b'\x17'  # End of Transmission Block - Marks the end of an intermediate data block

# Timer constants (in seconds)
TIMER_A = 1.0    # Response timeout
TIMER_B = 0.1    # Block continuation timeout
TIMER_D = 2.0    # Session timeout

# Retry limits
MAX_START_ATTEMPTS = 10
MAX_DATA_TRANSFER_ATTEMPTS = 5

# Maximum block size (bytes)
MAX_BLOCK_SIZE = 245

# Acknowledgment sequences (DLE + character)
ACK0 = DLE + b'0' # DLE 0 (0x10 0x30)
ACK1 = DLE + b'1' # DLE 1 (0x10 0x31)
WACK = DLE + b';' # DLE ; (0x10 0x3B) - Wait Acknowledge
NAK  = b'\x15'    # Negative Acknowledge

# --- Setup Detailed Logging ---
# This is crucial for debugging the protocol.
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("dex_protocol.log"),
        logging.StreamHandler()
    ]
)

class DEXSession:
    """
    Manages a DEX/UCS communication session with a vending machine.
    Handles connection, handshaking, data transfer, and CRC validation.
    """

    def __init__(self, port, baudrate=9600, timeout=2.0):
        """
        Initializes the DEX session handler.
        :param port: The serial port name (e.g., 'COM3' or '/dev/ttyUSB0').
        :param baudrate: The communication speed (9600 for DEX).
        :param timeout: The read timeout in seconds.
        """
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.ser = None
        self.is_connected = False
        self.vmd_comm_id = None # Vending Machine Device Comm ID
        self.dc_comm_id = "PYDTS12345" # Data Collector (our) Comm ID

        # CRC calculator setup for CRC-16/ARC
        self.crc_calculator = CrcCalculator(Crc16.ARC)
        logging.info(f"DEXSession initialized for port {port} at {baudrate} baud.")

    def _send(self, data: bytes):
        """Low-level send with logging and required delay."""
        time.sleep(0.01)  # Minimum 10ms delay before sending (spec requirement)
        logging.debug(f"--> SEND: {data.hex(' ')} ({repr(data)})")
        self.ser.write(data)

    def _read_with_timeout(self, num_bytes=1, timeout=TIMER_A) -> bytes:
        """Read with configurable timeout."""
        original_timeout = self.ser.timeout
        self.ser.timeout = timeout
        response = self.ser.read(num_bytes)
        self.ser.timeout = original_timeout
        
        if response:
            logging.debug(f"<-- RECV: {response.hex(' ')} ({repr(response)})")
        else:
            logging.warning(f"<-- RECV: Timeout after {timeout} seconds")
        return response

    def _handle_wack(self, max_retries=3):
        """Handle WACK response with retries."""
        for attempt in range(max_retries):
            if attempt > 0:
                logging.info(f"WACK retry attempt {attempt + 1}/{max_retries}")
            time.sleep(0.1)  # Wait 100ms before retry
            return True
        return False

    def _send_control_frame(self, data: bytes):
        """
        Sends a control frame (like a handshake) with DLE/STX framing and CRC.
        The data inside is NOT DLE-stuffed as it's a control frame.
        """
        crc_val = self.crc_calculator.calculate_checksum(data)
        crc_bytes = crc_val.to_bytes(2, byteorder='little') # LSB first
        
        frame = DLE + STX + data + DLE + ETX + crc_bytes
        logging.info(f"Constructed control frame. Data: {repr(data)}, CRC: {crc_bytes.hex(' ')}")
        self._send(frame)

    def _read_and_validate_block(self) -> (bytes, bool):
        """
        Reads a full data block from the VMD, performs DLE unstuffing,
        and validates the CRC.
        :return: A tuple of (unstuffed_data, is_final_block).
                 Returns (None, False) on CRC error or timeout.
        """
        # Find the start of the block
        while self._read_with_timeout() != DLE:
            pass # Wait for DLE
        
        start_char = self._read_with_timeout()
        if start_char != STX:
            logging.error(f"Expected STX after DLE, but got {start_char.hex()}")
            return None, False

        logging.info("STX received, starting data block read.")
        raw_frame = bytearray()
        unstuffed_data = bytearray()
        
        # Read until we find the end-of-block DLE
        while True:
            char = self._read_with_timeout()
            if not char: return None, False # Timeout
            raw_frame.append(char[0])

            if char == DLE:
                next_char = self._read_with_timeout()
                if not next_char: return None, False # Timeout
                raw_frame.append(next_char[0])

                if next_char == DLE: # DLE stuffing
                    unstuffed_data.append(DLE[0])
                elif next_char in (ETX, ETB):
                    is_final_block = (next_char == ETX)
                    logging.info(f"End of block detected: {'ETX' if is_final_block else 'ETB'}")
                    break
                else:
                    logging.error(f"Unexpected character after DLE: {next_char.hex()}")
                    return None, False
            else:
                unstuffed_data.append(char[0])

        # Read the 2-byte CRC
        received_crc_bytes = self._read_with_timeout(2)
        if len(received_crc_bytes) < 2:
            logging.error("Failed to read full 2-byte CRC.")
            return None, False
        
        received_crc = int.from_bytes(received_crc_bytes, 'little')
        calculated_crc = self.crc_calculator.calculate_checksum(unstuffed_data)

        logging.info(f"Unstuffed Data: {repr(unstuffed_data.decode('ascii', 'ignore'))}")
        logging.info(f"Received CRC: {received_crc:04X}, Calculated CRC: {calculated_crc:04X}")

        if received_crc == calculated_crc:
            logging.info("CRC check PASSED.")
            return bytes(unstuffed_data), is_final_block
        else:
            logging.error("CRC check FAILED.")
            return None, False

    def connect(self):
        """
        Opens the serial port and performs the full two-stage DEX handshake.
        Implements retry logic as per spec.
        """
        try:
            self.ser = serial.Serial(self.port, self.baudrate, timeout=self.timeout)
            logging.info(f"Serial port {self.port} opened successfully.")
        except serial.SerialException as e:
            logging.error(f"Failed to open serial port {self.port}: {e}")
            return False

        # --- First Handshake (We are MASTER) ---
        for attempt in range(MAX_START_ATTEMPTS):
            logging.info(f"--- Starting First Handshake (DC as Master) - Attempt {attempt + 1}/{MAX_START_ATTEMPTS} ---")
            self.ser.flushInput()
            self.ser.flushOutput()
            self._send(ENQ)
            
            response = self._read_with_timeout(2)
            if response == WACK:
                if not self._handle_wack():
                    continue
            elif response != ACK0:
                logging.error(f"First Handshake: Did not receive ACK0. Got: {response.hex(' ')}")
                if attempt < MAX_START_ATTEMPTS - 1:
                    continue
                self.ser.close()
                return False
            logging.info("First Handshake: ACK0 received.")

            # Send our info: Comm ID, Operation 'R' (Read), Revision/Level
            handshake_data = f"{self.dc_comm_id}R00L06".encode('ascii')
            self._send_control_frame(handshake_data)

            response = self._read_with_timeout(2)
            if response == WACK:
                if not self._handle_wack():
                    continue
            elif response != ACK1:
                logging.error(f"First Handshake: Did not receive ACK1. Got: {response.hex(' ')}")
                if attempt < MAX_START_ATTEMPTS - 1:
                    continue
                self.ser.close()
                return False
            logging.info("First Handshake: ACK1 received.")
            logging.info("--- First Handshake Succeeded ---")
            break
        else:
            logging.error("Failed to complete first handshake after maximum attempts")
            self.ser.close()
            return False
        
        time.sleep(0.2) # Intersession pause

        # --- Second Handshake (VMD is MASTER) ---
        logging.info("--- Starting Second Handshake (VMD as Master) ---")
        logging.info("Waiting for VMD to send ENQ...")
        
        # VMD will now initiate
        response = self._read_with_timeout(timeout=TIMER_D)
        if response != ENQ:
            logging.error(f"Second Handshake: Did not receive ENQ. Got: {response.hex(' ')}")
            self.ser.close()
            return False
        logging.info("Second Handshake: ENQ received from VMD.")
        self._send(ACK0)

        # Read VMD's control frame
        vmd_frame, _ = self._read_and_validate_block()
        if not vmd_frame:
            logging.error("Second Handshake: Failed to read VMD's control frame.")
            self.ser.close()
            return False
        
        # Parse the VMD's response
        # Format: ResponseCode(2), CommID(10), RevLevel(6)
        response_code = vmd_frame[0:2].decode()
        self.vmd_comm_id = vmd_frame[2:12].decode()
        rev_level = vmd_frame[12:].decode()
        logging.info(f"VMD Response: Code='{response_code}', CommID='{self.vmd_comm_id}', Rev='{rev_level}'")
        
        if response_code != "00":
            logging.error(f"VMD responded with non-OK status: {response_code}")
            self.ser.close()
            return False
            
        self._send(ACK1)
        
        response = self._read_with_timeout(timeout=TIMER_D)
        if response != EOT:
            logging.warning(f"Second Handshake: Expected EOT, got {response.hex(' ')}")
        
        logging.info("--- Second Handshake Succeeded ---")
        self.is_connected = True
        return True

    def read_audit_data(self):
        """
        Executes the data transfer phase to read the audit data.
        Implements retry logic and block size validation as per spec.
        """
        if not self.is_connected:
            logging.error("Cannot read audit data: not connected. Please run connect() first.")
            return None

        for attempt in range(MAX_DATA_TRANSFER_ATTEMPTS):
            logging.info(f"--- Starting Data Transfer Phase (VMD as Sender) - Attempt {attempt + 1}/{MAX_DATA_TRANSFER_ATTEMPTS} ---")
            logging.info("Waiting for VMD to send ENQ to start data dump...")
            
            response = self._read_with_timeout(timeout=TIMER_D)
            if response != ENQ:
                logging.error(f"Data Transfer: Did not receive initial ENQ. Got: {response.hex(' ')}")
                if attempt < MAX_DATA_TRANSFER_ATTEMPTS - 1:
                    continue
                return None
            
            full_data = bytearray()
            ack_to_send = ACK0 # Start with ACK0, then alternate

            while True:
                self._send(ack_to_send)
                block_data, is_final = self._read_and_validate_block()
                
                if block_data is None:
                    logging.error("Aborting data transfer due to block read error.")
                    # Send NAK to signal an error to the VMD
                    self._send(NAK)
                    if attempt < MAX_DATA_TRANSFER_ATTEMPTS - 1:
                        break  # Try again from the start
                    return None
                
                # Validate block size
                if len(block_data) > MAX_BLOCK_SIZE:
                    logging.error(f"Block size {len(block_data)} exceeds maximum allowed size of {MAX_BLOCK_SIZE}")
                    self._send(NAK)
                    if attempt < MAX_DATA_TRANSFER_ATTEMPTS - 1:
                        break  # Try again from the start
                    return None
                
                full_data.extend(block_data)
                
                if is_final:
                    logging.info("Final block received.")
                    break # Exit loop after processing the final block

                # Alternate the ACK for the next block
                ack_to_send = ACK1 if ack_to_send == ACK0 else ACK0

            # If we got here without errors, we're done
            break
        else:
            logging.error("Failed to complete data transfer after maximum attempts")
            return None

        # Send EOT to formally end the session
        self._send(EOT)
        logging.info("--- Data Transfer Complete ---")
        return full_data.decode('ascii', 'ignore')

    def close(self):
        """Closes the serial connection if it's open."""
        if self.ser and self.ser.is_open:
            self.ser.close()
            logging.info(f"Serial port {self.port} closed.")
            self.is_connected = False
            
def parse_eva_dts_data(raw_data: str):
    """
    A simple parser to convert the raw, asterisk-delimited data string
    into a more usable Python structure (list of dictionaries).
    """
    if not raw_data:
        return []
    
    parsed = []
    lines = raw_data.strip().split('\r\n')
    for line in lines:
        parts = line.split('*')
        if not parts:
            continue
        
        record = {
            "segment_id": parts[0],
            "data": parts[1:]
        }
        parsed.append(record)
        logging.info(f"Parsed Line: ID={record['segment_id']}, Data={record['data']}")
    return parsed


if __name__ == '__main__':
    # --- Main Execution Logic ---
    # To run this without a real vending machine, you need a virtual serial port pair.
    # On Linux: `socat -d -d pty,raw,echo=0 pty,raw,echo=0`
    # This will create two ports like /dev/pts/2 and /dev/pts/3.
    # On Windows: Use a tool like `com0com`.
    #
    # Then run this script with PORT_A, and run the `mock_vending_machine.py`
    # script (in a separate terminal) with PORT_B.
    
    # --- CONFIGURATION ---
    # Replace with your actual or virtual serial port
    VENDING_MACHINE_PORT = 'COM3' # or '/dev/pts/2'
    
    dex_session = DEXSession(VENDING_MACHINE_PORT)
    
    try:
        if dex_session.connect():
            logging.info("Handshake successful. Proceeding to read audit data.")
            
            audit_data_string = dex_session.read_audit_data()
            
            if audit_data_string:
                logging.info("\n--- RAW AUDIT DATA DUMP ---")
                print(audit_data_string)
                logging.info("--- END RAW AUDIT DATA DUMP ---\n")
                
                logging.info("\n--- PARSED AUDIT DATA ---")
                parsed_data = parse_eva_dts_data(audit_data_string)
                for item in parsed_data:
                    print(item)
                logging.info("--- END PARSED AUDIT DATA ---\n")
            else:
                logging.error("Failed to retrieve audit data.")
        else:
            logging.error("Failed to connect to the vending machine.")

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
    finally:
        dex_session.close()