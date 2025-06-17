import serial
import time
import logging
from typing import List
from crc_calculator import calculate_crc_with_config, load_crc_config


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
        logging.FileHandler("reference_dex_protocol.log"),
        logging.StreamHandler()
    ]
)

def calculate_crc(data: List[int]) -> int:
    """Calculate CRC using parameters from config file."""
    return calculate_crc_with_config(data, 'crc_config.yaml')

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

        # Load CRC configuration
        self.crc_config = load_crc_config('crc_config.yaml')
        
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
        # Convert bytes to list of integers for CRC calculation
        data_list = list(data)
        crc_val = calculate_crc(data_list)
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
        
        # Process message bytes according to config (same approach as dex_session.py)
        if self.crc_config.get('data_processing') == "Raw Data":
            message_bytes = list(unstuffed_data)  # Use full message including DLE and SOH
            logging.info("Using raw data for CRC calculation (including DLE and SOH bytes)")
        else:
            message_bytes = [b for b in unstuffed_data if b != DLE[0] and b != 0x01]  # Filter out DLE and SOH
            logging.info("Filtering out DLE and SOH bytes for CRC calculation")
            
        calculated_crc = calculate_crc(message_bytes)

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
        Follows the same protocol flow as dex_session.py - waits for VMC to initiate.
        """
        try:
            self.ser = serial.Serial(self.port, self.baudrate, timeout=self.timeout)
            self.ser.reset_input_buffer()
            self.ser.reset_output_buffer()
            time.sleep(2)  # Allow time for the serial port to initialize
            logging.info(f"Serial port {self.port} opened successfully.")
        except serial.SerialException as e:
            logging.error(f"Failed to open serial port {self.port}: {e}")
            return False

        # --- First Handshake (VMC is MASTER, we respond) ---
        logging.info("--- Starting First Handshake (VMC as Master) ---")
        logging.info("Waiting for VMC to send ENQ... (Press F2 DEX button now)")
        
        # Wait for VMC to send ENQ (like dex_session.py does)
        enq_received = False
        start_time = time.time()
        while time.time() - start_time < 300:  # Wait for 5 minutes for ENQ
            if self.ser.in_waiting > 0:
                data = self.ser.read(1)
                logging.debug(f"<-- RECV: {data.hex(' ')} ({repr(data)})")
                if data == ENQ:
                    logging.info("First Handshake: ENQ received from VMC")
                    enq_received = True
                    break
        
        if not enq_received:
            logging.error("First Handshake: ENQ not received within timeout")
            self.ser.close()
            return False
            
        # Send ACK0 response
        self._send(ACK0)
        logging.info("First Handshake: Sent ACK0")
        
        time.sleep(0.05)  # Small delay after sending ACK0
        
        # Read the VMC's operation request message (like dex_session.py)
        logging.info("Reading VMC operation request message...")
        message = bytearray()
        while True:
            if self.ser.in_waiting > 0:
                byte = self.ser.read(1)
                logging.debug(f"<-- RECV: {byte.hex(' ')} ({repr(byte)})")
                message.append(byte[0])
                if len(message) >= 2 and message[-2:] == DLE + ETX:
                    break
                    
        # Read the 2-byte CRC
        crc_received = self.ser.read(2)
        logging.debug(f"<-- RECV CRC: {crc_received.hex(' ')} ({repr(crc_received)})")
        crc_received_value = int.from_bytes(crc_received, byteorder='little')
        full_message = message + crc_received
        logging.info(f"Full VMC message received: {full_message.hex()}")
        
        # Verify the received message format
        if not message.endswith(DLE + ETX):
            logging.error("First Handshake: Invalid message format received")
            self.ser.close()
            return False
            
        # Process message bytes according to config (same as dex_session.py)
        if self.crc_config.get('data_processing') == "Raw Data":
            message_bytes = list(message)  # Use full message including DLE and SOH
            logging.info("Using raw data for CRC calculation (including DLE and SOH bytes)")
        else:
            message_bytes = [b for b in message if b != DLE[0] and b != 0x01]  # Filter out DLE and SOH
            logging.info("Filtering out DLE and SOH bytes for CRC calculation")
            
        calculated_crc = calculate_crc(message_bytes)
        
        logging.info(f"Received CRC: {crc_received_value:04x}, Calculated CRC: {calculated_crc:04x}")
        logging.info(f"Message bytes for CRC calculation: {[hex(b) for b in message_bytes]}")
        
        if crc_received_value != calculated_crc:
            logging.error("First Handshake: CRC mismatch")
            self.ser.close()
            return False
            
        logging.info("CRC check passed!")
        
        # Parse VMC identity from the message (like dex_session.py)
        if len(message) >= 4 and message[0] == DLE[0] and message[1] == 0x01:  # DLE + SOH
            if message[-2:] == DLE + ETX:
                content = message[2:-2]  # Remove framing
                
                # Find the 'R' marker
                r_index = content.find(ord('R'))
                if r_index > 0:
                    comm_id = bytes(content[:r_index])
                    remaining = content[r_index+1:]  # Skip the 'R'
                    
                    # Next 2 bytes should be revision level
                    if len(remaining) >= 2:
                        rev_level = bytes(remaining[:2])
                        layer_info = bytes(remaining[2:])  # Everything else is layer info
                        
                        self.vmd_comm_id = comm_id.decode('ascii', errors='ignore')
                        logging.info(f"VMC Communication ID: '{comm_id.decode('ascii', errors='ignore')}'")
                        logging.info(f"VMC Revision Level: '{rev_level.decode('ascii', errors='ignore')}'")
                        logging.info(f"VMC Layer Info: '{layer_info.decode('ascii', errors='ignore')}'")
        
        # Send ACK1 to complete first handshake
        self._send(ACK1)
        logging.info("First Handshake: Sent ACK1")
        
        # Wait for EOT
        logging.info("Waiting for EOT...")
        eot_received = False
        start_time = time.time()
        while time.time() - start_time < 5:  # Wait for 5 seconds for EOT
            if self.ser.in_waiting > 0:
                data = self.ser.read(1)
                logging.debug(f"<-- RECV: {data.hex(' ')} ({repr(data)})")
                if data == EOT:
                    logging.info("First Handshake: EOT received")
                    eot_received = True
                    break
                    
        if not eot_received:
            logging.error("First Handshake: EOT not received")
            self.ser.close()
            return False
            
        time.sleep(0.05)  # Small delay
        logging.info("--- First Handshake Succeeded ---")

        # --- Second Handshake (We are MASTER now, like dex_session.py) ---
        logging.info("--- Starting Second Handshake (DC as Master) ---")
        self._send(ENQ)
        logging.info("Second Handshake: Sent ENQ")
        
        # Wait for ACK0
        ack_received = False
        start_time = time.time()
        while time.time() - start_time < 5:  # Wait for 5 seconds for ACK
            if self.ser.in_waiting > 0:
                data = self.ser.read(self.ser.in_waiting)  # Read all available bytes
                logging.debug(f"<-- RECV: {data.hex(' ')} ({repr(data)})")
                
                # Check if we have ACK0
                if ACK0 in data:
                    logging.info("Second Handshake: ACK0 received")
                    ack_received = True
                    break
                    
        if not ack_received:
            logging.error("Second Handshake: ACK0 not received")
            self.ser.close()
            return False
            
        # Send our DDC identity (try one format and get detailed diagnostics)
        logging.info("DEX UCS Protocol Requirements:")
        logging.info("- Communication ID: 10-digit code from GS1") 
        logging.info("- VMC expects valid registered Communication ID")
        
        success = self._send_ddc_identity_and_diagnose()
        if not success:
            logging.error("Check diagnostic logs above for VMC response details")
            self.ser.close()
            return False
             
        logging.info("--- Second Handshake Succeeded ---")
        self.is_connected = True
        return True

    def _send_ddc_identity_and_diagnose(self):
        """Send DDC identity and capture detailed diagnostic information from VMC response."""
        # Try standard 10-digit format first
        comm_id = b'0000000001'
        rev_level = b'01'
        
        logging.info(f"ATTEMPT: Trying 10-digit format")
        logging.info(f"Communication ID: '{comm_id.decode('ascii', errors='ignore')}'")
        logging.info(f"Revision Level: '{rev_level.decode('ascii', errors='ignore')}'")
        
        # Build message content according to DEX UCS spec
        message_content = comm_id + b'R' + rev_level
        message = DLE + b'\x01' + message_content + DLE + ETX  # DLE + SOH + content + DLE + ETX
        
        logging.info(f"Message content: '{message_content.decode('ascii', errors='ignore')}'")
        logging.info(f"Message framed: {message.hex()}")
        
        # Calculate CRC using same approach as dex_session.py
        if self.crc_config.get('data_processing') == "Raw Data":
            message_bytes = list(message)
        else:
            message_bytes = [b for b in message if b != DLE[0] and b != 0x01]
            
        crc = calculate_crc(message_bytes)
        crc_bytes = crc.to_bytes(2, 'little')
        
        logging.info(f"Calculated CRC: {crc:04x} (bytes: {crc_bytes.hex()})")
        
        # Send the message and analyze it
        full_message = message + crc_bytes
        send_interpretation = log_frame_interpretation(full_message, "SEND", logging)
        self._send(full_message)
        
        # Store diagnostic information
        diagnostic_info = {
            "send_frame": send_interpretation,
            "responses": [],
            "final_decision": None
        }
        
        # Wait for response and capture ALL diagnostic information with detailed timing
        logging.info("Waiting for VMC response to DDC identity...")
        start_time = time.time()
        received_data = bytearray()
        response_count = 0
        byte_timestamps = []
        
        # Enhanced data collection - read systematically for up to 10 seconds
        while time.time() - start_time < 10:  # Extended timeout for complete message
            if self.ser.in_waiting > 0:
                # Read one byte at a time to capture timing
                byte_data = self.ser.read(1)
                if byte_data:
                    received_data.extend(byte_data)
                    response_count += 1
                    timestamp = time.time() - start_time
                    byte_timestamps.append(timestamp)
                    
                    logging.info(f"<-- BYTE {response_count} at {timestamp:.3f}s: {byte_data.hex().upper()} (0x{byte_data[0]:02X})")
                    
                    # Check if we have a complete Enhanced DDCMP message (8 bytes starting with 0x05)
                    if len(received_data) == 1 and received_data[0] == 0x05:
                        logging.info("Detected start of Enhanced DDCMP control message (0x05) - collecting remaining 7 bytes...")
                    elif len(received_data) == 8 and received_data[0] == 0x05:
                        logging.info("Complete 8-byte Enhanced DDCMP message received!")
                        break
                    # Check for simple single-byte responses
                    elif len(received_data) == 1 and received_data[0] in [0x15, 0x06]:  # NAK or ACK
                        logging.info(f"Single-byte control character detected: 0x{received_data[0]:02X}")
                        # Wait longer to see if more bytes follow
                        logging.info("Waiting additional time to check for multi-byte message...")
                        extended_wait_start = time.time()
                        while time.time() - extended_wait_start < 2.0:  # Wait 2 more seconds
                            if self.ser.in_waiting > 0:
                                additional_byte = self.ser.read(1)
                                if additional_byte:
                                    received_data.extend(additional_byte)
                                    response_count += 1
                                    timestamp = time.time() - start_time
                                    byte_timestamps.append(timestamp)
                                    logging.info(f"<-- BYTE {response_count} at {timestamp:.3f}s: {additional_byte.hex().upper()} (0x{additional_byte[0]:02X})")
                            time.sleep(0.01)
                        
                        if len(received_data) == 1:
                            logging.info("No additional bytes received - confirmed single-byte response")
                        break
                    
                # Continue reading if we have partial data
                continue
            time.sleep(0.001)  # Very short sleep to avoid busy waiting
        
        # Comprehensive timing and structure analysis
        logging.info("=== DETAILED MESSAGE ANALYSIS ===")
        logging.info(f"Total bytes received: {len(received_data)}")
        logging.info(f"Total time span: {byte_timestamps[-1] if byte_timestamps else 0:.3f} seconds")
        logging.info(f"Complete message hex: {received_data.hex().upper()}")
        
        # Byte-by-byte breakdown with timing
        for i, (byte_val, timestamp) in enumerate(zip(received_data, byte_timestamps)):
            logging.info(f"  Byte {i+1}: 0x{byte_val:02X} at {timestamp:.3f}s")
        
        # Analyze message structure based on length and content
        if len(received_data) == 0:
            logging.warning("No response received from VMC")
            diagnostic_info["final_decision"] = "NO_RESPONSE"
            result = False
        elif len(received_data) == 1:
            single_byte = received_data[0]
            logging.info("Single-byte response analysis:")
            if single_byte == 0x15:
                logging.info("  Response: Simple NAK (0x15) - Basic negative acknowledge")
                logging.info("  Protocol: Basic DEX protocol (not Enhanced DDCMP)")
                diagnostic_info["final_decision"] = "REJECTED_SIMPLE_NAK"
                result = False
            elif single_byte == 0x06:
                logging.info("  Response: Simple ACK (0x06) - Basic acknowledge")
                diagnostic_info["final_decision"] = "ACCEPTED_SIMPLE_ACK"
                result = True
            else:
                logging.info(f"  Response: Unknown single byte (0x{single_byte:02X})")
                diagnostic_info["final_decision"] = f"UNKNOWN_SINGLE_0x{single_byte:02X}"
                result = False
        elif len(received_data) == 2 and received_data[0] == 0x10:
            logging.info("Two-byte DLE sequence analysis:")
            if received_data == b'\x10\x31':  # DLE + '1'
                logging.info("  Response: DLE ACK1 (0x10 0x31) - Sequence acknowledge")
                diagnostic_info["final_decision"] = "ACCEPTED_DLE_ACK1"
                result = True
            else:
                logging.info(f"  Response: DLE sequence (0x10 0x{received_data[1]:02X})")
                diagnostic_info["final_decision"] = f"DLE_SEQUENCE_0x{received_data[1]:02X}"
                result = False
        elif len(received_data) == 8 and received_data[0] == 0x05:
            logging.info("Enhanced DDCMP control message analysis:")
            # Perform full Enhanced DDCMP interpretation
            enhanced_interpretation = interpret_dex_frame(bytes(received_data))
            logging.info(f"  Enhanced DDCMP details: {enhanced_interpretation}")
            if enhanced_interpretation.get('frame_type') == 'NACK_ENHANCED':
                diagnostic_info["final_decision"] = "REJECTED_ENHANCED_NACK"
                result = False
            else:
                diagnostic_info["final_decision"] = "ENHANCED_DDCMP_OTHER"
                result = False
        else:
            logging.info(f"Multi-byte response analysis ({len(received_data)} bytes):")
            # Interpret as best we can
            interpretation = interpret_dex_frame(bytes(received_data))
            logging.info(f"  Frame interpretation: {interpretation}")
            diagnostic_info["final_decision"] = f"MULTI_BYTE_{len(received_data)}"
            result = False
        
        # Store diagnostic info as instance variable for later analysis
        diagnostic_info["byte_timing"] = list(zip(received_data, byte_timestamps))
        diagnostic_info["final_interpretation"] = interpret_dex_frame(bytes(received_data))
        self.last_diagnostic_info = diagnostic_info
        
        logging.info("=== END DETAILED MESSAGE ANALYSIS ===")
        return result

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

def interpret_dex_frame(frame_bytes):
    """
    Interpret DEX/UCS protocol control frames and data messages.
    
    Parameters:
    frame_bytes (bytes): The received frame bytes
    
    Returns:
    dict: Dictionary containing the interpreted frame information
    """
    if not frame_bytes:
        return {"error": "Empty frame"}
        
    result = {
        "frame_type": None,
        "frame_length": len(frame_bytes),
        "raw_hex": frame_bytes.hex(),
        "description": None,
        "details": {}
    }
    
    # Single byte control characters
    if len(frame_bytes) == 1:
        byte = frame_bytes[0]
        if byte == 0x05:
            result["frame_type"] = "ENQ"
            result["description"] = "Enquiry - Request for communication"
        elif byte == 0x04:
            result["frame_type"] = "EOT" 
            result["description"] = "End of Transmission - Session termination"
        elif byte == 0x15:
            result["frame_type"] = "NAK_SIMPLE"
            result["description"] = "Simple Negative Acknowledge - Message rejected"
            result["details"]["note"] = "Single-byte NAK format (not Enhanced DDCMP)"
        elif byte == 0x06:
            result["frame_type"] = "ACK"
            result["description"] = "Acknowledge - Simple acknowledgment"
        else:
            result["frame_type"] = "UNKNOWN_SINGLE"
            result["description"] = f"Unknown single-byte control: 0x{byte:02x}"
            
    # Two byte DLE sequences
    elif len(frame_bytes) == 2 and frame_bytes[0] == 0x10:
        dle_char = frame_bytes[1]
        if dle_char == 0x30:  # DLE + '0'
            result["frame_type"] = "ACK0"
            result["description"] = "DLE ACK0 - Acknowledge with sequence 0"
        elif dle_char == 0x31:  # DLE + '1'
            result["frame_type"] = "ACK1" 
            result["description"] = "DLE ACK1 - Acknowledge with sequence 1"
        elif dle_char == 0x3B:  # DLE + ';'
            result["frame_type"] = "WACK"
            result["description"] = "Wait Acknowledge - Busy, try again"
        else:
            result["frame_type"] = "DLE_SEQUENCE"
            result["description"] = f"DLE sequence: DLE + 0x{dle_char:02x}"
            
    # Enhanced DDCMP Control Messages (8 bytes)
    elif len(frame_bytes) == 8 and frame_bytes[0] == 0x05:
        result["frame_type"] = "ENHANCED_DDCMP_CONTROL"
        result["description"] = "Enhanced DDCMP Control Frame"
        
        # Parse control message type from byte 2
        if frame_bytes[1] == 0x06:
            result["details"]["control_type"] = "START"
        elif frame_bytes[1] == 0x07:
            result["details"]["control_type"] = "STACK" 
        elif frame_bytes[1] == 0x01:
            result["details"]["control_type"] = "ACK"
        elif frame_bytes[1] == 0x02:
            result["details"]["control_type"] = "NACK"
            result["frame_type"] = "NACK_ENHANCED"
            result["description"] = "Enhanced DDCMP NACK with error code"
            
            # Parse error code from byte 3 (least significant 6 bits)
            error_code = frame_bytes[2] & 0x3F  # Extract bits 0-5
            result["details"]["error_code"] = error_code
            
            # Interpret error codes according to standard
            if error_code == 1:
                result["details"]["error_description"] = "Header block check error (CRC16 error in Control/Data Message Header)"
                result["details"]["error_category"] = "Transmission medium error"
            elif error_code == 2:
                result["details"]["error_description"] = "Data field block check error (CRC16 error in Command Message/Response or Data Message)"
                result["details"]["error_category"] = "Transmission medium error"
            elif error_code == 3:
                result["details"]["error_description"] = "REP response (not used in Enhanced DDCMP)"
                result["details"]["error_category"] = "Transmission medium error"
            elif error_code == 8:
                result["details"]["error_description"] = "Buffer temporarily unavailable"
                result["details"]["error_category"] = "Computer/interface error"
            elif error_code == 9:
                result["details"]["error_description"] = "Receive overrun"
                result["details"]["error_category"] = "Computer/interface error"
            elif error_code == 16:
                result["details"]["error_description"] = "Message too long"
                result["details"]["error_category"] = "Computer/interface error"
            elif error_code == 17:
                result["details"]["error_description"] = "Message header format error"
                result["details"]["error_category"] = "Computer/interface error"
            else:
                result["details"]["error_description"] = f"Unknown error code: {error_code}"
                result["details"]["error_category"] = "Unknown"
        
        # Parse additional fields from Enhanced DDCMP control frame
        result["details"]["select_flag"] = (frame_bytes[2] & 0x80) >> 7  # Bit 7
        result["details"]["quick_sync_flag"] = (frame_bytes[2] & 0x40) >> 6  # Bit 6
        result["details"]["rx_number"] = frame_bytes[3]  # Number of last message received OK
        result["details"]["slave_address"] = frame_bytes[5] if len(frame_bytes) > 5 else None
            
    # Multi-byte data frames with DLE framing
    elif len(frame_bytes) > 2 and frame_bytes[0] == 0x10:
        if frame_bytes[1] == 0x01:  # DLE + SOH
            result["frame_type"] = "DATA_FRAME"
            result["description"] = "Data frame with DLE+SOH framing"
            
            # Look for DLE+ETX or DLE+ETB ending
            if len(frame_bytes) >= 4:
                for i in range(2, len(frame_bytes)-1):
                    if frame_bytes[i] == 0x10:
                        if frame_bytes[i+1] == 0x03:  # DLE + ETX
                            result["details"]["ending"] = "DLE+ETX (final block)"
                            result["details"]["data_length"] = i - 2
                            if len(frame_bytes) >= i + 4:  # Has CRC
                                crc_bytes = frame_bytes[i+2:i+4]
                                result["details"]["crc"] = crc_bytes.hex()
                                result["details"]["crc_value"] = int.from_bytes(crc_bytes, 'little')
                            break
                        elif frame_bytes[i+1] == 0x17:  # DLE + ETB
                            result["details"]["ending"] = "DLE+ETB (intermediate block)"
                            result["details"]["data_length"] = i - 2
                            if len(frame_bytes) >= i + 4:  # Has CRC
                                crc_bytes = frame_bytes[i+2:i+4]
                                result["details"]["crc"] = crc_bytes.hex()
                                result["details"]["crc_value"] = int.from_bytes(crc_bytes, 'little')
                            break
                            
                # Extract data content (between DLE+SOH and DLE+ETX/ETB)
                if "data_length" in result["details"]:
                    data_content = frame_bytes[2:2+result["details"]["data_length"]]
                    try:
                        ascii_content = data_content.decode('ascii', errors='ignore')
                        result["details"]["content"] = ascii_content
                        result["details"]["content_hex"] = data_content.hex()
                    except:
                        result["details"]["content_hex"] = data_content.hex()
                        
        elif frame_bytes[1] == 0x02:  # DLE + STX
            result["frame_type"] = "CONTROL_FRAME"
            result["description"] = "Control frame with DLE+STX framing"
    else:
        result["frame_type"] = "UNKNOWN_MULTI"
        result["description"] = f"Unknown multi-byte frame starting with 0x{frame_bytes[0]:02x}"
        
        # Check if this might be a truncated Enhanced DDCMP frame
        if frame_bytes[0] == 0x05 and len(frame_bytes) < 8:
            result["details"]["possible_truncated"] = f"May be truncated Enhanced DDCMP control frame (expected 8 bytes, got {len(frame_bytes)})"
        
    return result

def log_frame_interpretation(frame_bytes, direction="RECV", logger=None):
    """Log detailed interpretation of a DEX frame."""
    if not logger:
        logger = logging
        
    interpretation = interpret_dex_frame(frame_bytes)
    
    logger.info(f"=== {direction} FRAME ANALYSIS ===")
    logger.info(f"Complete Result Dictionary:")
    logger.info(f"{interpretation}")
    logger.info("=== END FRAME ANALYSIS ===")
    
    return interpretation

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
    VENDING_MACHINE_PORT = '/dev/cu.usbmodem5B43E73635381'  # Your actual port
    
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