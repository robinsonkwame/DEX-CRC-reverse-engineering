from enum import Enum, auto
from typing import List, Optional, Tuple
import logging
import sys
import time
from serial_connection import SerialConnection

# Control characters
DLE = 0x10
SOH = 0x01
STX = 0x02
ETX = 0x03
EOT = 0x04
ENQ = 0x05
ACK = 0x06
NAK = 0x15

class DEXState(Enum):
    IDLE = auto()
    WAITING_FOR_FIRST_ENQ = auto()
    WAITING_FOR_ACK_RESPONSE = auto()
    WAITING_FOR_EOT_AFTER_COMM_ID = auto()
    READY_FOR_SECOND_HANDSHAKE = auto()
    ERROR = auto()

class DEXStateMachine:
    def __init__(self, serial_conn: SerialConnection):
        self.state = DEXState.IDLE
        self.buffer: List[int] = []
        self.logger = logging.getLogger(__name__)
        self.serial_conn = serial_conn
        self.vmc_comm_id: Optional[bytes] = None
        self.vmc_revision: Optional[bytes] = None

    def start_handshake(self) -> bool:
        """Start the DEX handshake process."""
        self.logger.info("Starting DEX handshake process...")
        
        # Reset buffers
        self.serial_conn.reset_buffers()
        
        # Wait for 2 seconds
        self.logger.info("Waiting 2 seconds for vending machine to stabilize...")
        time.sleep(2)
        
        # Set state to wait for first ENQ
        self.state = DEXState.WAITING_FOR_FIRST_ENQ
        self.logger.info("Ready to receive first ENQ from vending machine")
        return True

    def calculate_crc16_dex_custom(self, data: List[int], initial_value: int = 0x0000) -> int:
        """Calculate CRC16 using DEX custom algorithm."""
        crc = initial_value
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc = crc >> 1
        return crc

    def calculate_crc(self, data: List[int]) -> int:
        """Calculate CRC with final XOR as per README specifications."""
        crc = self.calculate_crc16_dex_custom(data)
        return crc ^ 0x0D4D

    def format_message(self, data: List[int]) -> List[int]:
        """Format message with DLE escaping and CRC."""
        message = [DLE, SOH] + data + [DLE, ETX]
        crc = self.calculate_crc(message)
        # Add CRC in little-endian
        message.extend([crc & 0xFF, (crc >> 8) & 0xFF])
        return message

    def handle_first_enq(self) -> bool:
        """Handle initial ENQ from vending machine."""
        if self.state == DEXState.WAITING_FOR_FIRST_ENQ:
            self.logger.info("Received first ENQ, sending DLE+ACK0")
            # Send DLE+ACK0 (DLE followed by '0')
            response = [DLE, 0x30]  # DLE+ACK0
            if self.serial_conn.write_bytes(bytes(response)):
                self.state = DEXState.WAITING_FOR_ACK_RESPONSE
                self.logger.info("State transition to WAITING_FOR_ACK_RESPONSE")
                return True
            else:
                self.logger.error("Failed to send DLE+ACK0")
                self.state = DEXState.ERROR
        return False

    def process_comm_id_response(self, data: List[int]) -> bool:
        """Process VMC communication ID response."""
        self.logger.info(f"Processing comm ID response: {' '.join([f'0x{b:02x}' for b in data])}")
        
        if len(data) < 23:  # Minimum length for a valid comm ID response
            self.logger.error(f"Invalid comm ID response length: {len(data)}")
            return False

        # Verify frame structure
        if not (data[0] == DLE and data[1] == SOH and data[-3] == DLE and data[-2] == ETX):
            self.logger.error("Invalid frame structure in comm ID response")
            self.logger.error(f"Expected DLE+SOH at start, got: 0x{data[0]:02x} 0x{data[1]:02x}")
            self.logger.error(f"Expected DLE+ETX at end, got: 0x{data[-3]:02x} 0x{data[-2]:02x}")
            return False

        # Verify CRC
        received_crc = (data[-1] << 8) | data[-2]  # Little-endian
        calculated_crc = self.calculate_crc(data[:-2])
        
        if received_crc != calculated_crc:
            self.logger.error(f"CRC mismatch: received {hex(received_crc)}, calculated {hex(calculated_crc)}")
            return False

        # Extract VMC Communication ID (bytes 2-9) and Revision Level (bytes 11-18)
        try:
            self.vmc_comm_id = bytes(data[2:10])
            self.vmc_revision = bytes(data[11:19])
            self.logger.info(f"Received VMC Comm ID: {self.vmc_comm_id.decode('ascii')}")
            self.logger.info(f"Received VMC Revision: {self.vmc_revision.decode('ascii')}")
            
            # Send DLE+ACK1
            response = [DLE, 0x31]  # DLE+ACK1
            self.logger.info(f"Sending DLE+ACK1: {' '.join([f'0x{b:02x}' for b in response])}")
            if self.serial_conn.write_bytes(bytes(response)):
                self.state = DEXState.WAITING_FOR_EOT_AFTER_COMM_ID
                self.logger.info("State transition to WAITING_FOR_EOT_AFTER_COMM_ID")
                return True
            else:
                self.logger.error("Failed to send DLE+ACK1")
                self.state = DEXState.ERROR
        except Exception as e:
            self.logger.error(f"Error processing comm ID response: {str(e)}")
            self.state = DEXState.ERROR
            return False

    def handle_byte(self, byte: int) -> None:
        """Handle incoming byte and update state machine."""
        self.logger.info(f"Received byte: 0x{byte:02x} (State: {self.state.name})")
        
        if byte == ENQ and self.state == DEXState.WAITING_FOR_FIRST_ENQ:
            self.handle_first_enq()
        elif byte == DLE:
            self.logger.info("Starting new DLE sequence")
            self.buffer = [byte]
        elif self.buffer and self.buffer[0] == DLE:
            self.buffer.append(byte)
            self.logger.info(f"Buffer contents: {' '.join([f'0x{b:02x}' for b in self.buffer])}")
            
            if byte == ETX and self.state == DEXState.WAITING_FOR_ACK_RESPONSE:
                self.logger.info("Received ETX, processing comm ID response")
                if self.process_comm_id_response(self.buffer):
                    self.buffer = []
                else:
                    self.state = DEXState.ERROR
            elif byte == EOT and self.state == DEXState.WAITING_FOR_EOT_AFTER_COMM_ID:
                self.state = DEXState.READY_FOR_SECOND_HANDSHAKE
                self.logger.info("First handshake complete, ready for second handshake")
                self.buffer = []
            elif byte == EOT:
                self.logger.warning(f"Received unexpected EOT in state {self.state.name}")
            elif byte == ETX:
                self.logger.warning(f"Received unexpected ETX in state {self.state.name}")
        else:
            self.logger.warning(f"Received unexpected byte 0x{byte:02x} in state {self.state.name}")

    def run(self, timeout_seconds: int = 30) -> None:
        """Main loop to process incoming bytes from the serial connection, with timeout."""
        start_time = time.time()
        
        # Start the handshake process
        if not self.start_handshake():
            self.logger.error("Failed to start handshake process")
            return
        
        while self.serial_conn.is_connected():
            if time.time() - start_time > timeout_seconds:
                self.logger.error(f"Timeout reached ({timeout_seconds}s) with no valid response. Exiting.")
                break
                
            byte = self.serial_conn.read_byte()
            if byte is not None:
                self.logger.debug(f"Received byte: 0x{byte:02x}")
                self.handle_byte(byte)

def setup_logging():
    """Configure logging for the application."""
    import os
    from datetime import datetime
    
    # Create logs directory if it doesn't exist
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Create timestamped log filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"dex_session_{timestamp}.log")
    
    # Configure logging to write to both file and console
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logger = logging.getLogger(__name__)
    logger.info(f"Logging to file: {log_file}")

def main():
    """Main function to test the DEX state machine."""
    setup_logging()
    logger = logging.getLogger(__name__)
    
    # Serial connection settings
    port = "/dev/cu.usbmodem5B43E73635381"
    baud_rate = 9600
    data_bits = 8
    stop_bits = 1
    parity = "none"
    use_hardware_flow_control = False

    logger.info("Starting DEX state machine test")
    logger.info(f"Connecting to port {port} with settings:")
    logger.info(f"  Baud rate: {baud_rate}")
    logger.info(f"  Data bits: {data_bits}")
    logger.info(f"  Stop bits: {stop_bits}")
    logger.info(f"  Parity: {parity}")
    logger.info(f"  Hardware flow control: {use_hardware_flow_control}")

    # Create and connect serial connection
    serial_conn = SerialConnection()
    if not serial_conn.connect(
        port=port,
        baud_rate=baud_rate,
        data_bits=data_bits,
        stop_bits=stop_bits,
        parity=parity,
        use_hardware_flow_control=use_hardware_flow_control
    ):
        logger.error("Failed to connect to serial port")
        return 1

    # Create state machine
    state_machine = DEXStateMachine(serial_conn)
    logger.info("State machine initialized")

    try:
        # Run the state machine
        state_machine.run()
    except KeyboardInterrupt:
        logger.info("\nReceived keyboard interrupt, shutting down...")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return 1
    finally:
        # Clean up
        serial_conn.disconnect()
        logger.info("Serial connection closed")

    return 0

if __name__ == "__main__":
    sys.exit(main())
