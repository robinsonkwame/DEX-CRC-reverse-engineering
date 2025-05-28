import serial
import time
import logging
import os
from datetime import datetime
from typing import List, Optional, Tuple, Union
import io
from crc_calculator import calculate_crc_with_config, load_crc_config
import sys


# Constants for DEX/UCS protocol
ENQ = b'\x05'  # Enquiry signal
EOT = b'\x04'  # End of Transmission
DLE = b'\x10'  # Data Link Escape
ACK0 = DLE + b'\x30'  # Acknowledge 0 (DLE0)
ACK1 = DLE + b'\x31'  # Acknowledge 1 (DLE1)
NAK = b'\x15'  # Negative Acknowledge
SOH = b'\x01'  # Start of Header
STX = b'\x02'  # Start of Text
ETX = b'\x03'  # End of Text
ETB = b'\x17'  # End of Transmission Block

# Communication details
BAUDRATE = 9600  # Baudrate for serial communication
DEXDELAY = 0.05  # Delay to handle timing issues

# DDC (Data Collection Device) - Your script's identifiers
DDC_CommunicationID = b'DEXPYTHN'  # 8-character identifier for your script
DDC_RevisionLevel = b'01'  # 2-character revision level

# VMC (Vending Machine Controller) - Parsed from first handshake
VMC_CommunicationID = b''  # Will be populated from first handshake
VMC_RevisionLevel = b''  # Will be populated from first handshake
VMC_LayerInfo = b''  # Will be populated from first handshake

# Default values
port = "/dev/cu.usbmodem5B43E73635381"
DEFAULT_COM_PORT = port

def calculate_crc(data: List[int]) -> int:
    """Calculate CRC using parameters from config file."""
    return calculate_crc_with_config(data, 'crc_config.yaml')

def parse_vmc_identity(message: bytearray) -> Tuple[bytes, bytes, bytes]:
    """Parse VMC identity from the first handshake message.
    
    Expected format: DLE + SOH + CommID(8) + 'R' + RevLevel(2) + LayerInfo + DLE + ETX
    Returns: (communication_id, revision_level, layer_info)
    """
    global VMC_CommunicationID, VMC_RevisionLevel, VMC_LayerInfo
    
    # Remove DLE + SOH from start and DLE + ETX from end
    if len(message) >= 4 and message[0] == DLE[0] and message[1] == SOH[0]:
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
                    
                    VMC_CommunicationID = comm_id
                    VMC_RevisionLevel = rev_level
                    VMC_LayerInfo = layer_info
                    
                    return comm_id, rev_level, layer_info
    
    return b'', b'', b''

def send_ack(serial_port, ack_type, logger):
    """Send an ACK (acknowledge) signal."""
    logger.info(f"Sending ACK: {ack_type.hex()}")
    serial_port.write(ack_type)
    serial_port.flush()

def send_enq(serial_port, logger):
    """Send an ENQ (enquiry) signal."""
    logger.info("Sending ENQ...")
    serial_port.write(ENQ)
    serial_port.flush()

def wait_for_enq(serial_port, logger):
    """Wait for an ENQ (enquiry) signal."""
    logger.info("Waiting for ENQ...")
    start_time = time.time()
    while time.time() - start_time < 300:  # Wait for 5 minutes for ENQ
        if serial_port.in_waiting > 0:
            data = serial_port.read(1)
            logger.info(f"Received byte: {data.hex()}")
            if data == ENQ:
                return True
    return False

def wait_for_eot(serial_port, logger):
    """Wait for an EOT (end of transmission) signal."""
    logger.info("Waiting for EOT...")
    start_time = time.time()
    while time.time() - start_time < 5:  # Wait for 5 seconds for EOT
        if serial_port.in_waiting > 0:
            data = serial_port.read(1)
            logger.info(f"Received byte: {data.hex()}")
            if data == EOT:
                return True
    return False

def wait_for_ack(serial_port, expected_ack, logger):
    """Wait for an ACK (acknowledge) signal."""
    logger.info(f"Waiting for ACK {expected_ack.hex()}...")
    start_time = time.time()
    while time.time() - start_time < 5:  # Wait for 5 seconds for ACK
        if serial_port.in_waiting >= 2:
            data = serial_port.read(2)
            logger.info(f"Received bytes: {data.hex()}")
            if data == expected_ack:
                return True
    return False

def dex_first_handshake(serial_port, logger):
    """Perform the first handshake in the DEX protocol."""
    if not wait_for_enq(serial_port, logger):
        logger.error("First Handshake Error: ENQ not received")
        return False

    send_ack(serial_port, DLE + b'\x30', logger)

    time.sleep(DEXDELAY)  # Small delay after sending ACK0

    # Read the device's operation request message
    message = bytearray()
    while True:
        byte = serial_port.read(1)
        logger.info(f"Received byte: {byte.hex()}")
        message.append(byte[0])
        if len(message) >= 2 and message[-2:] == DLE + ETX:
            break

    crc_received = serial_port.read(2)
    logger.info(f"Received CRC bytes: {crc_received.hex()}")
    crc_received_value = int.from_bytes(crc_received, byteorder='little')
    full_message = message + crc_received
    logger.info(f"Full message received: {full_message.hex()}")

    # Verify the received message ends with the expected DLE + ETX + CRC
    if not message.endswith(DLE + ETX):
        logger.error("First Handshake Error: Invalid message format received")
        return False

    # Load CRC config to check data processing setting
    crc_config = load_crc_config('crc_config.yaml')
    
    # Process message bytes according to config
    if crc_config.get('data_processing') == "Raw Data":
        message_bytes = list(message)  # Use full message including DLE and SOH
        logger.info("Using raw data for CRC calculation (including DLE and SOH bytes)")
    else:
        message_bytes = [b for b in message if b != DLE[0] and b != SOH[0]]
        logger.info("Filtering out DLE and SOH bytes for CRC calculation")

    crc_calculated = calculate_crc(message_bytes)

    logger.info(f"Received CRC: {crc_received_value:04x}, Calculated CRC: {crc_calculated:04x}")
    logger.info(f"Message bytes for CRC calculation: {[hex(b) for b in message_bytes]}")

    if crc_received_value != crc_calculated:
        logger.error("First Handshake Error: CRC mismatch")
        return False
    
    logger.info("CRC check passed!")
    
    # Parse VMC identity from the message
    comm_id, rev_level, layer_info = parse_vmc_identity(message)
    logger.info(f"VMC Communication ID: '{comm_id.decode('ascii', errors='ignore')}'")
    logger.info(f"VMC Revision Level: '{rev_level.decode('ascii', errors='ignore')}'")
    logger.info(f"VMC Layer Info: '{layer_info.decode('ascii', errors='ignore')}'")
    
    #sys.exit(0)  # Exit with success code

    # This part is unknown
    send_ack(serial_port, DLE + b'\x31', logger)

    if not wait_for_eot(serial_port, logger):
        logger.error("First Handshake Error: EOT not received")
        return False

    time.sleep(DEXDELAY)
    return True

def setup_logging():
    """Setup logging to a timestamped file in the logs directory."""
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Create timestamped log file
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = f'logs/dex_session_{timestamp}.log'
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()  # Also log to console
        ]
    )
    return logging.getLogger(__name__)

def read_serial_data(serial_port, timeout=5):
    """Read data from serial port until timeout or complete message is received.
    
    Returns: (data_with_crc, is_final_block)
    - data_with_crc: The complete message including CRC
    - is_final_block: True if ended with DLE+ETX, False if ended with DLE+ETB
    """
    data = bytearray()
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        if serial_port.in_waiting > 0:
            byte = serial_port.read(1)
            data.append(byte[0])
            
            # Check for end of message (DLE + ETX or DLE + ETB)
            if len(data) >= 2:
                if data[-2:] == DLE + ETX:
                    # Final block - read CRC and return
                    crc_bytes = serial_port.read(2)
                    if len(crc_bytes) == 2:
                        return data + crc_bytes, True
                elif data[-2:] == DLE + ETB:
                    # More blocks to follow - read CRC and return
                    crc_bytes = serial_port.read(2)
                    if len(crc_bytes) == 2:
                        return data + crc_bytes, False
        time.sleep(0.01)
    
    return data, True  # Assume final if timeout

def handle_multi_block_transfer(serial_port, logger):
    """Handle multi-block data transfer from VMC.
    
    Returns: List of all received data blocks (without CRC)
    """
    all_blocks = []
    block_number = 0
    expected_ack = ACK0  # Start with ACK0
    crc_config = load_crc_config('crc_config.yaml')
    
    logger.info("Starting multi-block data transfer...")
    
    while True:
        block_number += 1
        logger.info(f"Reading block {block_number}...")
        
        # Read the next block
        block_data, is_final_block = read_serial_data(serial_port)
        
        if not block_data:
            logger.warning(f"No data received for block {block_number}")
            break
            
        # Log block information
        block_type = "FINAL" if is_final_block else "INTERMEDIATE"
        ending = "DLE+ETX" if is_final_block else "DLE+ETB" 
        logger.info(f"Block {block_number} ({block_type}): {len(block_data)} bytes, ending with {ending}")
        logger.info(f"Block {block_number} data: {block_data.hex()}")
        
        # Verify CRC of received block
        if len(block_data) >= 2:
            received_crc = int.from_bytes(block_data[-2:], byteorder='little')
            
            # Process received message bytes according to config
            if crc_config.get('data_processing') == "Raw Data":
                message_bytes = list(block_data[:-2])  # Use full message including DLE and SOH
                logger.info(f"Block {block_number}: Using raw data for CRC calculation")
            else:
                message_bytes = [b for b in block_data[:-2] if b != DLE[0] and b != SOH[0]]
                logger.info(f"Block {block_number}: Filtering out DLE and SOH bytes for CRC calculation")
            
            calculated_crc = calculate_crc(message_bytes)
            logger.info(f"Block {block_number}: Received CRC: {received_crc:04x}, Calculated CRC: {calculated_crc:04x}")
            
            if received_crc == calculated_crc:
                logger.info(f"Block {block_number}: CRC verification successful")
                
                # Store the block data (without CRC)
                all_blocks.append(block_data[:-2])
                
                # Send appropriate ACK
                send_ack(serial_port, expected_ack, logger)
                logger.info(f"Block {block_number}: Sent ACK {expected_ack.hex()}")
                
                # Alternate ACK for next block
                expected_ack = ACK1 if expected_ack == ACK0 else ACK0
                
                # If this was the final block, we're done
                if is_final_block:
                    logger.info("Final block received. Multi-block transfer complete.")
                    break
                    
            else:
                logger.error(f"Block {block_number}: CRC verification failed. Received: {received_crc:04x}, Calculated: {calculated_crc:04x}")
                # Send NAK or handle error appropriately
                break
        else:
            logger.error(f"Block {block_number}: Insufficient data for CRC verification")
            break
    
    logger.info(f"Multi-block transfer completed. Received {len(all_blocks)} blocks.")
    return all_blocks

def dex_second_handshake(serial_port, logger):
    """Perform the second handshake in the DEX protocol and read response data."""
    logger.info("Starting second handshake")
    send_enq(serial_port, logger)

    if not wait_for_ack(serial_port, DLE + b'\x30', logger):
        logger.error("Second Handshake Error: ACK0 not received")
        return False

    # Prepare the message with DDC communication ID and revision level
    logger.info(f"DDC Communication ID: '{DDC_CommunicationID.decode('ascii', errors='ignore')}'")
    logger.info(f"DDC Revision Level: '{DDC_RevisionLevel.decode('ascii', errors='ignore')}'")
    
    message_content = DDC_CommunicationID + b'R' + DDC_RevisionLevel
    message = DLE + SOH + message_content + DLE + ETX
    
    logger.info(f"DDC message content: '{message_content.decode('ascii', errors='ignore')}'")
    logger.info(f"DDC message framed: {message.hex()}")

    # Load CRC config to check data processing setting
    crc_config = load_crc_config('crc_config.yaml')
    
    # Process message bytes according to config
    if crc_config.get('data_processing') == "Raw Data":
        message_bytes = list(message)  # Use full message including DLE and SOH
        logger.info("Using raw data for DDC message CRC calculation (including DLE and SOH bytes)")
    else:
        message_bytes = [b for b in message if b != DLE[0] and b != SOH[0]]
        logger.info("Filtering out DLE and SOH bytes for DDC message CRC calculation")

    # Calculate CRC
    crc = calculate_crc(message_bytes)
    crc_bytes = crc.to_bytes(2, 'little')
    
    logger.info(f"DDC Message bytes for CRC calculation: {[hex(b) for b in message_bytes]}")
    logger.info(f"Calculated CRC: {crc:04x} (bytes: {crc_bytes.hex()})")

    # Send the message with CRC
    full_message = message + crc_bytes
    serial_port.write(full_message)
    serial_port.flush()
    logger.info(f"Sent DDC identity message: {full_message.hex()}")

    if not wait_for_ack(serial_port, DLE + b'\x31', logger):
        logger.error("Second Handshake Error: ACK1 not received after sending DDC communication ID and revision level")
        return False

    logger.info("DDC Identity accepted by VMC (DLE+ACK1 received!). Ready for data transfer.")
    time.sleep(DEXDELAY)

    # Handle multi-block data transfer
    logger.info("Starting data transfer phase...")
    all_blocks = handle_multi_block_transfer(serial_port, logger)
    
    if all_blocks:
        logger.info(f"Successfully received {len(all_blocks)} data blocks")
        
        # Combine all blocks into one data stream
        combined_data = bytearray()
        for i, block in enumerate(all_blocks):
            logger.info(f"Block {i+1}: {len(block)} bytes")
            combined_data.extend(block)
        
        logger.info(f"Total combined data: {len(combined_data)} bytes")
        
        # Try to decode and log the data content
        try:
            # Most DEX data is ASCII text
            text_data = combined_data.decode('ascii', errors='ignore')
            logger.info(f"DEX Data Content Preview (first 500 chars):")
            logger.info(text_data[:500])
            
            # Save the raw data to a file for analysis
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            data_file = f'logs/dex_data_{timestamp}.bin'
            with open(data_file, 'wb') as f:
                f.write(combined_data)
            logger.info(f"Raw DEX data saved to: {data_file}")
            
            # Save the text data to a file
            text_file = f'logs/dex_data_{timestamp}.txt'
            with open(text_file, 'w') as f:
                f.write(text_data)
            logger.info(f"Text DEX data saved to: {text_file}")
            
            # Parse the DEX data format
            parsed_data = parse_dex_data(text_data, logger)
            
        except Exception as e:
            logger.error(f"Error processing DEX data: {e}")
    else:
        logger.warning("No data blocks received")

    # Send EOT to complete the session
    serial_port.write(EOT)
    serial_port.flush()
    logger.info("Sent EOT to complete session")

    return True

def send_data_line(serial_port, line, line_number, is_last_line):
    """Send a line of data from the EVADTS file."""
    # Ensure the data is sent in binary mode
    data_bytes = line.encode('utf-8')
    
    if is_last_line:
        data_bytes += DLE + ETX
    else:
        data_bytes += DLE + ETB

    print(f"Data bytes for CRC calculation: {data_bytes.hex()}")
    message_bytes = [b for b in data_bytes if b != DLE[0]]
    dwCRC = calculate_crc(message_bytes)

    # Print the calculated CRC
    print(f"Calculated CRC: {dwCRC:04x}")

    # Prepare the message
    message = DLE + STX + data_bytes + dwCRC.to_bytes(2, 'little')

    print(f"Sending line {line_number}: {message.hex()}")
    serial_port.write(message)
    serial_port.flush()

    start_time = time.time()
    while time.time() - start_time < 5:
        if serial_port.in_waiting > 0:
            response = serial_port.read(2)
            print(f"Received: {response.hex()}")
            if response == ACK0 or response == ACK1:  # ACK0 or ACK1
                return
            elif response == NAK:
                print("NAK received, resending line")
                serial_port.write(message)
                serial_port.flush()
            time.sleep(DEXDELAY)
    print("Error: Did not receive ACK0, ACK1 or NAK in time")

class MockSerialPort:
    """Mock serial port that replays data from a log file."""
    def __init__(self, log_file_path: str):
        self.log_file_path = log_file_path
        self.response_queue = []
        self._in_waiting = 0
        self._parse_log_file()
        
    def _parse_log_file(self):
        """Parse the log file to extract the sequence of bytes."""
        with open(self.log_file_path, 'r') as f:
            for line in f:
                if "Received byte:" in line:
                    # Extract hex value from line
                    hex_value = line.split("Received byte:")[1].strip()
                    if hex_value:
                        try:
                            byte_value = int(hex_value, 16)
                            self.response_queue.append(bytes([byte_value]))
                        except ValueError:
                            continue
                elif "Received bytes:" in line:
                    # Extract hex values from line
                    hex_values = line.split("Received bytes:")[1].strip()
                    if hex_values:
                        try:
                            byte_values = bytes.fromhex(hex_values)
                            self.response_queue.append(byte_values)
                        except ValueError:
                            continue
                elif "Received CRC bytes:" in line:
                    # Extract hex values from line
                    hex_values = line.split("Received CRC bytes:")[1].strip()
                    if hex_values:
                        try:
                            byte_values = bytes.fromhex(hex_values)
                            self.response_queue.append(byte_values)
                        except ValueError:
                            continue

    @property
    def in_waiting(self) -> int:
        """Return the number of bytes waiting to be read."""
        return len(self.response_queue) if self.response_queue else 0

    def read(self, size: int = 1) -> bytes:
        """Read bytes from the mock serial port."""
        if not self.response_queue:
            return b''
        
        response = self.response_queue.pop(0)
        if len(response) > size:
            # If we have more bytes than requested, put the rest back
            self.response_queue.insert(0, response[size:])
            return response[:size]
        return response

    def write(self, data: bytes) -> int:
        """Write bytes to the mock serial port."""
        return len(data)

    def flush(self):
        """Flush the mock serial port."""
        pass

    def reset_input_buffer(self):
        """Reset the input buffer."""
        self.response_queue = []
        self._parse_log_file()

    def reset_output_buffer(self):
        """Reset the output buffer."""
        pass

    def close(self):
        """Close the mock serial port."""
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

def parse_dex_data(data_text: str, logger):
    """Parse DEX data format and extract key information."""
    logger.info("Parsing DEX data format...")
    
    lines = data_text.split('\n')
    parsed_info = {
        'header': {},
        'sections': {},
        'total_lines': len(lines)
    }
    
    current_section = None
    
    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
            
        # DEX lines typically start with a 2-character identifier
        if len(line) >= 2:
            line_id = line[:2]
            data_part = line[2:] if len(line) > 2 else ''
            
            # Common DEX line identifiers
            if line_id == 'DX':
                parsed_info['header']['dex_version'] = data_part
                logger.info(f"DEX Version: {data_part}")
            elif line_id == 'ST':
                parsed_info['header']['start_time'] = data_part
                logger.info(f"Start Time: {data_part}")
            elif line_id == 'EN':
                parsed_info['header']['end_time'] = data_part
                logger.info(f"End Time: {data_part}")
            elif line_id == 'CB':
                current_section = 'cashbox'
                if current_section not in parsed_info['sections']:
                    parsed_info['sections'][current_section] = []
                parsed_info['sections'][current_section].append(line)
            elif line_id == 'CA':
                current_section = 'cash_audit'
                if current_section not in parsed_info['sections']:
                    parsed_info['sections'][current_section] = []
                parsed_info['sections'][current_section].append(line)
            elif line_id == 'VA':
                current_section = 'vend_audit'
                if current_section not in parsed_info['sections']:
                    parsed_info['sections'][current_section] = []
                parsed_info['sections'][current_section].append(line)
            elif line_id == 'PA':
                current_section = 'price_audit'
                if current_section not in parsed_info['sections']:
                    parsed_info['sections'][current_section] = []
                parsed_info['sections'][current_section].append(line)
            elif current_section:
                # Continue adding to current section
                parsed_info['sections'][current_section].append(line)
    
    # Log summary
    logger.info(f"DEX Data Summary:")
    logger.info(f"  Total lines: {parsed_info['total_lines']}")
    logger.info(f"  Header info: {len(parsed_info['header'])} fields")
    logger.info(f"  Sections found: {list(parsed_info['sections'].keys())}")
    
    for section, items in parsed_info['sections'].items():
        logger.info(f"    {section}: {len(items)} entries")
    
    return parsed_info

def main():
    """Main function to initialize the serial port and perform DEX/UCS operations."""
    # Setup logging
    logger = setup_logging()
    logger.info("Starting DEX session")
    
    # Use the default port directly
    com_port = DEFAULT_COM_PORT
    logger.info(f"Using COM port: {com_port}")

    # Create a mock serial port that replays the log file
    mock_port = MockSerialPort('logs/dex_session_20250519_115731.log')
    
    # Choose between real and mock serial port
    use_mock = False #True  # Set to False to use real serial port
    
    while True:
        try:
            if use_mock:
                serial_port = mock_port
            else:
                serial_port = serial.Serial(com_port, baudrate=BAUDRATE, timeout=1, 
                                          bytesize=serial.EIGHTBITS, 
                                          parity=serial.PARITY_NONE, 
                                          stopbits=serial.STOPBITS_ONE)
            
            serial_port.reset_input_buffer()  # Clear the input buffer
            serial_port.reset_output_buffer()  # Clear the output buffer
            time.sleep(2)  # Allow time for the serial port to initialize

            if dex_first_handshake(serial_port, logger):
                logger.info("First handshake successful")

                if dex_second_handshake(serial_port, logger):
                    logger.info("Second handshake successful")
                    logger.info("File transfer completed")
                else:
                    logger.error("Second handshake failed")
            else:
                logger.error("First handshake failed")

            logger.info("Restarting the process...")
            
            if not use_mock:
                serial_port.close()
                
        except Exception as e:
            logger.error(f"Error during DEX session: {str(e)}")
            time.sleep(5)  # Wait before retrying

if __name__ == "__main__":
    main()