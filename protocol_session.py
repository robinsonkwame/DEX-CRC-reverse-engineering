import serial
import time
import logging
import os
from datetime import datetime
from typing import List, Optional, Tuple, Union
import io
import yaml
from dataclasses import dataclass
from enum import Enum

# Constants for DEX/UCS protocol
class DEXConstants:
    ENQ = 0x05  # Enquiry signal
    EOT = 0x04  # End of Transmission
    DLE = 0x10  # Data Link Escape
    ACK0 = 0x30  # Acknowledge 0
    ACK1 = 0x31  # Acknowledge 1
    NAK = 0x15  # Negative Acknowledge
    SOH = 0x01  # Start of Header
    STX = 0x02  # Start of Text
    ETX = 0x03  # End of Text
    ETB = 0x17  # End of Transmission Block
    
    # Timeouts
    HANDSHAKE_TIMEOUT = 5
    DATA_TIMEOUT = 10

class DEXState(Enum):
    IDLE = 0
    MASTER_HANDSHAKE = 1
    SLAVE_HANDSHAKE = 2
    DATA_TRANSFER = 3
    COMPLETE = 4
    ERROR = 5

@dataclass
class DEXMessage:
    data: bytes
    is_valid: bool
    is_final: bool
    crc: int = 0

class DEXFraming:
    @staticmethod
    def parse_frame(frame: bytes, crc_calc) -> DEXMessage:
        """Parse a DEX frame and validate its CRC."""
        if len(frame) < 4:  # Minimum frame size: DLE+SOH + data + DLE+ETX + CRC
            return DEXMessage(data=b'', is_valid=False, is_final=False)
        
        # Check frame boundaries
        if frame[0] != DEXConstants.DLE or frame[1] != DEXConstants.SOH:
            return DEXMessage(data=b'', is_valid=False, is_final=False)
        
        # Find the end of the frame
        end_idx = -1
        for i in range(2, len(frame)-1):
            if frame[i] == DEXConstants.DLE and frame[i+1] in [DEXConstants.ETX, DEXConstants.ETB]:
                end_idx = i
                break
        
        if end_idx == -1:
            return DEXMessage(data=b'', is_valid=False, is_final=False)
        
        # Extract data and check if it's final
        data = frame[2:end_idx]
        is_final = frame[end_idx+1] == DEXConstants.ETX
        
        # Extract and validate CRC
        if len(frame) < end_idx + 4:  # Need 2 more bytes for CRC
            return DEXMessage(data=data, is_valid=False, is_final=is_final)
        
        received_crc = int.from_bytes(frame[end_idx+2:end_idx+4], byteorder='little')
        
        # Calculate CRC on data plus ETX/ETB
        crc_data = bytearray(data)
        crc_data.append(frame[end_idx+1])  # Add ETX/ETB
        calculated_crc = crc_calc.calculate(crc_data)
        
        return DEXMessage(
            data=data,
            is_valid=received_crc == calculated_crc,
            is_final=is_final,
            crc=received_crc
        )

class CRCCalculator:
    def __init__(self, config_path='crc_config.yaml'):
        self.config = self._load_config(config_path)
        self.polynomial = self.config.get('polynomial', 0x1021)
        self.initial_value = self.config.get('initial_value', 0xFFFF)
        self.final_xor = self.config.get('final_xor', 0x0000)
        self.reflect_input = self.config.get('reflect_input', True)
        self.reflect_output = self.config.get('reflect_output', True)
    
    def _load_config(self, config_path):
        """Load CRC configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logging.warning(f"Failed to load CRC config: {e}")
            return {}
    
    def _reflect(self, value, bits):
        """Reflect the bits in a value."""
        reflected = 0
        for i in range(bits):
            if value & (1 << i):
                reflected |= (1 << (bits - 1 - i))
        return reflected
    
    def calculate(self, data: List[int]) -> int:
        """Calculate CRC-16 using the configured parameters."""
        crc = self.initial_value
        
        for byte in data:
            if self.reflect_input:
                byte = self._reflect(byte, 8)
            
            crc ^= (byte << 8)
            for _ in range(8):
                if crc & 0x8000:
                    crc = ((crc << 1) ^ self.polynomial) & 0xFFFF
                else:
                    crc = (crc << 1) & 0xFFFF
        
        if self.reflect_output:
            crc = self._reflect(crc, 16)
        
        return crc ^ self.final_xor

class DEXProtocolError(Exception):
    """Custom exception for DEX protocol errors."""
    pass

def perform_slave_handshake(self) -> dict:
    """Perform Second Handshake phase (where we act as slave)"""
    logger.info("Starting Second Handshake - waiting for machine ENQ")
    self.state = DEXState.SLAVE_HANDSHAKE
    
    # Wait for ENQ from VMD (now master)
    response = self.wait_for_byte(DEXConstants.ENQ, timeout=DEXConstants.HANDSHAKE_TIMEOUT)
    
    if not response:
        logger.error("No ENQ received from VMD during Second Handshake")
        return None
    
    # Send DLE 0 (ACK 0) in response to ENQ
    if not self.send_bytes(bytes([DEXConstants.DLE, ord('0')])):
        logger.error("Failed to send DLE 0 during Second Handshake")
        return None
    
    # Wait for the identification frame starting with DLE SOH
    frame = self.wait_for_frame(timeout=DEXConstants.HANDSHAKE_TIMEOUT)
    
    if not frame:
        logger.error("No identification frame received from VMD")
        return None
    
    # Parse the identification frame
    message = DEXFraming.parse_frame(frame, self.crc_calc)
    
    if not message.is_valid:
        logger.error("Invalid identification frame received")
        self.send_nak()
        return None
    
    # Send DLE 1 (ACK 1) for the identification frame
    if not self.send_bytes(bytes([DEXConstants.DLE, ord('1')])):
        logger.error("Failed to ACK VMD identification")
        return None
    
    # Wait for EOT to complete the Second Handshake
    eot = self.wait_for_byte(DEXConstants.EOT, timeout=DEXConstants.HANDSHAKE_TIMEOUT)
    if not eot:
        logger.error("No EOT received to complete Second Handshake")
        return None
    
    # Parse the identification data - format should be: ResponseCode + CommunicationID + RevisionLevel
    id_data = message.data.decode('ascii', errors='replace')
    logger.info(f"VMD identification received: {id_data}")
    
    # Extract response code, VMC ID, revision, and level information
    machine_info = self.parse_machine_identification(id_data)
    
    logger.info(f"Response Code: {machine_info.get('response_code', 'Unknown')}")
    logger.info(f"VMC ID: {machine_info.get('vmc_id', 'Unknown')}")
    logger.info(f"Revision: {machine_info.get('revision', 'Unknown')}")
    logger.info(f"Level: {machine_info.get('level', 'Unknown')}")
    
    return machine_info

def parse_machine_identification(self, id_data: str) -> dict:
    """Parse machine identification string from Second Handshake"""
    machine_info = {'raw_data': id_data}
    
    try:
        # According to DEX/UCS spec, the Second Handshake response should contain:
        # ResponseCode (00=OK) + CommunicationID (10 chars) + RevisionLevel (R01L01 or R00L06)
        
        if len(id_data) >= 18:  # Minimum length for valid response
            # First two characters should be response code (00 = OK)
            machine_info['response_code'] = id_data[:2]
            
            # Next 10 characters are the Communication ID
            machine_info['vmc_id'] = id_data[2:12]
            
            # Revision and Level information (R01L01 or R00L06)
            if len(id_data) >= 18:
                revision_level = id_data[12:18]
                if revision_level.startswith('R'):
                    machine_info['revision'] = revision_level[1:3]
                    machine_info['level'] = revision_level[4:6] if len(revision_level) >= 6 else ''
        
    except Exception as e:
        logger.error(f"Error parsing machine identification: {e}")
    
    return machine_info

def parse_control_message(self, data: bytes) -> dict:
    """Parse DDCMP control message and extract detailed information
    
    Control Message Format (8 bytes):
    Byte 1: Always 05 (start of control message)
    Byte 2: Message type (01=START, 02=NACK, 03=ACK, 06=STACK)
    Byte 3: Flags and error codes
    Byte 4: Message number
    Byte 5: Fill byte (always 0)
    Byte 6: Station address (always 1 for point-to-point)
    Bytes 7-8: CRC16
    """
    control_info = {
        'is_control_message': False,
        'message_type': None,
        'error_code': None,
        'error_description': None,
        'message_number': None,
        'raw_bytes': data.hex() if data else ''
    }
    
    if not data or len(data) < 8:
        return control_info
    
    # Check if this is a control message (starts with 0x05)
    if data[0] != 0x05:
        return control_info
    
    control_info['is_control_message'] = True
    
    # Parse message type
    msg_type = data[1]
    type_names = {
        0x01: 'START',
        0x02: 'NACK', 
        0x03: 'ACK',
        0x06: 'STACK',
        0x07: 'STACK'
    }
    control_info['message_type'] = type_names.get(msg_type, f'UNKNOWN(0x{msg_type:02x})')
    
    # Parse byte 3 (flags and error codes)
    byte3 = data[2]
    
    # Extract flags from most significant 2 bits
    select_flag = (byte3 >> 7) & 0x01
    quick_sync_flag = (byte3 >> 6) & 0x01
    
    control_info['select_flag'] = select_flag
    control_info['quick_sync_flag'] = quick_sync_flag
    
    # For NACK messages, extract error code from least significant 6 bits
    if msg_type == 0x02:  # NACK
        error_code = byte3 & 0x3F  # Mask to get least significant 6 bits
        control_info['error_code'] = error_code
        control_info['error_description'] = self.get_nack_error_description(error_code)
    
    # Parse message number
    control_info['message_number'] = data[3]
    
    # Parse fill byte and station address
    control_info['fill_byte'] = data[4]
    control_info['station_address'] = data[5]
    
    # Extract CRC
    received_crc = (data[7] << 8) | data[6]  # Big-endian CRC
    control_info['received_crc'] = f"0x{received_crc:04x}"
    
    return control_info

def get_nack_error_description(self, error_code: int) -> str:
    """Get human-readable description of NACK error code"""
    error_descriptions = {
        # Transmission medium errors
        1: "Header block check error - CRC16 error in Control Message Header or Data Message Header",
        2: "Data field block check error - CRC16 error in Command Message/Response or Data Message", 
        3: "REP response - not used in Enhanced DDCMP Communications link",
        
        # Computer/interface errors
        8: "Buffer temporarily unavailable",
        9: "Receive overrun",
        16: "Message too long",
        17: "Message header format error"
    }
    
    description = error_descriptions.get(error_code, f"Unknown error code: {error_code}")
    
    # Categorize error type
    if error_code in [1, 2, 3]:
        category = "Transmission Medium Error"
    elif error_code in [8, 9, 16, 17]:
        category = "Computer/Interface Error"
    else:
        category = "Unknown Error Category"
    
    return f"{category}: {description}"

def analyze_received_message(self, data: bytes) -> dict:
    """Analyze any received message to determine if it's a control message or data message"""
    analysis = {
        'message_class': 'unknown',
        'details': {}
    }
    
    if not data:
        analysis['message_class'] = 'empty'
        return analysis
    
    # Check if it's a control message
    control_info = self.parse_control_message(data)
    if control_info['is_control_message']:
        analysis['message_class'] = 'control'
        analysis['details'] = control_info
        
        # Log detailed control message information
        logger.info(f"=== CONTROL MESSAGE RECEIVED ===")
        logger.info(f"Type: {control_info['message_type']}")
        logger.info(f"Raw bytes: {control_info['raw_bytes']}")
        logger.info(f"Message number: {control_info['message_number']}")
        logger.info(f"Station address: {control_info['station_address']}")
        logger.info(f"CRC: {control_info['received_crc']}")
        
        if control_info['message_type'] == 'NACK':
            logger.error(f"NACK ERROR DETAILS:")
            logger.error(f"  Error Code: {control_info['error_code']}")
            logger.error(f"  Description: {control_info['error_description']}")
            logger.error(f"  Select Flag: {control_info['select_flag']}")
            logger.error(f"  Quick Sync Flag: {control_info['quick_sync_flag']}")
        
        logger.info("==============================")
    else:
        # Check if it's a data message (starts with DLE SOH)
        if len(data) >= 2 and data[0] == DEXConstants.DLE and data[1] == DEXConstants.SOH:
            analysis['message_class'] = 'data'
            analysis['details'] = {
                'length': len(data),
                'starts_with_dle_soh': True
            }
        else:
            analysis['message_class'] = 'other'
            analysis['details'] = {
                'first_byte': f"0x{data[0]:02x}" if data else None,
                'length': len(data)
            }
    
    return analysis

def wait_for_response_with_analysis(self, expected_types: list, timeout: int = None) -> tuple[bytes, dict]:
    """Wait for a response and analyze it, returning both raw data and analysis"""
    if timeout is None:
        timeout = DEXConstants.HANDSHAKE_TIMEOUT
    
    # This method would need to be implemented based on your existing wait methods
    # For now, this is a placeholder showing the concept
    data = self.wait_for_frame(timeout=timeout)
    if data:
        analysis = self.analyze_received_message(data)
        return data, analysis
    return None, {'message_class': 'timeout'}

def get_last_received_data(self) -> bytes:
    """Get the last received data for analysis - placeholder implementation"""
    # This would need to be implemented to store the last received raw data
    # For now, return empty bytes as a placeholder
    return b''

def receive_data_blocks(self) -> Optional[bytes]:
    """Receive data blocks with enhanced control message analysis"""
    logger.info("Starting data block reception with control message analysis")
    all_data = bytearray()
    block_count = 0
    
    while True:
        # Wait for data block
        frame = self.wait_for_frame(timeout=DEXConstants.DATA_TIMEOUT)
        
        if not frame:
            logger.warning("No data frame received - checking for control messages")
            break
        
        # First, analyze what type of message we received
        analysis = self.analyze_received_message(frame)
        
        if analysis['message_class'] == 'control':
            control_details = analysis['details']
            if control_details['message_type'] == 'NACK':
                logger.error("Received NACK during data transfer - aborting")
                return None
            elif control_details['message_type'] in ['ACK', 'START', 'STACK']:
                logger.info(f"Received {control_details['message_type']} control message during data transfer")
                # Handle according to protocol - might need to continue or respond
                continue
            else:
                logger.warning(f"Received unexpected control message: {control_details['message_type']}")
                continue
        
        elif analysis['message_class'] == 'data':
            # Parse the data frame
            message = DEXFraming.parse_frame(frame, self.crc_calc)
            
            if not message.is_valid:
                logger.error("Invalid data frame received")
                # Send NACK for invalid frame
                self.send_nak()
                continue
            
            # Add data to collection
            all_data.extend(message.data)
            block_count += 1
            logger.info(f"Received valid data block {block_count}, size: {len(message.data)} bytes")
            
            # Send appropriate ACK
            ack_byte = ord('0') if block_count % 2 == 1 else ord('1')
            if not self.send_bytes(bytes([DEXConstants.DLE, ack_byte])):
                logger.error("Failed to send ACK for data block")
                return None
            
            # Check if this was the final block (ends with ETX)
            if message.is_final:
                logger.info("Received final data block")
                break
        
        else:
            logger.warning(f"Received unrecognized message type: {analysis['message_class']}")
            # Analyze the raw bytes for debugging
            if frame:
                logger.debug(f"Raw message bytes: {frame.hex()}")
    
    if all_data:
        logger.info(f"Data reception complete: {len(all_data)} total bytes received in {block_count} blocks")
        return bytes(all_data)
    else:
        logger.error("No valid data received")
        return None

def send_nak(self, error_code: int = 2) -> bool:
    """Send a NACK control message with specified error code
    
    Args:
        error_code: Error code for NACK (default 2 = data field block check error)
    """
    # Build NACK control message according to DDCMP format
    nack_message = bytearray([
        0x05,  # Byte 1: Control message start
        0x02,  # Byte 2: NACK message type
        0x40 | (error_code & 0x3F),  # Byte 3: Quick sync flag + error code (6 bits)
        0x00,  # Byte 4: Message number (0)
        0x00,  # Byte 5: Fill byte
        0x01,  # Byte 6: Station address (point-to-point)
    ])
    
    # Calculate CRC on first 6 bytes
    crc = self.crc_calc.calculate(nack_message)
    nack_message.extend([crc & 0xFF, (crc >> 8) & 0xFF])  # Add CRC (little-endian)
    
    logger.info(f"Sending NACK with error code {error_code}: {self.get_nack_error_description(error_code)}")
    logger.debug(f"NACK message bytes: {nack_message.hex()}")
    
    return self.send_bytes(bytes(nack_message))

def dump_dex_data(self) -> tuple[Optional[bytes], Optional[dict]]:
    """Complete DEX data dump sequence - returns (data, machine_info)"""
    logger.info("Starting DEX data dump sequence")
    
    try:
        # Phase 1: First Handshake (we're Master)
        if not self.perform_master_handshake():
            raise DEXProtocolError("First handshake failed")
        
        time.sleep(0.1)
        
        # Phase 2: Second Handshake (we're Slave)
        machine_info = self.perform_slave_handshake()
        if not machine_info:
            raise DEXProtocolError("Second handshake failed")
        
        # Check response code - should be "00" for OK
        if machine_info.get('response_code') != "00":
            logger.warning(f"VMD returned non-OK response code: {machine_info.get('response_code')}")
            if machine_info.get('response_code') == "04":
                raise DEXProtocolError("VMD has no data to transfer")
        
        time.sleep(0.1)
        
        # Phase 3: Data Reception
        dex_data = self.receive_data_blocks()
        
        if not dex_data:
            raise DEXProtocolError("No data received")
        
        # Send final EOT acknowledgment
        self.send_bytes(bytes([DEXConstants.EOT]))
        
        self.state = DEXState.COMPLETE
        logger.info("DEX data dump completed successfully")
        
        return dex_data, machine_info
        
    except Exception as e:
        logger.error(f"DEX data dump failed: {e}")
        self.state = DEXState.ERROR
        return None, None

def perform_master_handshake(self) -> bool:
    """Perform First Handshake phase (we're Master)"""
    logger.info("Starting First Handshake as Master")
    self.state = DEXState.MASTER_HANDSHAKE
    
    # Send ENQ
    if not self.send_bytes(bytes([DEXConstants.ENQ])):
        logger.error("Failed to send ENQ")
        return False
    
    # Wait for DLE 0 (ACK 0) with analysis
    dle_0 = self.wait_for_sequence(bytes([DEXConstants.DLE, ord('0')]), 
                                  timeout=DEXConstants.HANDSHAKE_TIMEOUT)
    if not dle_0:
        logger.error("No DLE 0 received from VMD")
        # Check if we received a NACK instead
        received_data = self.get_last_received_data()  # You'd need to implement this
        if received_data:
            analysis = self.analyze_received_message(received_data)
            if analysis['message_class'] == 'control' and analysis['details'].get('message_type') == 'NACK':
                logger.error("Received NACK instead of ACK0 - handshake rejected")
        return False
    
    # Send identification frame with DLE SOH
    comm_id = "XYZ1234567"  # 10-digit Communication ID
    op_request = "R"        # R = Read audit data
    rev_level = "R00L06"    # Revision and level (EVA-DTS 6.0+)
    
    frame_data = f"{comm_id}{op_request}{rev_level}".encode('ascii')
    frame = self.build_frame(frame_data)
    
    if not self.send_bytes(frame):
        logger.error("Failed to send identification frame")
        return False
    
    # Wait for DLE 1 (ACK 1) with analysis
    dle_1 = self.wait_for_sequence(bytes([DEXConstants.DLE, ord('1')]), 
                                  timeout=DEXConstants.HANDSHAKE_TIMEOUT)
    if not dle_1:
        logger.error("No DLE 1 received from VMD")
        # Check if we received a NACK instead
        received_data = self.get_last_received_data()  # You'd need to implement this
        if received_data:
            analysis = self.analyze_received_message(received_data)
            if analysis['message_class'] == 'control' and analysis['details'].get('message_type') == 'NACK':
                logger.error("Received NACK instead of ACK1 - identification frame rejected")
        return False
    
    # Send EOT to complete First Handshake
    if not self.send_bytes(bytes([DEXConstants.EOT])):
        logger.error("Failed to send EOT")
        return False
    
    logger.info("First Handshake completed successfully")
    return True

def build_frame(self, data: bytes) -> bytes:
    """Build a DEX frame with DLE SOH, data, DLE ETX, and CRC"""
    frame = bytearray([DEXConstants.DLE, DEXConstants.SOH])
    frame.extend(data)
    frame.extend([DEXConstants.DLE, DEXConstants.ETX])
    
    # Calculate CRC on data plus ETX (excluding DLEs)
    crc_data = bytearray(data)
    crc_data.append(DEXConstants.ETX)
    crc = self.crc_calc.calculate(crc_data)
    
    # Add CRC bytes (LSB first, MSB second)
    frame.append(crc & 0xFF)
    frame.append((crc >> 8) & 0xFF)
    
    return bytes(frame)

def main():
    # ... existing code ...
    
    # Perform data dump
    dex_data, machine_info = dex.dump_dex_data()
    
    if dex_data and machine_info:
        print(f"Successfully received {len(dex_data)} bytes of DEX data")
        print("\nMachine Information:")
        print(f"  Response Code: {machine_info.get('response_code', 'Not found')}")
        print(f"  VMC ID: {machine_info.get('vmc_id', 'Not found')}")
        print(f"  Revision: {machine_info.get('revision', 'Not found')}")
        print(f"  Level: {machine_info.get('level', 'Not found')}")
        
        # Save both data and machine info
        filename = save_dex_data(dex_data, args.output)
        if filename:
            print(f"Data saved to: {filename}")
            
            # Also save machine info
            info_filename = filename.replace('.txt', '_machine_info.txt')
            with open(info_filename, 'w') as f:
                for key, value in machine_info.items():
                    f.write(f"{key}: {value}\n")
            print(f"Machine info saved to: {info_filename}")