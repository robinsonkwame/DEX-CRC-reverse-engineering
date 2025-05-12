from enum import Enum, auto
from typing import List, Optional
import logging

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
    WAITING_FOR_ACK = auto()
    WAITING_FOR_RESPONSE = auto()
    PROCESSING_RESPONSE = auto()
    ERROR = auto()

class DEXStateMachine:
    def __init__(self):
        self.state = DEXState.IDLE
        self.buffer: List[int] = []
        self.logger = logging.getLogger(__name__)

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

    def handle_enq(self) -> List[int]:
        """Handle ENQ request from vending machine."""
        if self.state == DEXState.IDLE:
            self.state = DEXState.WAITING_FOR_ACK
            # Send ACK
            return [DLE, ACK]
        return []

    def handle_ack(self) -> Optional[List[int]]:
        """Handle ACK from vending machine."""
        if self.state == DEXState.WAITING_FOR_ACK:
            self.state = DEXState.WAITING_FOR_RESPONSE
            # Example: Send a status request
            return self.format_message([0x01, 0x43, 0x4E, 0x56])  # CNV
        return None

    def process_response(self, data: List[int]) -> bool:
        """Process response from vending machine."""
        if len(data) < 4:  # Minimum length for a valid message
            return False

        # Verify CRC
        received_crc = (data[-1] << 8) | data[-2]  # Little-endian
        calculated_crc = self.calculate_crc(data[:-2])
        
        if received_crc != calculated_crc:
            self.logger.error(f"CRC mismatch: received {hex(received_crc)}, calculated {hex(calculated_crc)}")
            return False

        # Process the message content
        self.state = DEXState.IDLE
        return True

    def handle_byte(self, byte: int) -> Optional[List[int]]:
        """Handle incoming byte and return response if needed."""
        if byte == ENQ:
            return self.handle_enq()
        elif byte == ACK:
            return self.handle_ack()
        elif byte == DLE:
            self.buffer = [byte]
        elif self.buffer and self.buffer[0] == DLE:
            self.buffer.append(byte)
            if byte == ETX:
                if self.process_response(self.buffer):
                    self.state = DEXState.IDLE
                else:
                    self.state = DEXState.ERROR
                self.buffer = []
        return None
