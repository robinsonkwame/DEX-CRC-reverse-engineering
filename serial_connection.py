import serial
import logging
from typing import Optional

class SerialConnection:
    def __init__(self):
        self.serial_port: Optional[serial.Serial] = None
        self.logger = logging.getLogger(__name__)

    def connect(self, port: str = "/dev/cu.usbmodem5B43E73635381", 
                baud_rate: int = 9600,
                data_bits: int = 8,
                stop_bits: int = 1,
                parity: str = "none",
                use_hardware_flow_control: bool = False) -> bool:
        """
        Connect to the serial port with specified settings.
        
        Args:
            port: Serial port path
            baud_rate: Baud rate (default: 9600)
            data_bits: Number of data bits (default: 8)
            stop_bits: Number of stop bits (default: 1)
            parity: Parity setting (default: "none")
            use_hardware_flow_control: Whether to use hardware flow control (default: False)
            
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            self.serial_port = serial.Serial(
                port=port,
                baudrate=baud_rate,
                bytesize=data_bits,
                stopbits=stop_bits,
                parity=parity[0].upper(),  # Convert "none" to "N", "even" to "E", etc.
                rtscts=use_hardware_flow_control,
                timeout=1  # 1 second timeout for read operations
            )
            self.logger.info(f"Successfully connected to {port}")
            return True
        except serial.SerialException as e:
            self.logger.error(f"Failed to connect to {port}: {str(e)}")
            return False

    def disconnect(self) -> None:
        """Close the serial connection if it's open."""
        if self.serial_port and self.serial_port.is_open:
            self.serial_port.close()
            self.logger.info("Serial connection closed")

    def read_byte(self) -> Optional[int]:
        """Read a single byte from the serial port."""
        if not self.serial_port or not self.serial_port.is_open:
            return None
        try:
            return self.serial_port.read(1)[0]
        except (IndexError, serial.SerialException) as e:
            self.logger.error(f"Error reading from serial port: {str(e)}")
            return None

    def write_bytes(self, data: bytes) -> bool:
        """Write bytes to the serial port."""
        if not self.serial_port or not self.serial_port.is_open:
            return False
        try:
            self.serial_port.write(data)
            return True
        except serial.SerialException as e:
            self.logger.error(f"Error writing to serial port: {str(e)}")
            return False

    def is_connected(self) -> bool:
        """Check if the serial connection is open."""
        return self.serial_port is not None and self.serial_port.is_open 