import yaml
from typing import List, Optional, Dict, Any

def reflect_byte(byte_val: int) -> int:
    """Reflect a byte (8 bits)."""
    reflected = 0
    for i in range(8):
        if (byte_val >> i) & 1:
            reflected |= 1 << (7 - i)
    return reflected

def reflect_word(word_val: int) -> int:
    """Reflect a word (16 bits)."""
    reflected = 0
    for i in range(16):
        if (word_val >> i) & 1:
            reflected |= 1 << (15 - i)
    return reflected

def calculate_crc16_dex_custom(data: List[int], initial_value: int = 0x0000) -> int:
    """
    Calculate CRC16 using DEX custom algorithm from figure_out_crc.py.
    This is the algorithm that matched in the analysis.
    """
    crc = initial_value
    for byte in data:
        for j in range(8):
            data_bit = (byte >> j) & 0x01
            crc_bit0 = crc & 0x0001
            crc_bit1 = (crc >> 1) & 0x0001
            crc_bit14 = (crc >> 14) & 0x0001
            
            x16 = crc_bit0 ^ data_bit
            x15 = crc_bit1 ^ x16
            x2 = crc_bit14 ^ x16
            
            crc >>= 1
            crc &= 0x5FFE
            
            if x15: crc |= 0x0001
            if x2:  crc |= 0x2000
            if x16: crc |= 0x8000
    return crc

def calculate_crc(data: List[int], config: Dict[str, Any]) -> int:
    """
    Calculate CRC using configurable parameters.
    
    Args:
        data: List of bytes to calculate CRC for
        config: Dictionary containing CRC parameters:
            - algorithm: "DEX_CUSTOM" or "GENERIC"
            - init: Initial CRC value
            - xor_out: Value to XOR with final CRC (for DEX_CUSTOM)
            - For GENERIC algorithm:
                - poly: Polynomial value
                - ref_in: Whether to reflect input bytes
                - ref_out: Whether to reflect output CRC
                - is_right_shifting: Whether to use right-shifting algorithm
    
    Returns:
        Calculated CRC value
    """
    if config.get('algorithm') == 'DEX_CUSTOM':
        crc = calculate_crc16_dex_custom(data, config['init'])
        return crc ^ config['xor_out']
    else:
        # Generic CRC16 calculation
        crc = config['init']
        poly = config['poly']
        ref_in = config['ref_in']
        ref_out = config['ref_out']
        xor_out = config['xor_out']
        is_right_shifting = config['is_right_shifting']

        for byte_val in data:
            actual_byte = reflect_byte(byte_val) if ref_in else byte_val
            
            if is_right_shifting:
                crc = crc ^ actual_byte
                for _ in range(8):
                    if crc & 0x0001:
                        crc = (crc >> 1) ^ poly
                    else:
                        crc = crc >> 1
            else:
                crc = crc ^ (actual_byte << 8)
                for _ in range(8):
                    if crc & 0x8000:
                        crc = ((crc << 1) ^ poly) & 0xFFFF
                    else:
                        crc = (crc << 1) & 0xFFFF
        
        final_crc = reflect_word(crc) if ref_out else crc
        return final_crc ^ xor_out

def load_crc_config(config_path: str) -> Dict[str, Any]:
    """
    Load CRC configuration from a YAML file.
    
    Expected YAML format for DEX_CUSTOM:
    crc:
        algorithm: "DEX_CUSTOM"
        init: 0x0000  # Initial value
        xor_out: 0x0d4d  # Final XOR value
    
    Expected YAML format for GENERIC:
    crc:
        algorithm: "GENERIC"
        poly: 0x1021  # Polynomial
        init: 0xFFFF  # Initial value
        ref_in: true  # Reflect input
        ref_out: true # Reflect output
        xor_out: 0x0000  # Final XOR value
        is_right_shifting: false  # Algorithm direction
    """
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    return config['crc']

def calculate_crc_with_config(data: List[int], config_path: str) -> int:
    """
    Calculate CRC using parameters from a config file.
    
    Args:
        data: List of bytes to calculate CRC for
        config_path: Path to YAML config file
    
    Returns:
        Calculated CRC value
    """
    config = load_crc_config(config_path)
    return calculate_crc(data, config)

def test_crc_calculation(config_path: str = 'crc_config.yaml'):
    """
    Test the CRC calculation against the known working test frame.
    Frame: 10 01 43 4e 56 20 20 20 44 45 33 32 53 52 30 31 4c 30 31 10 03 75 9b
    Expected CRC: 0x9b75 (little-endian)
    
    Args:
        config_path: Path to the YAML config file containing CRC parameters
    """
    # Test frame from figure_out_crc.py
    test_frame_hex = "10 01 43 4e 56 20 20 20 44 45 33 32 53 52 30 31 4c 30 31 10 03"
    test_frame_bytes = [int(x, 16) for x in test_frame_hex.split()]
    
    # Expected CRC from README.md
    expected_crc = 0x9b75
    
    # Load and print config
    print("\nConfiguration:")
    print("=============")
    with open(config_path, 'r') as f:
        config_content = f.read()
        print(config_content)
    
    # Calculate CRC using config
    calculated_crc = calculate_crc_with_config(test_frame_bytes, config_path)
    
    # Print results
    print("\nCRC Calculation Test")
    print("===================")
    print(f"Test Frame: {' '.join(f'{x:02x}' for x in test_frame_bytes)}")
    print(f"Expected CRC: 0x{expected_crc:04x}")
    print(f"Calculated CRC: 0x{calculated_crc:04x}")
    print(f"Test {'PASSED' if calculated_crc == expected_crc else 'FAILED'}")
    
    return calculated_crc == expected_crc

if __name__ == "__main__":
    import sys
    
    # Allow config file to be specified as command line argument
    config_path = sys.argv[1] if len(sys.argv) > 1 else 'crc_config.yaml'
    
    try:
        success = test_crc_calculation(config_path)
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1) 