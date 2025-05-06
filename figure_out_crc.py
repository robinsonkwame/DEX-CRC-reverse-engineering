import sys

# CRC calculation functions
def reflect_byte(byte_val):
    reflected = 0
    for i in range(8):
        if (byte_val >> i) & 1:
            reflected |= 1 << (7 - i)
    return reflected

def reflect_word(word_val):
    reflected = 0
    for i in range(16):
        if (word_val >> i) & 1:
            reflected |= 1 << (15 - i)
    return reflected

def crc16_generic(data_bytes, poly, init_crc, ref_in, ref_out, xor_out, is_right_shifting=True):
    """
    Generic CRC-16 calculation function.
    - poly: The polynomial. If is_right_shifting, this should be the reflected polynomial.
            If not is_right_shifting (i.e., left-shifting), this should be the normal polynomial.
    - init_crc: Initial CRC value.
    - ref_in: Boolean, if True, reflect each input byte.
    - ref_out: Boolean, if True, reflect the final CRC value.
    - xor_out: Value to XOR with the final CRC.
    - is_right_shifting: Boolean, True for LSB-first (right-shifting) logic,
                         False for MSB-first (left-shifting) logic.
    """
    crc = init_crc

    for byte_val in data_bytes:
        actual_byte = reflect_byte(byte_val) if ref_in else byte_val
        
        if is_right_shifting:
            crc = crc ^ actual_byte  # XOR with byte (or LSB of CRC register)
            for _ in range(8):
                if crc & 0x0001: # If LSB is 1
                    crc = (crc >> 1) ^ poly
                else:
                    crc = crc >> 1
        else:  # Left-shifting
            crc = crc ^ (actual_byte << 8) # XOR with byte in MSB position of CRC
            for _ in range(8):
                if crc & 0x8000: # If MSB is 1
                    crc = ((crc << 1) ^ poly) & 0xFFFF
                else:
                    crc = (crc << 1) & 0xFFFF
    
    final_crc = reflect_word(crc) if ref_out else crc
    return final_crc ^ xor_out

# Custom DEX CRC from the C++ logger (remains specific)
def calculate_crc16_dex_custom(data_bytes, initial_value=0x0000):
    crc = initial_value
    for byte in data_bytes:
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

# Predefined CRC algorithms
# Normal Poly is the standard representation (e.g., 0x8005 for x^16+x^15+x^2+1)
# Reflected Poly is its bit-reversed form (e.g., 0xA001 for 0x8005)
# The 'poly_for_method' is what crc16_generic expects based on 'is_right_shifting'
PREDEFINED_ALGORITHMS = [
    {
        "name": "CRC-16/MODBUS", "normal_poly": 0x8005, "poly_for_method": 0xA001, 
        "init": 0xFFFF, "ref_in": True, "ref_out": True, "xor_out": 0x0000, 
        "is_right_shifting": True
    },
    {
        "name": "CRC-16/CCITT-FALSE", "normal_poly": 0x1021, "poly_for_method": 0x1021,
        "init": 0xFFFF, "ref_in": False, "ref_out": False, "xor_out": 0x0000,
        "is_right_shifting": False # Typically left-shifting
    },
    {
        "name": "CRC-16/XMODEM", "normal_poly": 0x1021, "poly_for_method": 0x1021, 
        "init": 0x0000, "ref_in": False, "ref_out": False, "xor_out": 0x0000,
        "is_right_shifting": False # Often left-shifting
    },
    { # Also known as CRC-16/A or CRC-16/CCITT-TRUE
        "name": "CRC-16/KERMIT", "normal_poly": 0x1021, "poly_for_method": 0x8408,
        "init": 0x0000, "ref_in": True, "ref_out": True, "xor_out": 0x0000,
        "is_right_shifting": True
    },
    { # MAXIM-DOW
        "name": "CRC-16/MAXIM", "normal_poly": 0x8005, "poly_for_method": 0xA001,
        "init": 0x0000, "ref_in": True, "ref_out": True, "xor_out": 0xFFFF,
        "is_right_shifting": True
    },
    {
        "name": "CRC-16/USB", "normal_poly": 0x8005, "poly_for_method": 0xA001,
        "init": 0xFFFF, "ref_in": True, "ref_out": True, "xor_out": 0xFFFF,
        "is_right_shifting": True
    },
    { # From image: CRC16_CCITT_ZERO
        "name": "CRC-16/CCITT-ZERO", "normal_poly": 0x1021, "poly_for_method": 0x1021,
        "init": 0x0000, "ref_in": False, "ref_out": False, "xor_out": 0x0000,
        "is_right_shifting": False
    },
    # Add more from the image if parameters can be reliably found
    # ARC, AUG_CCITT, BUYPASS, CDMA2000, DDS_110, DECT_R, DECT_X, DNP, EN_13757, GENIBUS, MCRF4XX, RIELLO, T10_DIF, TELEDISK, TMS37157, X_25
]

def byte_pair_swap(data):
    result = bytearray()
    for i in range(0, len(data) - 1, 2):
        result.append(data[i+1])
        result.append(data[i])
    if len(data) % 2 != 0:
        result.append(data[-1])
    return bytes(result)

def analyze_frame_crc(full_frame_hex, show_all=True): # always show all = True
    original_frame_bytes = bytes.fromhex(full_frame_hex.replace(" ", ""))

    if len(original_frame_bytes) < 3:
        print("Frame too short.")
        return []

    frame_endian_variations = [
        ("Normal Frame Order", original_frame_bytes),
        ("Byte-Pair Swapped Frame", byte_pair_swap(original_frame_bytes)),
    ]

    all_found_matches = []
    
    # Header for overall results
    # Adjusted column widths slightly
    header_format = "{:<25} {:<12} {:<12} {:<23} {:<6} {:<7} {:<7} {:<7} {:<7} {:<10} {:<8}"
    if show_all:
        print(header_format.format(
            "Algorithm", "Frame Type", "CRC Loc", "Data Bytes Used", "Init", "Poly", "RefIn", "RefOut", "XOROut", "Result", "Matches"
        ))
        print("-" * 128) # Adjusted separator length

    for frame_label, current_frame_bytes in frame_endian_variations:
        print(f"\n=== Testing Frame: {frame_label} ({' '.join(f'{b:02x}' for b in current_frame_bytes)}) ===")

        crc_location_variations = [
            ("CRC at End", current_frame_bytes[:-2], current_frame_bytes[-2:]),
            ("CRC at Start", current_frame_bytes[2:], current_frame_bytes[:2]),
        ]

        for crc_loc_label, data_for_crc, extracted_crc_bytes in crc_location_variations:
            if not data_for_crc or not extracted_crc_bytes or len(extracted_crc_bytes) != 2:
                continue

            target_crc_be = (extracted_crc_bytes[0] << 8) | extracted_crc_bytes[1]
            target_crc_le = (extracted_crc_bytes[1] << 8) | extracted_crc_bytes[0]

            print(f"  --- CRC Location: {crc_loc_label} (Extracted Bytes: {extracted_crc_bytes[0]:02x} {extracted_crc_bytes[1]:02x}) ---")
            print(f"      Data for CRC: {' '.join(f'{b:02x}' for b in data_for_crc)}")
            print(f"      Target CRC (BE): 0x{target_crc_be:04x}, Target CRC (LE): 0x{target_crc_le:04x}")

            data_processing_variations = [
                ("Raw Data", data_for_crc),
                ("No DLE-SOH/ETX", bytes([b for i, b in enumerate(data_for_crc) 
                                   if not (i > 0 and data_for_crc[i-1] == 0x10 and b in [0x01, 0x03])]))
            ]

            for data_label, current_data_bytes in data_processing_variations:
                
                # Test Predefined Algorithms
                for algo_params in PREDEFINED_ALGORITHMS:
                    calculated_crc = crc16_generic(
                        current_data_bytes,
                        poly=algo_params["poly_for_method"],
                        init_crc=algo_params["init"],
                        ref_in=algo_params["ref_in"],
                        ref_out=algo_params["ref_out"],
                        xor_out=algo_params["xor_out"],
                        is_right_shifting=algo_params["is_right_shifting"]
                    )
                    
                    match_type = None
                    if calculated_crc == target_crc_be: match_type = "BE"
                    elif calculated_crc == target_crc_le: match_type = "LE"
                    
                    if match_type or show_all:
                        print(header_format.format(
                            algo_params['name'], frame_label[:10], crc_loc_label[:10], data_label[:21], 
                            f"0x{algo_params['init']:04x}", f"0x{algo_params['normal_poly']:04x}", 
                            str(algo_params['ref_in']), str(algo_params['ref_out']), f"0x{algo_params['xor_out']:04x}",
                            f"0x{calculated_crc:04x}", match_type if match_type else ""
                        ))
                    if match_type:
                        all_found_matches.append({**algo_params, "frame_label":frame_label, "crc_loc_label": crc_loc_label, "data_label":data_label, "calculated_crc": calculated_crc, "matched_target": match_type})
                
                # Test Custom DEX Algorithm
                dex_init_values = [0x0000, 0xFFFF] 
                final_xor_for_dex = 0x0D4D # XOR difference (0x9B75 ^ 0x9638)

                for dex_init in dex_init_values:
                    # Standard DEX_CUSTOM calculation
                    calculated_dex_crc = calculate_crc16_dex_custom(current_data_bytes, dex_init)
                    match_type_dex = None
                    if calculated_dex_crc == target_crc_be: match_type_dex = "BE"
                    elif calculated_dex_crc == target_crc_le: match_type_dex = "LE"

                    if match_type_dex or show_all:
                         print(header_format.format(
                            "DEX_CUSTOM", frame_label[:10], crc_loc_label[:10], data_label[:21], 
                            f"0x{dex_init:04x}", "N/A", "N/A", "N/A", "N/A", 
                            f"0x{calculated_dex_crc:04x}", match_type_dex if match_type_dex else ""
                        ))
                    if match_type_dex:
                         all_found_matches.append({"name": "DEX_CUSTOM", "init": dex_init, "frame_label":frame_label, "crc_loc_label": crc_loc_label, "data_label":data_label, "calculated_crc": calculated_dex_crc, "matched_target": match_type_dex, "final_xor_applied": 0x0000})
                    
                    # DEX_CUSTOM calculation with final XOR
                    calculated_dex_crc_xored = calculated_dex_crc ^ final_xor_for_dex
                    match_type_dex_xored = None
                    if calculated_dex_crc_xored == target_crc_be: match_type_dex_xored = "BE"
                    elif calculated_dex_crc_xored == target_crc_le: match_type_dex_xored = "LE"

                    if match_type_dex_xored or show_all:
                         print(header_format.format(
                            "DEX_CUSTOM (XORed)", frame_label[:10], crc_loc_label[:10], data_label[:21], 
                            f"0x{dex_init:04x}", "N/A", "N/A", "N/A", f"0x{final_xor_for_dex:04x}", 
                            f"0x{calculated_dex_crc_xored:04x}", match_type_dex_xored if match_type_dex_xored else ""
                        ))
                    if match_type_dex_xored:
                         all_found_matches.append({"name": "DEX_CUSTOM (XORed)", "init": dex_init, "frame_label":frame_label, "crc_loc_label": crc_loc_label, "data_label":data_label, "calculated_crc": calculated_dex_crc_xored, "matched_target": match_type_dex_xored, "final_xor_applied": final_xor_for_dex})

    if all_found_matches:
        print("\n=== MATCHING ALGORITHMS FOUND ===")
        for i, match in enumerate(all_found_matches):
            print(f"\nMatch {i+1}:")
            print(f"  Algorithm:        {match['name']}")
            print(f"  Frame Tested:     {match['frame_label']}")
            print(f"  CRC Location:     {match['crc_loc_label']}")
            print(f"  Data Processing:  {match['data_label']}")
            if match['name'] not in ["DEX_CUSTOM", "DEX_CUSTOM (XORed)"]:
                print(f"  Poly (Normal):    0x{match.get('normal_poly', match.get('poly',0)):04x}")
                print(f"  Initial Value:    0x{match['init']:04x}")
                print(f"  Reflect Input:    {match['ref_in']}")
                print(f"  Reflect Output:   {match['ref_out']}")
                print(f"  XOR Output:       0x{match['xor_out']:04x}")
            else: # For DEX_CUSTOM variants
                print(f"  Initial Value:    0x{match['init']:04x}")
                if match['name'] == "DEX_CUSTOM (XORed)":
                    print(f"  Final XOR Applied:0x{match['final_xor_applied']:04x}")
            print(f"  Calculated CRC:   0x{match['calculated_crc']:04x}")
            print(f"  Matched Target:   {match['matched_target']}")
    else:
        print("\n=== NO MATCHING ALGORITHMS FOUND ===")

    return all_found_matches

# Main execution
if __name__ == "__main__":
    # Frame from the log: 10 01 ... 10 03 (data) 75 9b (CRC)
    # The C++ logger calculates CRC on bytes 0-20 (21 bytes) for this frame.
    # And interprets the received 75 9b as 0x9B75.
    # It calculates 0x9638 for its own dex_crc16(0, data[0..20]).
    test_frame_hex = "10 01 43 4e 56 20 20 20 44 45 33 32 53 52 30 31 4c 30 31 10 03 75 9b"
    
    print(f"Starting CRC analysis for frame: {test_frame_hex}")
    analyze_frame_crc(test_frame_hex, show_all=True)