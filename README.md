# DEX-CRC-reverse-engineering
Simple proof of concept (or failure) to reverse engineer the CRC check and initialization values used by an unknown DEX protocol machine in response to ENQ

# Crane 423 Shopper Results

=== MATCHING ALGORITHMS FOUND ===

Match 1:
  Algorithm:        DEX_CUSTOM (XORed)
  Frame Tested:     Normal Frame Order
  CRC Location:     CRC at End
  Data Processing:  Raw Data
  Initial Value:    0x0000
  Final XOR Applied:0x0d4d
  Calculated CRC:   0x9b75
  Matched Target:   LE

Let's break down what this means:
Algorithm: DEX_CUSTOM (XORed)
This refers to your C++ logger's dex_crc16 algorithm (which we ported to calculate_crc16_dex_custom in Python).
The "(XORed)" part means the match was found after applying the final XOR value of 0x0D4D to the result of the calculate_crc16_dex_custom function.
Frame Tested: Normal Frame Order
The match was found using the frame bytes exactly as they appear in your log: 10 01 43 4e ... 10 03 75 9b. No byte-pair swapping of the entire frame was needed.
CRC Location: CRC at End
The script correctly identified the CRC bytes as the last two bytes of the frame (75 9b).
Data Processing: Raw Data
The CRC was calculated on the data portion: 10 01 43 4e 56 20 20 20 44 45 33 32 53 52 30 31 4c 30 31 10 03. This is the segment from DLE SOH up to and including DLE ETX, exactly as your C++ logger calculates it. No DLE filtering was needed for the match.
Initial Value: 0x0000
The calculate_crc16_dex_custom function was called with an initial CRC value of 0x0000. This aligns with how your C++ logger initializes its CRC calculation: uint16_t calculatedCRC = 0x0000;.
Final XOR Applied: 0x0D4D
After calculate_crc16_dex_custom (with initial 0x0000) produced 0x9638 (as we know from the C++ logger and previous Python runs), XORing this result with 0x0D4D yielded 0x9B75.
(0x9638 ^ 0x0D4D = 0x9B75)
Calculated CRC: 0x9B75
This is the final value after the custom calculation and the subsequent XOR.
Matched Target: LE (Little-Endian)
The extracted CRC bytes 75 9b were interpreted as 0x9B75 (Little-Endian: 9b is MSB, 75 is LSB). This matches how your C++ logger interprets the received CRC: static_cast<uint16_t>(data[21]) | (static_cast<uint16_t>(data[22]) << 8); where data[21] is 0x75 (LSB) and data[22] is 0x9B (MSB).
Conclusion:
The Vending Machine Controller (VMC) appears to be using the following process to generate its CRC:
It calculates a 16-bit CRC using the exact same algorithm as your dex_logger.cpp's dex_crc16 function.
It initializes this CRC calculation with 0x0000.
After the CRC calculation is complete (resulting in 0x9638 for this specific frame's data), it performs a final XOR operation with the value 0x0D4D.
The result of this XOR (0x9B75) is then transmitted as the CRC, with the Least Significant Byte (0x75) first, followed by the Most Significant Byte (0x9B)