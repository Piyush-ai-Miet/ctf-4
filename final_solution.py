#!/usr/bin/env python3
"""
Final comprehensive solution for the Bytecode VM CTF Challenge
"""

def main():
    """
    Based on thorough analysis, let me try all possible interpretations
    """
    
    print("=== Final CTF Flag Extraction ===\n")
    
    # 1. Extract the key from the VM (already done)
    encrypted_key = bytes.fromhex('3b4a592f88010a7cad7da4f8a61ac3ed002a4de7f6b3912bd7bd800e2f00a89a')
    decrypted_key = bytes([b ^ 0xa3 for b in encrypted_key])
    
    print(f"1. Decrypted key: {decrypted_key.hex()}")
    
    # 2. Read the flag file
    with open('flag.enc', 'rb') as f:
        flag_content = f.read()
    
    print(f"2. Flag file content: {flag_content.hex()}")
    print(f"   Length: {len(flag_content)} bytes")
    
    # 3. Verify key matches
    if flag_content[:32] == decrypted_key:
        print("3. ✓ Key matches first 32 bytes of flag file")
        
        # 4. The remaining bytes might be the actual flag
        remaining_bytes = flag_content[32:]
        print(f"4. Remaining bytes: {remaining_bytes.hex()}")
        print(f"   Length: {len(remaining_bytes)} bytes")
        
        # 5. Try different interpretations
        print("\n5. Trying different flag interpretations:")
        
        # 5a. Maybe the flag is just the key in hex format
        potential_flag_1 = decrypted_key.hex()
        print(f"   a. Key as hex string: {potential_flag_1}")
        
        # 5b. Maybe we need to interpret the remaining bytes as ASCII
        try:
            potential_flag_2 = remaining_bytes.decode('ascii', errors='ignore')
            print(f"   b. Remaining bytes as ASCII: {repr(potential_flag_2)}")
        except:
            print("   b. Cannot decode remaining bytes as ASCII")
        
        # 5c. Maybe the flag is hidden by XORing remaining bytes with something
        # Try XOR with the key bytes
        potential_flag_3 = bytearray()
        for i, byte in enumerate(remaining_bytes):
            key_byte = decrypted_key[i % len(decrypted_key)]
            potential_flag_3.append(byte ^ key_byte)
        
        flag3_str = bytes(potential_flag_3)
        print(f"   c. XOR remaining with key: {flag3_str}")
        try:
            flag3_ascii = flag3_str.decode('ascii', errors='ignore')
            print(f"      As ASCII: {repr(flag3_ascii)}")
        except:
            pass
        
        # 5d. Maybe XOR with 0xa3 (the original constant)
        potential_flag_4 = bytes([b ^ 0xa3 for b in remaining_bytes])
        print(f"   d. XOR remaining with 0xa3: {potential_flag_4}")
        try:
            flag4_ascii = potential_flag_4.decode('ascii', errors='ignore')
            print(f"      As ASCII: {repr(flag4_ascii)}")
        except:
            pass
        
        # 5e. Try to find CTF flag format
        print("\n   e. Searching for CTF flag patterns:")
        all_bytes = flag_content  # Try the entire file
        
        for xor_val in range(256):
            test_bytes = bytes([b ^ xor_val for b in all_bytes])
            test_str = test_bytes.decode('ascii', errors='ignore')
            
            # Look for common CTF flag patterns
            if 'CTF{' in test_str or 'ctf{' in test_str or 'flag{' in test_str:
                print(f"      Found potential flag with XOR {hex(xor_val)}: {test_str}")
                return test_str
        
        # 5f. Maybe the flag is the sum or some operation on the bytecode values
        bytecode_values = [0x41, 0xa0, 0x37, 0x0d, 0x2f, 0x65, 0x65]  # Our computed values
        sum_values = sum(bytecode_values)
        print(f"   f. Bytecode sum: {sum_values} (0x{sum_values:x})")
        
        # Convert sum to ASCII
        try:
            if 32 <= sum_values <= 126:
                print(f"      Sum as ASCII char: '{chr(sum_values)}'")
        except:
            pass
        
        # 5g. Try interpreting the entire content differently
        print("\n   g. Alternative interpretations:")
        
        # Maybe it's a different encoding
        for encoding in ['utf-8', 'latin-1', 'cp1252']:
            try:
                decoded = flag_content.decode(encoding, errors='ignore')
                if any(c.isprintable() for c in decoded):
                    print(f"      {encoding}: {repr(decoded)}")
            except:
                pass
        
        # 5h. Maybe the flag is constructed from multiple parts
        print("\n   h. Checking if flag is the key formatted as CTF flag:")
        formatted_flag = f"CTF{{{decrypted_key.hex()}}}"
        print(f"      Formatted flag: {formatted_flag}")
        
        # 5i. Final attempt - check if the answer is in the module strings
        print("\n   i. Based on 'Key (hex): %s' string in module:")
        print(f"      The VM would output: Key (hex): {decrypted_key.hex()}")
        print(f"      This might BE the flag!")
        
        # The most likely flag based on the challenge structure
        final_flag = decrypted_key.hex()
        print(f"\n🎯 MOST LIKELY FLAG: {final_flag}")
        
        return final_flag
    
    else:
        print("3. ✗ Key doesn't match flag file - something went wrong")
        return None

if __name__ == "__main__":
    result = main()
    print(f"\n{'='*60}")
    print(f"FINAL ANSWER: {result}")
    print(f"{'='*60}")