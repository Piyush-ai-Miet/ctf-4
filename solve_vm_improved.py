#!/usr/bin/env python3
"""
Improved Bytecode VM CTF Challenge Solver

This script simulates the VM logic to find the correct bytecode sequence
and extracts the flag.
"""

def simulate_vm_logic(bytecode):
    """
    Simulate the VM logic based on the assembly analysis.
    
    The VM appears to:
    1. Read stack values from specific positions
    2. Validate ranges for each position  
    3. Sum all values and check against 0x21e
    4. If valid, decrypt and return the key
    """
    
    if len(bytecode) < 7:
        print("Bytecode too short")
        return False
        
    # The VM reads from stack positions and validates ranges
    # Based on the assembly analysis:
    stack = list(bytecode[:7])  # First 7 bytes become stack values
    
    print(f"Stack values: {[hex(v) for v in stack]}")
    
    # Range validations from the assembly
    checks = [
        (stack[0] - 0x1f, 0x22),   # (value - 0x1f) <= 0x22
        (stack[1] - 0x26, 0xb6),   # (value - 0x26) <= 0xb6  
        (stack[2] - 0x37, 0x21),   # (value - 0x37) <= 0x21
        (stack[3] - 0xd, 0x5b),    # (value - 0xd) <= 0x5b
        (stack[4] - 0x2f, 0x2c),   # (value - 0x2f) <= 0x2c
        (stack[5] - 0x65, 0x83),   # (value - 0x65) <= 0x83
        (stack[6] - 0x65, 0x10),   # (value - 0x65) <= 0x10
    ]
    
    valid = True
    for i, (diff, max_diff) in enumerate(checks):
        if diff > max_diff or diff < 0:
            print(f"✗ Range check {i} failed: {diff} > {max_diff}")
            valid = False
        else:
            print(f"✓ Range check {i} passed: {diff} <= {max_diff}")
    
    # Sum check
    total = sum(stack)
    print(f"Sum: {total} (0x{total:x}) vs target 0x21e ({0x21e})")
    
    if total != 0x21e:
        print(f"✗ Sum check failed: {total} != {0x21e}")
        valid = False
    else:
        print("✓ Sum check passed")
    
    return valid

def decrypt_key():
    """Decrypt the key from the VM"""
    # Key from .rodata section 
    encrypted_key = bytes.fromhex('3b4a592f88010a7cad7da4f8a61ac3ed002a4de7f6b3912bd7bd800e2f00a89a')
    decrypted_key = bytes([b ^ 0xa3 for b in encrypted_key])
    return decrypted_key

def find_valid_bytecode():
    """Find a valid bytecode sequence that passes all checks"""
    
    target_sum = 0x21e  # 542
    
    # Define the valid ranges for each position
    ranges = [
        (0x1f, 0x1f + 0x22),  # [0x1f, 0x41]
        (0x26, 0x26 + 0xb6),  # [0x26, 0xdc] 
        (0x37, 0x37 + 0x21),  # [0x37, 0x58]
        (0xd, 0xd + 0x5b),    # [0xd, 0x68]
        (0x2f, 0x2f + 0x2c),  # [0x2f, 0x5b]
        (0x65, 0x65 + 0x83),  # [0x65, 0xe8]
        (0x65, 0x65 + 0x10),  # [0x65, 0x75]
    ]
    
    print("Valid ranges for each position:")
    for i, (min_val, max_val) in enumerate(ranges):
        print(f"  Position {i}: [{hex(min_val)}, {hex(max_val)}] (range: {max_val - min_val + 1})")
    
    # Start with minimum values
    values = [r[0] for r in ranges]
    current_sum = sum(values)
    needed = target_sum - current_sum
    
    print(f"\nStarting with min values: {[hex(v) for v in values]}")
    print(f"Sum: {current_sum}, need to add: {needed}")
    
    # Distribute the needed amount
    for i in range(len(values)):
        min_val, max_val = ranges[i]
        available = max_val - values[i]
        add_amount = min(needed, available)
        values[i] += add_amount
        needed -= add_amount
        print(f"  Position {i}: add {add_amount}, new value: {hex(values[i])}")
        if needed == 0:
            break
    
    if needed > 0:
        print(f"✗ Cannot satisfy sum requirement, still need {needed}")
        return None
        
    final_sum = sum(values)
    print(f"\nFinal values: {[hex(v) for v in values]}")
    print(f"Final sum: {final_sum} (0x{final_sum:x})")
    
    # Verify the solution
    bytecode = bytes(values)
    if simulate_vm_logic(bytecode):
        print("✓ Found valid bytecode!")
        return bytecode
    else:
        print("✗ Bytecode validation failed")
        return None

def try_decrypt_flag(key):
    """Try to decrypt the flag using various methods"""
    
    with open('flag.enc', 'rb') as f:
        content = f.read()
    
    print(f"Flag file length: {len(content)}")
    print(f"Key length: {len(key)}")
    
    # The first 32 bytes match our key, so the flag is the rest
    if content[:32] == key:
        print("✓ Key matches first 32 bytes of flag.enc")
        encrypted_flag = content[32:]
        print(f"Encrypted flag length: {len(encrypted_flag)}")
        
        # Try XOR decryption with the key
        decrypted = bytearray()
        for i, byte in enumerate(encrypted_flag):
            key_byte = key[i % len(key)]
            decrypted.append(byte ^ key_byte)
        
        print(f"Decrypted bytes: {list(decrypted)}")
        
        # Try to find printable parts
        result = bytes(decrypted)
        print(f"Decrypted (hex): {result.hex()}")
        
        # Look for flag patterns
        try:
            text = result.decode('ascii', errors='ignore')
            print(f"ASCII decode: {repr(text)}")
        except:
            pass
            
        # Try to find CTF flag pattern
        for i in range(len(result) - 3):
            if result[i:i+3] in [b'CTF', b'ctf', b'flag', b'FLAG']:
                print(f"Found potential flag marker at position {i}")
                
        # Try different XOR patterns
        print("\nTrying alternative decryption methods...")
        
        # Method 1: XOR with first byte of key repeated
        key_byte = key[0]
        alt1 = bytes([b ^ key_byte for b in encrypted_flag])
        print(f"Method 1 (XOR {hex(key_byte)}): {alt1}")
        
        # Method 2: Try XOR with 0xa3 (the original XOR constant)
        alt2 = bytes([b ^ 0xa3 for b in encrypted_flag])
        print(f"Method 2 (XOR 0xa3): {alt2}")
        
        # Method 3: Look for patterns in the decrypted data
        # CTF flags often start with specific patterns
        for start_pattern in [b'CTF{', b'ctf{', b'flag{', b'FLAG{']:
            for i in range(256):
                test = bytes([b ^ i for b in encrypted_flag])
                if test.startswith(start_pattern):
                    print(f"Found flag with XOR {hex(i)}: {test}")
                    return test
                    
        return result
    else:
        print("✗ Key doesn't match flag file")
        return None

def main():
    """Main solver function"""
    print("=== Improved Bytecode VM CTF Challenge Solver ===\n")
    
    # Find valid bytecode
    bytecode = find_valid_bytecode()
    if not bytecode:
        print("Failed to find valid bytecode")
        return
    
    # Write bytecode file
    with open('/tmp/bytecodevm', 'wb') as f:
        f.write(bytecode)
    print(f"\nWrote bytecode to /tmp/bytecodevm: {bytecode.hex()}")
    
    # Get the decrypted key
    key = decrypt_key()
    print(f"\nDecrypted key: {key.hex()}")
    
    # Try to decrypt the flag
    print("\n=== Attempting flag decryption ===")
    flag = try_decrypt_flag(key)
    
    if flag:
        print(f"\nFinal result: {flag}")
        # Look for readable text in the result
        readable = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in flag)
        print(f"Readable chars: {readable}")

if __name__ == "__main__":
    main()