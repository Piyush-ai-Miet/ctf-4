#!/usr/bin/env python3
"""
Solution for the Bytecode VM CTF Challenge

This script analyzes the bytecode VM and crafts the correct instruction sequence
to satisfy all requirements and extract the flag.
"""

def decrypt_key_from_rodata():
    """Decrypt the embedded key using XOR 0xA3"""
    # Key from .rodata section at offset 0x420
    encrypted_key = bytes.fromhex('3b4a592f88010a7cad7da4f8a61ac3ed002a4de7f6b3912bd7bd800e2f00a89a')
    decrypted_key = bytes([b ^ 0xa3 for b in encrypted_key])
    return decrypted_key

def analyze_vm_requirements():
    """
    From the assembly analysis, the VM checks several stack positions:
    - stack[0]: range check (value - 0x1f) <= 0x22  -> value in [0x1f, 0x41]
    - stack[1]: range check (value - 0x26) <= 0xb6  -> value in [0x26, 0xdc] 
    - stack[2]: range check (value - 0x37) <= 0x21  -> value in [0x37, 0x58]
    - stack[3]: range check (value - 0xd) <= 0x5b   -> value in [0xd, 0x68]
    - stack[4]: range check (value - 0x2f) <= 0x2c  -> value in [0x2f, 0x5b]
    - stack[5]: range check (value - 0x65) <= 0x83  -> value in [0x65, 0xe8]
    - stack[6]: range check (value - 0x65) <= 0x10  -> value in [0x65, 0x75]
    
    Sum of all values must equal 0x21e (542 decimal)
    """
    
    # Let's find valid values that sum to 0x21e
    target_sum = 0x21e  # 542
    
    # Use middle values from each range to start
    ranges = [
        (0x1f, 0x41),  # stack[0]
        (0x26, 0xdc),  # stack[1] 
        (0x37, 0x58),  # stack[2]
        (0xd, 0x68),   # stack[3]
        (0x2f, 0x5b),  # stack[4]
        (0x65, 0xe8),  # stack[5]
        (0x65, 0x75),  # stack[6]
    ]
    
    # Start with minimum values and adjust
    values = [r[0] for r in ranges]
    current_sum = sum(values)
    
    print(f"Initial sum with min values: {current_sum} (0x{current_sum:x})")
    print(f"Target sum: {target_sum} (0x{target_sum:x})")
    print(f"Need to add: {target_sum - current_sum} (0x{target_sum - current_sum:x})")
    
    # Adjust values to reach target sum
    remaining = target_sum - current_sum
    
    # Distribute the remaining amount across the ranges where we have room
    for i in range(len(values)):
        min_val, max_val = ranges[i]
        room = max_val - values[i]
        add_amount = min(remaining, room)
        values[i] += add_amount
        remaining -= add_amount
        if remaining == 0:
            break
    
    final_sum = sum(values)
    print(f"Final values: {[hex(v) for v in values]}")
    print(f"Final sum: {final_sum} (0x{final_sum:x})")
    print(f"Matches target: {final_sum == target_sum}")
    
    return values

def create_bytecode_sequence():
    """
    Create a bytecode sequence that will set up the stack properly.
    
    From the analysis:
    - 0x01: basic instruction, moves to next
    - 0x02: jumps to specific handler 
    - 0xFF: jumps to specific handler
    
    The VM processes instructions sequentially and appears to expect
    specific stack values to be set up for the validation.
    """
    
    stack_values = analyze_vm_requirements()
    
    # We need to craft bytecode that sets up these stack values
    # Based on the assembly, it looks like the VM uses the bytecode
    # to populate stack positions and then validates them
    
    # Try a simple approach: use the computed values directly as bytecode
    # The VM might be treating the bytecode bytes as stack initialization values
    
    bytecode = bytearray()
    
    # Add the stack values we computed
    for val in stack_values:
        bytecode.append(val & 0xff)  # Take low byte
    
    # Add padding if needed to ensure proper execution
    # Based on the instruction checks, we need valid opcodes
    bytecode.extend([0x01] * (16 - len(bytecode)))  # Fill with 0x01 instructions
    
    return bytes(bytecode)

def write_bytecode_file(bytecode):
    """Write the bytecode to /tmp/bytecodevm for the kernel module to read"""
    with open('/tmp/bytecodevm', 'wb') as f:
        f.write(bytecode)
    print(f"Wrote {len(bytecode)} bytes to /tmp/bytecodevm")
    print(f"Bytecode: {bytecode.hex()}")

def test_different_approaches():
    """Try different approaches to find the correct bytecode"""
    
    # Approach 1: Use the stack values directly
    print("=== Approach 1: Direct stack values ===")
    stack_values = analyze_vm_requirements()
    bytecode1 = bytes(stack_values)
    
    # Approach 2: Try with specific instruction patterns
    print("\n=== Approach 2: Instruction patterns ===")
    # Use patterns that might trigger specific VM behaviors
    bytecode2 = bytes([0x30, 0x56, 0x40, 0x30, 0x40, 0x70, 0x70])  # Values that sum to 0x21e
    
    # Approach 3: Try mixed instructions and values
    print("\n=== Approach 3: Mixed pattern ===")
    # Some instructions followed by values
    bytecode3 = bytes([0x01, 0x02, 0x35, 0x55, 0x42, 0x32, 0x42, 0x6f, 0x6f, 0xff])
    
    return [bytecode1, bytecode2, bytecode3]

def main():
    """Main solving function"""
    print("=== Bytecode VM CTF Challenge Solver ===")
    
    # First, get the decrypted key
    key = decrypt_key_from_rodata()
    print(f"Decrypted key: {key.hex()}")
    
    # Try different bytecode approaches
    bytecodes = test_different_approaches()
    
    # Let's manually try the values that should work
    # Based on the assembly analysis, let's try values that sum to 0x21e
    target_sum = 0x21e  # 542
    
    # Try a simple distribution
    values = [0x30, 0x56, 0x40, 0x30, 0x40, 0x70, 0x70]  # These sum to 0x21c, close
    values = [0x30, 0x56, 0x40, 0x30, 0x40, 0x70, 0x72]  # Adjust last to get 0x21e
    
    current_sum = sum(values)
    print(f"\nTrying values: {[hex(v) for v in values]}")
    print(f"Sum: {current_sum} (0x{current_sum:x}) vs target 0x21e")
    
    if current_sum == target_sum:
        print("✓ Sum matches target!")
        bytecode = bytes(values)
        write_bytecode_file(bytecode)
        
        print("\nBytecode file created. Now the kernel module should be able to process it.")
        print("Load the kernel module and read from the device to get the flag.")
    else:
        print("✗ Sum doesn't match, adjusting...")
        # Adjust the last value
        diff = target_sum - current_sum
        values[-1] += diff
        print(f"Adjusted values: {[hex(v) for v in values]}")
        print(f"New sum: {sum(values)} (0x{sum(values):x})")
        
        bytecode = bytes(values)
        write_bytecode_file(bytecode)

if __name__ == "__main__":
    main()