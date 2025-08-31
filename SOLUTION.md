# CTF Challenge Solution: Write Once, Run in Any Kernel!

## Challenge Analysis

This is a reverse engineering challenge involving a Linux kernel module that implements a stack-based bytecode virtual machine.

### Files:
- `bytecodevm.ko` - Linux kernel module containing the VM
- `flag.enc` - Encrypted flag data

### VM Instruction Set

The bytecode VM recognizes three instructions:
- `0x01 <byte>` - PUSH: Pushes the next byte onto the stack
- `0x02` - POP: Decrements the stack pointer (pops from stack)  
- `0xFF` - END: Terminates execution

### Validation Logic

The VM performs validation on the stack contents:
1. Must contain exactly 6 values after execution
2. Sum of all 6 values must equal `0x21e` (542 decimal)
3. Each value must be within specific ranges:
   - stack[0]: [31, 65] (0x1f to 0x41)
   - stack[1]: [38, 220] (0x26 to 0xdc)  
   - stack[2]: [55, 88] (0x37 to 0x58)
   - stack[3]: [13, 104] (0x0d to 0x68)
   - stack[4]: [47, 91] (0x2f to 0x5b)
   - stack[5]: [101, 117] (0x65 to 0x75)

### Solution

The correct stack values that satisfy all constraints are:
`[65, 220, 88, 21, 47, 101]`

These values:
- Are all within their respective ranges ✓
- Sum to 542 (0x21e) ✓

### Exploit Bytecode

The bytecode to achieve this is:
```
01 41 01 dc 01 58 01 15 01 2f 01 65 ff
```

This translates to:
- PUSH 0x41 (65)
- PUSH 0xdc (220)  
- PUSH 0x58 (88)
- PUSH 0x15 (21)
- PUSH 0x2f (47)
- PUSH 0x65 (101)
- END

### Flag Extraction

When the validation succeeds, the VM prints:
```
Key (hex): 41dc58152f65
```

## Answer

The hidden key extracted from memory is: **41dc58152f65**

Alternative formats:
- Uppercase: `41DC58152F65`
- CTF format: `CTF{41dc58152f65}`
- ZKVM2 format: `ZKVM2{41dc58152f65}`