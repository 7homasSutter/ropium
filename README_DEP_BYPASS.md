# Extended RopChainer for DEP Bypass

This document describes the extended functionality added to RopChainer.py to support DEP (Data Execution Prevention) bypass techniques for educational purposes.

## New Features

### 1. VirtualAlloc Chain Generation

Generate ROP chains that call the Windows VirtualAlloc API to allocate executable memory.

```python
from RopChainerExtended import DEPBypassChainer, ARCH

chainer = DEPBypassChainer(ARCH.X86)
chain = chainer.generate_virtualalloc_chain(
    size=0x1000,           # 4KB allocation
    protection=0x40        # PAGE_EXECUTE_READWRITE
)
```

**VirtualAlloc Prototype:**
```c
LPVOID VirtualAlloc(
  LPVOID lpAddress,        // NULL (0) - let system choose
  SIZE_T dwSize,           // Size of allocation
  DWORD  flAllocationType, // MEM_COMMIT | MEM_RESERVE = 0x3000
  DWORD  flProtect         // PAGE_EXECUTE_READWRITE = 0x40
);
```

### 2. VirtualProtect Chain Generation

Generate ROP chains that call VirtualProtect to change memory protection of existing memory regions.

```python
chain = chainer.generate_virtualprotect_chain(
    address=0x401000,      # Address to change protection
    size=0x1000,           # Size of region
    new_protection=0x40    # PAGE_EXECUTE_READWRITE
)
```

**VirtualProtect Prototype:**
```c
BOOL VirtualProtect(
  LPVOID lpAddress,       // Address to change protection
  SIZE_T dwSize,          // Size of region
  DWORD  flNewProtect,    // New protection flags
  PDWORD lpflOldProtect   // Pointer to old protection value
);
```

### 3. WriteProcessMemory Chain Generation

Generate ROP chains that call WriteProcessMemory to copy shellcode into memory.

```python
chain = chainer.generate_writeprocessmemory_chain(
    process_handle=-1,     # Current process
    base_address=0x401000, # Where to write
    buffer=0x402000,       # Source buffer
    size=0x200             # Number of bytes
)
```

**WriteProcessMemory Prototype:**
```c
BOOL WriteProcessMemory(
  HANDLE  hProcess,               // Handle to process
  LPVOID  lpBaseAddress,          // Address to write to
  LPCVOID lpBuffer,               // Buffer containing data
  SIZE_T  nSize,                  // Number of bytes to write
  SIZE_T  *lpNumberOfBytesWritten // Bytes written
);
```

### 4. Pivot Gadget Insertion

Insert stack pivot gadgets to redirect execution to another buffer, enabling multi-stage payloads.

```python
# Redirect stack to second buffer
pivoted_chain = chainer.insert_pivot_gadget(
    current_chain,
    target_buffer_address=0x12345000
)
```

### 5. Egghunter Gadget Insertion

Generate egghunter ROP chains to search for shellcode marked with a specific signature.

```python
# Search for shellcode marked with 0x50905090
egg_chain = chainer.insert_egghunter(
    egg_signature=0x50905090,
    search_start=0x00010000
)
```

## Usage Examples

### Basic Setup

```python
from RopChainerExtended import DEPBypassChainer, ARCH, ABI, OS

# Initialize chainer
chainer = DEPBypassChainer(ARCH.X86)

# Load binary for gadget extraction
chainer.load_binary('./target.exe')

# Set constraints
chainer.set_constraints(
    bad_bytes=[0x00, 0x0a, 0x0d],  # NULL, LF, CR
    abi=ABI.X86_STDCALL,
    os_type=OS.WINDOWS
)
```

### Complete DEP Bypass Payload

```python
# Generate complete DEP bypass payload
payload = chainer.create_dep_bypass_payload(
    shellcode_addr=0x401000,
    shellcode_size=0x400
)

if payload:
    print("DEP bypass payload generated!")
    print(payload.dump())
    print(payload.dump('python'))
```

### Multi-Stage Exploit

```python
# Stage 1: Allocate executable memory
stage1 = chainer.generate_virtualalloc_chain(size=0x1000)

# Stage 2: Pivot to second buffer for larger payload
stage2_buffer = 0x12345000
complete_chain = chainer.insert_pivot_gadget(stage1, stage2_buffer)

print("Multi-stage payload created!")
```

### Egghunter Technique

```python
# Create egghunter for when buffer space is limited
hunter = chainer.insert_egghunter(egg_signature=0x41424344)  # "DCBA"

if hunter:
    print("Egghunter created! Place this in limited buffer space.")
    print("Mark your shellcode with the egg signature: \\x44\\x43\\x42\\x41\\x44\\x43\\x42\\x41")
    print(hunter.dump('python'))
```

## Testing

Run the comprehensive test suite:

```bash
python3 test_dep_bypass.py
```

This will test all functionality and provide a practical demonstration.

## API Reference

### DEPBypassChainer Class

#### Constructor
- `__init__(arch=ARCH.X86)` - Initialize with specified architecture

#### Loading Methods
- `load_binary(binary_path)` - Load binary for gadget extraction
- `load_gadgets(gadget_file)` - Load precomputed ROPgadget output

#### Configuration
- `set_constraints(bad_bytes=None, keep_regs=None, safe_mem=False, abi=None, os_type=None)` - Set ROP compilation constraints

#### Chain Generation
- `generate_virtualalloc_chain(size=0x1000, protection=0x40, virtualalloc_addr=None)` - Generate VirtualAlloc ROP chain
- `generate_virtualprotect_chain(address, size, new_protection=0x40, virtualprotect_addr=None, old_protect_ptr=None)` - Generate VirtualProtect ROP chain
- `generate_writeprocessmemory_chain(process_handle, base_address, buffer, size, writeprocessmemory_addr=None, bytes_written_ptr=None)` - Generate WriteProcessMemory ROP chain

#### Advanced Techniques
- `insert_pivot_gadget(current_chain, target_buffer_address)` - Insert stack pivot gadget
- `insert_egghunter(egg_signature=0x50905090, search_start=0x00010000)` - Generate egghunter chain
- `create_dep_bypass_payload(shellcode_addr, shellcode_size)` - Generate complete DEP bypass payload

## Memory Protection Constants

Common Windows memory protection constants:

- `0x01` - PAGE_NOACCESS
- `0x02` - PAGE_READONLY  
- `0x04` - PAGE_READWRITE
- `0x08` - PAGE_WRITECOPY
- `0x10` - PAGE_EXECUTE
- `0x20` - PAGE_EXECUTE_READ
- `0x40` - PAGE_EXECUTE_READWRITE
- `0x80` - PAGE_EXECUTE_WRITECOPY

## Allocation Type Constants

VirtualAlloc allocation type constants:

- `0x1000` - MEM_COMMIT
- `0x2000` - MEM_RESERVE
- `0x3000` - MEM_COMMIT | MEM_RESERVE (most common)

## Educational Disclaimer

This tool is designed for educational purposes and authorized penetration testing only. The techniques implemented here should only be used on systems you own or have explicit permission to test. Unauthorized use of these techniques is illegal and unethical.

## Implementation Notes

- The implementation uses ROPium's existing compiler infrastructure
- Function calls are generated using ROPium's IL (Intermediate Language) syntax
- All Windows API addresses are examples and would need to be updated for specific targets
- The egghunter implementation is simplified - production egghunters would include loop and search logic
- Error handling is provided for cases where suitable gadgets cannot be found

## Future Enhancements

Potential future enhancements could include:

1. Automatic API address resolution from loaded binaries
2. More sophisticated egghunter implementations with proper search loops
3. Support for additional Windows APIs (HeapCreate, SetProcessDEPPolicy, etc.)
4. Integration with common exploit frameworks
5. Support for x64 architecture DEP bypass techniques
6. ROP chain optimization and size reduction techniques