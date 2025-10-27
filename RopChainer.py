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

# Examples
# rop.compile('eax = 0')
# rop.compile('eax = 1')
# rop.compile('eax = ebx')
# rop.compile('eax = ecx')
# rop.compile('eax = edx')
# rop.compile('eax = esi')
# rop.compile('eax = edi')
# rop.compile('eax = esp')
# rop.compile('eax = ebp')
# rop.compile('ebx = 0')
# rop.compile('ebx = 1')
# rop.compile('ebx = eax')
# rop.compile('ebx = ecx')
# rop.compile('ebx = edx')
# rop.compile('ebx = esi')
# rop.compile('ebx = edi')
# rop.compile('ebx = esp')
# rop.compile('ebx = ebp')
# rop.compile('ecx = 0')
# rop.compile('ecx = 1')
# rop.compile('ecx = eax')
# rop.compile('ecx = ebx')
# rop.compile('ecx = edx')
# rop.compile('ecx = esi')
# rop.compile('ecx = edi')
# rop.compile('ecx = esp')
# rop.compile('ecx = ebp')
# rop.compile('edx = 0')
# rop.compile('edx = 1')
# rop.compile('edx = eax')

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
    rop.keep_regs = ["eax"]
    rop.safe_mem = True
    rop.abi = ABI.X86_STDCALL
    rop.os = OS.WINDOWS

    chain = rop.compile('edx = 0')
    if chain:
        print(chain.dump())
        print(chain.dump('raw'))
        print(chain.dump('python'))
    else:
        print("No chain found")

if __name__ == "__main__":
    basic_example()
    basic_example_with_constraints()