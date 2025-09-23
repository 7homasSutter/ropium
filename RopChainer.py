from ropium import *
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, message=".*PY_SSIZE_T_CLEAN.*")



def basic_example():
    rop = ROPium(ARCH.X86)
    rop.load('./samples/binaries/efssetup.exe')
    chain = rop.compile('eax = 0x1234')
    print(chain.dump())
    print(chain.dump('raw'))
    print(chain.dump('python'))


def basic_example_with_constraints():
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



if __name__ == "__main__":
    #basic_example()
    basic_example_with_constraints()