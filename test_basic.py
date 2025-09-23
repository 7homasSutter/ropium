#!/usr/bin/env python3

import sys
sys.path.insert(0, './bin')

try:
    from ropium import *
    print("ROPium import successful!")
    
    # Test basic functionality
    rop = ROPium(ARCH.X86)
    print("ROPium instance created successfully")
    rop.os = OS.WINDOWS
    rop.abi = ABI.X86_STDCALL
    
    # Test loading a binary instead of gadgets
    try:
        # Load binary file
        rop.load('./samples/binaries/efssetup.exe')
        print("Binary loaded successfully!")
        
        # Try a basic chain
        chain = rop.compile('eax = 0x1234')
        if chain:
            print("Basic chain compilation successful!")
            print(chain.dump())
        else:
            print("Chain compilation failed")
            
    except Exception as e:
        print(f"Binary loading or compilation error: {e}")

except ImportError as e:
    print(f"ROPium import failed: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")