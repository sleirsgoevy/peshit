# peshit

This is a **proof-of-concept** X86-to-ARM static recompiler. As of now it is able to correctly run a MinGW-compiled "Hello, world!" program. From the user's perspective, it takes a Windows .EXE file for X86 and outputs a (hopefully) equivalent Windows .EXE file for ARM.

Exceptions in recompiler code are postponed until runtime, so that e.g.bogus "instructions" from .rodata do not need to be supported.

## Checklist

X86 implementation status:

- [x] "Hello, world!" compiles and runs
- [ ] (8/14) [box86](https://github.com/ptitSeb/box86) test suite compiles and runs
- [ ] [box86](https://github.com/ptitSeb/box86) test suite compiles and runs with MSVC
- [ ] At least one real application compiles and runs

Output compatibility:

- [x] Recompiled executables run in Wine on ARM
- [ ] Recompiled executables run in Windows on ARM
- [ ] Recompiled executables can be inspected using binutils

## Non-goals

* JIT support
* Running on a native Windows system, except for finished recompiled executables

## Usage

Dependencies:
* A Linux system
* Python 3 with capstone library
* i686-w64-mingw32-gcc
* arm-linux-gnueabihf-gcc
* llvm-mingw

Usage:

`python3 main.py input.exe output.exe`

Specify valid toolchain prefixes in `cc.py` before usage.

## Development & debugging

The modules and their functions are as follows:

```
cc.py         Wrappers for toolchains
cfstyle.py    CF flag handling via "CF styles" (add/sub/xor)
iatindir.py   Import table indirection (the native one contains ARM function addresses)
indir.py      Indirect jump/call/return handling
main.py       Orchestrates the whole thing
pefile.py     PE file parsing & output
recompiler.py The main recompiler code, translates X86 instructions to ARM instructions
stubgen.py    Glue code for translating WinAPI calls
tlshooks.py   Translation of TLS callback functions
vmem.py       Virtual memory emulation for recompiler's internal use
```

Recompiler configuration (in `recompiler.py`):

```
TRACE = False # if True, EIP, translated PC, CPSR, and general-purpose registers will be printed before execution of each X86 instruction
TRACEBACK = True # if True (default), full tracebacks of recompiler exceptions will be embedded inside the executable and printed if the execution reaches the failed instruction
```
