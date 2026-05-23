# AI Notice
I take pride in the code that I write, and am completely transparent when I share code that has been AI generated. I needed this tool to help me search for patterns and wrote this 100% with claude, I did not even touch the code. I just verified that it works. I am only putting it on GitHub so someone else can use this (compiled executable in releases)

# pe_gadget_finder
A command-line tool for finding ROP (Return-Oriented Programming) gadgets in PE (Portable Executable) files.

## Overview
`pe_gadget_finder` parses Windows PE binaries and scans executable sections for useful ROP gadgets — sequences of instructions ending in a `ret` that can be chained together for exploitation research and security analysis.

## Feature
- Parses PE32 and PE32+ (64-bit) executables
- Scans all executable sections for gadgets
- Filters and displays gadget addresses and instruction sequences

## Building
Requires CMake and a C++ compiler (MSVC, GCC, or Clang).

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

## Usage
```bash
pe_gadget_finder.exe <target.exe>
```

## Use Cases
- CTF challenges
- Exploit development research
- Binary analysis and auditing

## Disclaimer
This tool is intended for educational purposes and authorized security research only. Do not use against binaries you do not own or have explicit permission to analyze.

## License

MIT
