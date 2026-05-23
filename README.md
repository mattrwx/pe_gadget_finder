# pe_gadget_finder

> **AI Notice:** I take pride in the code that I write, and am completely transparent when I share code that has been AI generated. I needed this tool to help me search for patterns and wrote this 100% with Claude — I did not even touch the code, I just verified that it works. I am only putting it on GitHub so someone else can use this (compiled executable in releases).

A command-line tool for scanning PE (Portable Executable) files for IDA-style byte patterns, with disassembly of each match using Zydis.

## Overview
`pe_gadget_finder` recursively walks a directory, parses every PE binary it finds, and searches executable sections (or all sections with `-ALLFILE`) for a user-supplied byte pattern. Each match is reported with its RVA, section name, filename, and disassembled instruction.

## Features
- Parses PE32 and PE32+ (64-bit) executables
- Supports IDA-style hex patterns with `?` / `??` wildcards (e.g. `0F 22 ? 05`)
- Recursive directory scanning
- Disassembles each match via [Zydis](https://github.com/zyantific/zydis)
- Results written to a formatted, aligned text file
- `-ALLFILE` flag to scan non-executable sections too

Supported extensions: `.exe` `.dll` `.sys` `.ocx` `.scr` `.drv` `.efi` `.mui`

## Building
Requires CMake, a C++ compiler (MSVC, GCC, or Clang), and [Zydis](https://github.com/zyantific/zydis).

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

## Usage
```bash
pe_gadget_finder.exe -dir="<path>" -pattern="<IDA pattern>" [-bin="<output>"] [-ALLFILE]
```

### Options
| Flag | Description |
|------|-------------|
| `-dir=<path>` | Directory to scan (recursive) |
| `-pattern=<pat>` | IDA-style hex pattern, e.g. `"0F 22 ? 05"` |
| `-bin=<file>` | Output file (default: `matches.txt`) |
| `-ALLFILE` | Scan all sections, not just executable ones |

### Example
```bash
pe_gadget_finder.exe -dir="C:\Windows\System32" -pattern="0F 22 ?? 05" -bin="results"
```

### Output format

```
RVA                | Section    | File                | Instruction
-------------------+------------+---------------------+------------
0x0000000000123456 | .text      | ntdll.dll           | mov cr0, rax
```
