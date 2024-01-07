# cattleya
A ELF obfuscator written in Rust

# How to use
```
$ cattleya -h
A CLI application to obfuscate a ELF file

Usage: cattleya [OPTIONS] --input <INPUT>

Options:
  -i, --input <INPUT>    input file name
  -o, --output <OUTPUT>  output file name [default: obfuscated]
  -c, --class            change architecture class in the ELF
  -e, --endian           change endian in the ELF
  -s, --sechdr           nullify section header in the ELF
  -h, --help             Print help
  -V, --version          Print version
```

# Obfuscation methods

## Endian obfuscation

Obfuscates by changing the part of the ELF file that indicates endianness

```
$ cattleya -i input -e
start obfuscating input...
obfuscation done!

$ readeld -h input
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
...

$ readelf -h obfuscated
ELF Header:
  Magic:   7f 45 4c 46 02 02 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, big endian
...
```

## Architcture obfuscation
Obfuscates by changing the part of the ELF file that indicates the architecture (32bit or 64bit)

```
$ cattleya -i input -c
start obfuscating input...
obfuscation done!

$ file input
input: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=287e5058b7070a849e4153fb8f072381f780541b, for GNU/Linux 3.2.0, not stripped

$ file obfuscated
obfuscated: ELF 32-bit LSB shared object, x86-64, version 1 (SYSV), no program header, no section header
```

## Section header obfuscation

Obfuscates by keeping section header information confidential

```
$ cattleya -i input -s
start obfuscating input...
obfuscation done!

$ readelf -S input > /dev/null

$ readelf -S obfuscated > /dev/null 
readelf: Error: no .dynamic section in the dynamic segment
```

# test

```
$ cargo test
```
