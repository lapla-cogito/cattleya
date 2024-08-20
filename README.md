# cattleya
An ELF obfuscator written in Rust

# How to use
```
$ cattleya -h
A CLI application to obfuscate ELF file(s)

Usage: cattleya [OPTIONS]

Options:
  -i, --input <INPUT>          input file name [default: ]
  -o, --output <OUTPUT>        output file name [default: ]
  -c, --class                  change architecture class in the ELF
  -e, --endian                 change endian in the ELF
  -s, --sechdr                 nullify section header in the ELF
      --symbol                 nullify symbols in the ELF
      --comment                nullify comment section in the ELF
      --section <SECTION>      nullify section in the ELF [default: ]
  -r, --recursive <RECURSIVE>  recursive [default: ]
  -g, --got                    perform GOT overwrite
      --got-l <GOT_L>          GOT overwrite target library function name [default: ]
      --got-f <GOT_F>          GOT overwrite target function name [default: ]
  -h, --help                   Print help
  -V, --version                Print version
```

Both input and recursive options cannot be empty.

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

## Nullify symbol names obfuscation

Erases symbol names in the target

```
$ cattleya -i input --symbol
start obfuscating input...
obfuscation done!

$ readelf -x29 input

Hex dump of section '.strtab':
  0x00000000 00536372 74312e6f 005f5f61 62695f74 .Scrt1.o.__abi_t
  0x00000010 61670063 72747374 7566662e 63006465 ag.crtstuff.c.de
  0x00000020 72656769 73746572 5f746d5f 636c6f6e register_tm_clon
  0x00000030 6573005f 5f646f5f 676c6f62 616c5f64 es.__do_global_d
  0x00000040 746f7273 5f617578 00636f6d 706c6574 tors_aux.complet
...

$ readelf -x29 obfuscated

Hex dump of section '':
  0x00000000 00000000 00000000 00000000 00000000 ................
  0x00000010 00000000 00000000 00000000 00000000 ................
  0x00000020 00000000 00000000 00000000 00000000 ................
  0x00000030 00000000 00000000 00000000 00000000 ................
  0x00000040 00000000 00000000 00000000 00000000 ................
...
```

## Nullify comments obfuscation

Erases comments in the target

```
$ cattleya -i input --comment
start obfuscating input...
obfuscation done!

$ readelf -x27 input

Hex dump of section '.comment':
  0x00000000 4743433a 20285562 756e7475 2031312e GCC: (Ubuntu 11.
  0x00000010 342e302d 31756275 6e747531 7e32322e 4.0-1ubuntu1~22.
  0x00000020 30342920 31312e34 2e3000            04) 11.4.0.

$ readelf -x29 obfuscated

Hex dump of section '.comment':
  0x00000000 00000000 00000000 00000000 00000000 ................
  0x00000010 00000000 00000000 00000000 00000000 ................
  0x00000020 00000000 00000000 000000            ...........
```

## GOT overwrite

Overwrites the GOT section with a specified value

```
$ cattleya -i bin/got --got --got-l system --got-f secret -o bin/res_got
$ ./bin/res_got
secret function called
```

As shown below, only the system function is called in the main function as far as disassembly is concerned:

```
$ objdump -d bin/res_got
...
00000000004011d2 <main>:
  4011d2:       f3 0f 1e fa             endbr64
  4011d6:       55                      push   %rbp
  4011d7:       48 89 e5                mov    %rsp,%rbp
  4011da:       48 83 ec 10             sub    $0x10,%rsp
  4011de:       48 8d 05 36 0e 00 00    lea    0xe36(%rip),%rax        # 40201b <_IO_stdin_used+0x1b>
  4011e5:       48 89 c7                mov    %rax,%rdi
  4011e8:       e8 73 fe ff ff          call   401060 <system@plt>
  4011ed:       89 45 fc                mov    %eax,-0x4(%rbp)
  4011f0:       b8 00 00 00 00          mov    $0x0,%eax
  4011f5:       c9                      leave
  4011f6:       c3                      ret
...
```

# Recursive option

By specifying the directory name in the recursive option, the same obfuscation can be applied to all ELF files in that directory:

```
$ tree recursive_sample
recursive_sample
├── bar
└── foo

0 directories, 2 file

$ cattleya -r recursive_sample --symbol
...
$ tree obfuscated_dir
tree obfuscated_dir
obfuscated_dir
└── recursive_sample
    ├── bar
    └── foo

1 directory, 2 files
```

# test

```
$ cargo test
```
