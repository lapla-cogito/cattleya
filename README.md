# cattleya
ELF obfuscator written in Rust

> [!NOTE]
> [日本語版のREADME](./README_ja.md)もあります（README in Japanese is also available）

<!-- TOC -->

- [How to use](#how-to-use)
- [Obfuscation methods](#obfuscation-methods)
  - [Endian obfuscation](#endian-obfuscation)
  - [Architecture obfuscation](#architecture-obfuscation)
  - [Section header obfuscation](#section-header-obfuscation)
  - [Nullify symbol names obfuscation](#nullify-symbol-names-obfuscation)
  - [Nullify comments obfuscation](#nullify-comments-obfuscation)
  - [Function name encryption](#function-name-encryption)
  - [GOT overwrite obfuscation](#got-overwrite)
- [Test](#test)

# How to use

```
$ cattleya -h
A CLI application to obfuscate ELF file(s)

Usage: cattleya [OPTIONS]

Options:
  -i, --input <INPUT>              input file name [default: ]
  -o, --output <OUTPUT>            output file name [default: ]
  -c, --class                      change architecture class in the ELF
  -e, --endian                     change endian in the ELF
  -s, --sechdr                     nullify section header in the ELF
      --symbol                     nullify symbols in the ELF
      --comment                    nullify comment section in the ELF
      --section <SECTION>          nullify section in the ELF [default: ]
  -r, --recursive <RECURSIVE>      recursive [default: ]
  -g, --got                        perform GOT overwrite
      --got-l <GOT_L>              GOT overwrite target library function name [default: ]
      --got-f <GOT_F>              GOT overwrite target function name [default: ]
      --encrypt                    encrypt function name with the given key
      --encrypt-f <ENCRYPT_F>      encryption target function name [default: ]
      --encrypt-key <ENCRYPT_KEY>  encryption key [default: ]
  -h, --help                       Print help
  -V, --version                    Print version
```

Both input and recursive options cannot be empty.

# Obfuscation methods

## Endian obfuscation

Obfuscates by changing the part of the ELF file that indicates endianness

```
$ cattleya -i input -e
start obfuscating input...
obfuscation done!

$ readelf -h input
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

$ objdump -d obfuscated
objdump: obfuscated: file format not recognized
```

## Architecture obfuscation
Obfuscates by changing the part of the ELF file that indicates the architecture (32bit or 64bit)

```
$ cattleya -i input -c
start obfuscating input...
obfuscation done!

$ file input
input: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=287e5058b7070a849e4153fb8f072381f780541b, for GNU/Linux 3.2.0, not stripped

$ file obfuscated
obfuscated: ELF 32-bit LSB shared object, x86-64, version 1 (SYSV), no program header, no section header

$ objdump -d obfuscated
objdump: obfuscated: file format not recognized
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

$ readelf -p .strtab input

String dump of section '.strtab':
  [     1]  Scrt1.o
  [     9]  __abi_tag
  [    13]  crtstuff.c
  [    1e]  deregister_tm_clones
  [    33]  __do_global_dtors_aux
  [    49]  completed.0
  [    55]  __do_global_dtors_aux_fini_array_entry
  [    7c]  frame_dummy
  [    88]  __frame_dummy_init_array_entry
  [    a7]  main.c
  [    ae]  __FRAME_END__
  [    bc]  _DYNAMIC
...

$ readelf -p .strtab obfuscated

String dump of section '.strtab':
  No strings found in this section.
```

## Nullify comments obfuscation

Erases comments in the target

```
$ cattleya -i input --comment
start obfuscating input...
obfuscation done!

$ readelf -p .comment input

String dump of section '.comment':
  [     0]  GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0

$ readelf -p .comment obfuscated

String dump of section '.comment':
  No strings found in this section.
```

## Function name encryption

Encrypts the name of a specific function with AES 256bit using the given key:

```
$ cattleya -i bin/test_64bit --encrypt --encrypt-f fac --encrypt-key foo -o bin/res_enc
start obfuscating bin/test_64bit...
obfuscation done!
$ ./bin/res_enc
fac(1)=1
fib(1)=1
fac(5)=120
fib(5)=5
fac(10)=3628800
fib(10)=55
$ objdump -d bin/res_enc
...
000000000000120c <main>:
    120c:       f3 0f 1e fa             endbr64 
    1210:       55                      push   %rbp
    1211:       48 89 e5                mov    %rsp,%rbp
    1214:       48 83 ec 10             sub    $0x10,%rsp
    1218:       89 7d fc                mov    %edi,-0x4(%rbp)
    121b:       48 89 75 f0             mov    %rsi,-0x10(%rbp)
    121f:       bf 01 00 00 00          mov    $0x1,%edi
    1224:       e8 20 ff ff ff          call   1149 <�0,>
    1229:       bf 01 00 00 00          mov    $0x1,%edi
    122e:       e8 6a ff ff ff          call   119d <fib>
    1233:       bf 05 00 00 00          mov    $0x5,%edi
    1238:       e8 0c ff ff ff          call   1149 <�0,>
    123d:       bf 05 00 00 00          mov    $0x5,%edi
    1242:       e8 56 ff ff ff          call   119d <fib>
    1247:       bf 0a 00 00 00          mov    $0xa,%edi
    124c:       e8 f8 fe ff ff          call   1149 <�0,>
    1251:       bf 0a 00 00 00          mov    $0xa,%edi
    1256:       e8 42 ff ff ff          call   119d <fib>
    125b:       b8 00 00 00 00          mov    $0x0,%eax
    1260:       c9                      leave  
    1261:       c3                      ret
...
```

Function name "fac" is encrypted.

## GOT overwrite

Overwrites the GOT section with a specified value

```
$ cat bin/got.c
// gcc got.c -no-pie -o got
#include <stdio.h>
#include <stdlib.h>

int secret(char* s) {
    if (s[0] == 's' && s[1] == 'e' && s[2] == 'c' && s[3] == 'r' && s[4] == 'e' && s[5] == 't' && s[6] == '?') {
        printf("secret function called\n");
    }

    return 0;
}

int main() {
    system("secret?\n");
}

$ cattleya -i bin/got --got --got-l system --got-f secret -o bin/res_got
start obfuscating bin/got...
obfuscation done!
$ ./bin/res_got
secret function called
```

As shown below, only the system function is called in the main function as far as disassembly of `main` is concerned:

```
$ objdump -d bin/res_got
...
00000000004011e1 <main>:
  4011e1:       f3 0f 1e fa             endbr64
  4011e5:       55                      push   %rbp
  4011e6:       48 89 e5                mov    %rsp,%rbp
  4011e9:       48 8d 05 2b 0e 00 00    lea    0xe2b(%rip),%rax        # 40201b <_IO_stdin_used+0x1b>
  4011f0:       48 89 c7                mov    %rax,%rdi
  4011f3:       e8 68 fe ff ff          call   401060 <system@plt>
  4011f8:       b8 00 00 00 00          mov    $0x0,%eax
  4011fd:       5d                      pop    %rbp
  4011fe:       c3                      ret
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

# Test

```
$ cargo test
```

By running this command, examples of binaries obfuscated using each obfuscation methods will be created in the bin directory.

Note that all tests are defined in `src/main.rs`. Some tests require external tools such as `readelf` and `nm`, and some tests need an environment capable of executing ELF files.
