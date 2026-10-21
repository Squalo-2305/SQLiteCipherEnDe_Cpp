# SQLiteCipherEnDe
This project is intended for educational and research purposes only. Use it only with data you own or are explicitly authorized to access.

A Windows C++ project that dynamically loads SQLCipher to encrypt/decrypt SQLite
databases.

The project loads `sqlcipher.dll` at runtime from the executable directory.
After a successful x64 build, the post-build step copies all three DLLs from
the project folder (`sqlcipher.dll`, `libcrypto-1_1-x64.dll`, and
`libssl-1_1-x64.dll`) next to the executable.

The supplied DLLs are 64-bit; run the project as `x64`.

## Overview

## How it work

## Usage
```
SQLiteCipherEnDe.exe <en|de> <3|4> -t <file|folder> -p <path> -k <key>
```
