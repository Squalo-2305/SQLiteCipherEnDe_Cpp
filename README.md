# SQLiteCipherEnDe [C++]
This project is intended for educational and research purposes only. Use it only with data you own or are explicitly authorized to access.

A Windows C++ project that dynamically loads SQLCipher to encrypt/decrypt SQLite
databases.

The project loads `sqlcipher.dll` at runtime from the executable directory.
After a successful x64 build, the post-build step copies all three DLLs from
the project folder (`sqlcipher.dll`, `libcrypto-1_1-x64.dll`, and
`libssl-1_1-x64.dll`) next to the executable.

The supplied DLLs are 64-bit; run the project as `x64`.

## Overview story
One day, while reverse-engineering an OTT chat app—just for the fun of it—with my goal was to figure out how to decrypt its database files. After some debugging, I discovered the local database key, as well as the method the application uses to encrypt the database file with that key.

I have observed that this OTT app uses the **SQLite Cipher** library with the **compatibility version set to 4**. After attempting to use **DB Browser (SQLCipher)** for decryption to verify the results of my reverse engineering, it appears I was correct.

![Decrypt database file with key and sqliteCipher 4 setting](/images/db_browser_input.png)

![Decrypted database](/images/db_browser_result.png)

I would now like to build a module that can automatically encrypt and decrypt files and folders. After attempting to build the [**SQLiteCipher library**](https://www.zetetic.net/sqlcipher/) for my processing tasks—and failing, for reasons I couldn't quite pin down—I decided, in the spirit of a reverse engineer, to take a different approach: leveraging the DLLs from **DB Browser (SQLCipher)**.

After some research, I discovered that everything required is contained within `sqlcipher.dll`. The necessary functions include **sqlite3_open_v2**, **sqlite3_exec**, **sqlite3_close**, **sqlite3_key**, and **sqlite3_key_v2** (based on the process of opening a database file and interacting with it). After defining and loading the necessary functions, I use the data structures from `sqlite3.h` to pass arguments to and invoke functions from `sqlcipher.dll`. Finally, I execute the function calls to carry out the decryption or encryption process.

![Define function pointer](/images/function_pointer.png)

My initial idea was to call the **rekey** function to remove the key from the database file; however, after researching the [**SQLiteCipher library**](https://www.zetetic.net/sqlcipher/), I discovered that it does not support this feature. Consequently, I shifted my approach to extracting the data into an unencrypted database file and then renaming that file.

## How it work
The tool will load `sqlcipher.dll` and initialize the necessary functions.

If the type is **folder**, a list of database files to be processed is generated from the input path folder; otherwise, the list consists of a single database file—the one specified by the input path.

If the mode is **en**, the temporary database file is attached, the data is copied over, and **setkey** is called to encrypt the temporary file. Conversely, if the mode is **de**, **setkey** is called immediately after loading the database; then, the temporary database file is attached, the data is copied into it, and the file is saved to decrypt the temporary file. 

After processing, the original file will be deleted, and the temporary file will be renamed to the original filename.

## Usage
Parameters include:
- **Mode**: specifies whether the tool should run in encryption or decryption mode. Accepted values: en | de
- **Version**: specifies the compatibility version to be used. Accepted values: 3 | 4
- **Type**: specifies whether the input is a single database file or a folder containing multiple database files. Accepted values: file | folder
- **Path**: the path to the input file or folder
- **Key**: the key used for encryption or decryption. To provide a byte-based key, pass it in hexadecimal format as follows: hex:<hex_string_key>

```
SQLiteCipherEnDe.exe <Mode> <Version> -t <Type> -p <Path> -k <Key>

<Mode>          Mode to run
                Accepted values: en | de
<Version>       Compatibility version to be used
                Accepted values: 3 | 4
<Type>          Flag define input is a single database file or a folder containing multiple database files
                Accepted values: file | folder
<Path>          The path to the input file or folder
<Key>           The key used for encryption or decryption.
                To provide a byte-based key, pass it in hexadecimal format as follows: hex:<hex_string_key>

Example:
SQLiteCipherEnDe.exe en 4 -t "file" -p "D:\code_research\SQLiteCipherEnDe\Index.db" -k "testkey"
SQLiteCipherEnDe.exe de 4 -t "file" -p "D:\code_research\SQLiteCipherEnDe\Index.db" -k "hex:746573746b6579"
SQLiteCipherEnDe.exe de 3 -t "folder" -p "D:\code_research\SQLiteCipherEnDe\Message" -k "hex:ffefbb48cb64c23c6a4352ed1d83fc9e"
```
