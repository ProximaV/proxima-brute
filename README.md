
# Proxima's Brute Force Key Search Tool

## Description

In working with DPA of various decryption processes, it is often the case that one may have parts of a key recovered. It is also common to have several options for different key bytes possible. With using DPA on decryption, this is often the 10th round key rather than the key itself.

This project aims to brute-force keys for a certain cryptographic process using multiple threads. The tool reads configurations for key space, loads header and body files, and performs the brute-force operation. It also gives an estimate of the remaining time required to complete the search based on current progress.

The code included here is for a specific use-case. Decrypting a header which contains the body key, then decrypting the body with that key. This framework can easily be extended for any other type of brute-forcing use-case as needed.

This framework is really for running multiple threads on a brute force task, and using hardware based AES to do so.

## Features

- Reads key configuration from a text file
- Supports multiple threads for parallel execution
- Provides an estimate of the remaining time to complete the search
- Handles file operations securely (Open, Load, Write)
- Calculates the total number of key combinations based on key configuration
- Written in C for maximum performance using native x64 aes hardware

## Dependencies

- Windows OS
- Visual Studio C++

## Compilation

Compile the project using Visual Studio.

## Usage

1. Place your header and body files in the project directory.
2. Create a key configuration file following the format described in `key_config_format.txt`.
3. Run the program from the command line as follows:

```bash
./program headerfile.bin bodyfile.bin keyconfig.txt 4
```

Replace `4` with the number of threads you want to use.

## Documentation

The source code includes Doxygen-compatible comment headers. To generate a Doxygen document, install Doxygen and run it in the directory containing the source files.

---
Certainly! Below is a sample content for `key_config_format.txt` that describes the format of the `keyconfig.txt` file, including an example.

---

# Key Configuration File Format (keyconfig.txt)

The `keyconfig.txt` file contains the possible values for each index (position) in the key that will be brute-forced. The format is simple, but it must be followed strictly for the program to read the file correctly.

## Format

Each line represents one index (position) in the key, and follows the pattern:

```
<Index>:<Hexadecimal values>
```

- `<Index>`: A two-digit hexadecimal number that represents the index of the byte in the key (from 00 to 0F).
- `<Hexadecimal values>`: The possible values for this byte, written as a continuous hexadecimal string. If all values are possible (0x00 to 0xFF), leave blank.

## Example

```
00:6EBE9901
01:5543
02:
03:22FE
04:6BDA5B
05:250199BED7
06:33
07:11
08:98BA32
09:
0A:2701
0B:F9C566
0C:5C068B
0D:
0E:E6
0F:98
```

In this example:

- The key's byte at index `00` can have a value of `0x6E`, `0xBE`, `0x99`, `0x01`.
- The key's byte at index `01` can have a value of `0x55` or `0x43`.
- The key's byte at index `02`, `09`, and `0D` can have any value between `0x00` and `0xFF` (indicated by no value).

---

That's it! Save your configuration in a text file and feed it into the program as described in the README.md.



