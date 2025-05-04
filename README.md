# CryptexX v2.1

## Stateless Dual-Layer Payload Encryption Tool

CryptexX is a lightweight, powerful encryption tool designed for autonomous deployment pipelines. It provides robust security through dual-layer encryption while remaining completely stateless and free of environmental constraints.

## Features

- **Dual-Layer Encryption**: Combines AES-256-CBC and XOR for enhanced security
- **Stateless Operation**: Works on any system without hardware or time validation
- **Compression**: Uses zlib to reduce payload size before encryption
- **Variable Padding**: Implements secure random padding instead of standard PKCS7
- **Self-Contained**: Produces a single encrypted file with all necessary components
- **Secure Key Derivation**: Employs PBKDF2-HMAC-SHA256 with 200,000 iterations

## How It Works

CryptexX follows a streamlined encryption process:

1. **Input Processing**:
   - Reads the target payload file
   - Compresses the data using zlib

2. **Encryption**:
   - Generates random salt and initialization vector (IV)
   - Derives encryption key using PBKDF2 with your password
   - Applies variable padding with random bytes
   - Performs first-layer encryption with AES-256-CBC
   - Generates random XOR key
   - Performs second-layer encryption with XOR

3. **Output Generation**:
   - Creates a single `.enc` file with the following structure:
     - Magic Header (4 bytes)
     - Salt (16 bytes)
     - IV (16 bytes)
     - XOR Key (32 bytes)
     - Encrypted Payload

## Usage

```bash
python cryptexx.py
```

Then follow the interactive prompts:
1. Enter the path to the file you want to encrypt
2. Provide an encryption password (and confirm it)

The tool will generate an encrypted `.enc` file in the same directory.

## Example Output

```
=============================================
CryptexX v2.1 - Stateless Payload Encrypter
=============================================

Enter payload file path: /path/to/payload.bin

[+] CryptexX v2.1 encryption successful!
    Magic: 0xC0DEDEAD
    Salt: 8f7d6a3c2b1e5f4a9d8c7b6a5f4e3d2c
    IV: 1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p
    XOR Key: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6
    Compressed: 15240 → 5280 bytes
    Final size: 5348 bytes
    Output: /path/to/payload.bin.enc

[+] Stateless payload ready for deployment.

[+] Operation complete.
```

## Security Notes

- The encryption password is never stored in the file
- Sensitive data is securely wiped from memory after use
- No hardware identifiers or time-based restrictions are included
- The tool is designed for elastic delivery via indirect vectors

## Requirements

- Python 3.6+
- PyCryptodome library

## Installation

```bash
# Install dependencies
pip install pycryptodome
```
