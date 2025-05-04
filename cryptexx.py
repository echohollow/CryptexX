# CryptexX v2.1 - Streamlined dual-layer encryption payload generator

import os
import sys
import zlib
import getpass
import struct
import secrets
import datetime
import hashlib
import ctypes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# Constants
MAGIC_HEADER = 0xC0DEDEAD
SALT_SIZE = 16
IV_SIZE = 16
XOR_KEY_SIZE = 32
KEY_ITERATIONS = 200000
KEY_LENGTH = 32  # 256 bits
VERSION = "2.1"

# ANSI color codes for terminal output
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
RESET = "\033[0m"

def secure_wipe(obj):
    """Attempt to securely wipe sensitive data from memory"""
    if isinstance(obj, bytes):
        # Get buffer size
        buf_size = len(obj)
        try:
            # Create ctypes buffer from the object's memory
            buf = (ctypes.c_byte * buf_size).from_buffer_copy(obj)
            # Overwrite with zeros
            ctypes.memset(ctypes.addressof(buf), 0, buf_size)
        except:
            # Fallback: at least replace the contents in Python space
            obj_id = id(obj)
            obj_type = type(obj)
            obj = bytes([0] * buf_size)
    elif isinstance(obj, bytearray):
        obj[:] = bytes([0] * len(obj))

def derive_key(password, salt):
    """Derive AES key using PBKDF2-HMAC-SHA256"""
    return PBKDF2(
        password, 
        salt, 
        dkLen=KEY_LENGTH, 
        count=KEY_ITERATIONS,
        hmac_hash_module=SHA256
    )

def generate_xor_key(size=XOR_KEY_SIZE):
    """Generate a random XOR key"""
    return secrets.token_bytes(size)

def xor_encrypt(data, key):
    """Encrypt data with XOR using provided key"""
    # Convert to bytearray for mutation
    result = bytearray(data)
    key_len = len(key)
    
    # Apply XOR with cycling through key bytes
    for i in range(len(result)):
        result[i] ^= key[i % key_len]
    
    return bytes(result)

def variable_pad(data, block_size=16):
    """Apply variable padding instead of standard PKCS7"""
    # Calculate how many bytes needed to reach multiple of block_size
    padding_len = block_size - (len(data) % block_size)
    if padding_len == 0:
        padding_len = block_size
    
    # Use random bytes for padding instead of same byte repeated
    # But store the padding length in the last byte (like PKCS7)
    padding = secrets.token_bytes(padding_len - 1) + bytes([padding_len])
    return data + padding

def encrypt_file(file_path, password):
    """Encrypt the file using dual-layer encryption without environmental constraints"""
    try:
        # Read the input file
        with open(file_path, "rb") as file:
            plaintext = file.read()

        # Compress the payload
        compressed = zlib.compress(plaintext)
        
        # Generate random salt and IV
        salt = secrets.token_bytes(SALT_SIZE)
        iv = secrets.token_bytes(IV_SIZE)
        
        # Derive key from password and salt
        master_key = derive_key(password.encode("utf-8"), salt)
        
        # Apply variable padding instead of standard PKCS7
        padded_data = variable_pad(compressed, AES.block_size)
        
        # Create AES cipher object
        cipher = AES.new(master_key, AES.MODE_CBC, iv)
        
        # First layer: AES encryption
        aes_encrypted = cipher.encrypt(padded_data)
        
        # Generate random XOR key for second layer
        xor_key = generate_xor_key()
        
        # Second layer: XOR encryption
        dual_encrypted = xor_encrypt(aes_encrypted, xor_key)
        
        # Create output filename
        output_path = file_path + ".enc"
        
        # Format the final payload with all components
        with open(output_path, "wb") as output_file:
            # Write magic header (4 bytes)
            output_file.write(struct.pack("<I", MAGIC_HEADER))
            # Write salt (16 bytes)
            output_file.write(salt)
            # Write IV (16 bytes) 
            output_file.write(iv)
            # Write XOR key (32 bytes)
            output_file.write(xor_key)
            # Write encrypted payload
            output_file.write(dual_encrypted)
            
        # Print success info
        print(f"\n{GREEN}[+] CryptexX v{VERSION} encryption successful!{RESET}")
        print(f"    Magic: 0x{MAGIC_HEADER:08X}")
        print(f"    Salt: {salt.hex()}")
        print(f"    IV: {iv.hex()}")
        print(f"    XOR Key: {xor_key.hex()}")
        
        print(f"    Compressed: {len(plaintext)} → {len(compressed)} bytes")
        print(f"    Final size: {os.path.getsize(output_path)} bytes")
        print(f"    Output: {YELLOW}{output_path}{RESET}")
        
        # Successfully created .enc file
        print(f"\n{GREEN}[+] Stateless payload ready for deployment.{RESET}")
        
        # Securely wipe sensitive data
        secure_wipe(master_key)
        secure_wipe(plaintext)
        secure_wipe(compressed)
        secure_wipe(padded_data)
        secure_wipe(aes_encrypted)
        
        return True
        
    except Exception as e:
        print(f"\n{RED}Error: {e}{RESET}")
        return False

def main():
    """Main function to handle user input and encryption"""
    print("\n=============================================")
    print(f"{YELLOW}CryptexX v{VERSION}{RESET} - Stateless Payload Encrypter")
    print("=============================================\n")
    
    try:
        # Get file path with validation
        while True:
            file_path = input("Enter payload file path: ").strip()
            if os.path.isfile(file_path):
                break
            print(f"{RED}Error: File '{file_path}' not found. Try again.{RESET}")
        
        # Get password with confirmation
        while True:
            password = getpass.getpass("Enter encryption password: ")
            if not password:
                print(f"{RED}Password cannot be empty. Try again.{RESET}")
                continue
            
            confirm = getpass.getpass("Confirm password: ")
            if password == confirm:
                break
            print(f"{RED}Passwords do not match. Try again.{RESET}")
        
        # Encrypt the file with no environmental constraints
        encrypt_file(file_path, password)
        
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Operation cancelled by user.{RESET}")
    except Exception as e:
        print(f"\n{RED}An unexpected error occurred: {e}{RESET}")
    
    print(f"\n{GREEN}[+] Operation complete.{RESET}\n")

if __name__ == "__main__":
    main()
