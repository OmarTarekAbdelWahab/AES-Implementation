# AES Encryption and Decryption in Python

## Overview
This project implements the **AES (Advanced Encryption Standard)** algorithm in Python using the **BitVector** library. It supports **128-bit key encryption and decryption**.

## Features
- Implements **AES key expansion** (key schedule)
- Supports **encryption and decryption** of 128-bit blocks
- Implements AES transformations:
  - **SubBytes & Inverse SubBytes**
  - **ShiftRows & Inverse ShiftRows**
  - **MixColumns & Inverse MixColumns**
  - **AddRoundKey**
- Encrypts and decrypts text in **16-byte blocks** (PKCS7 padding is not implemented)

## Installation
Ensure you have Python installed, then install `BitVector`:
```sh
pip install BitVector
```

## Usage
### Encrypting a message
```python
aes = AES("mysecretkey12345")  # 16-byte key
ciphertext = aes.encrypt("Hello, AES Encryption!")
print("Ciphertext:", ciphertext)
```

### Decrypting a message
```python
decrypted_text = aes.decrypt(ciphertext)
print("Decrypted text:", decrypted_text)
```

## File Structure
- `AES Implementation.py`: The main AES implementation
- `README.md`: Project documentation

## Notes
- The key must be **16 bytes (128 bits)**.
- Input text is padded with `0`s if not a multiple of 16 bytes.


