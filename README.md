# kuricrypt

> Fast cryptography extension library for Telegram clients

**kuricrypt** is a Rust-based Python extension that implements the AES algorithms used by Telegram:

- **`AES-256-IGE`** - used in MTProto 2.0.
- **`AES-256-CTR`** - used for CDN encrypted files.
- **`AES-256-CBC`** - used for encrypted passport credentials.

The Python API is compatible with the six public `tgcrypto` functions.

## Requirements

- Python 3.10 or higher.
- A Rust toolchain is required when building from source.

## Installation

```bash
pip3 install -U kuricrypt
```

To build and install from a source checkout:

```bash
python -m pip install .
```

## API

```python
def ige256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...
def ige256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...

def ctr256_encrypt(data: bytes, key: bytes, iv: bytes, state: bytes) -> bytes: ...
def ctr256_decrypt(data: bytes, key: bytes, iv: bytes, state: bytes) -> bytes: ...

def cbc256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...
def cbc256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...
```

All functions accept contiguous Python buffer-protocol objects. Writable CTR and CBC `iv` buffers are updated in place. CTR also updates a writable one-byte `state` buffer so a stream can continue across chunks. Immutable buffers are accepted but are not modified.

## Usage

### IGE Mode

**Note**: Data must be non-empty and padded to a multiple of the block size (16 bytes).

```python
import os

import kuricrypt

data = os.urandom(10 * 1024 * 1024 + 7)
key = os.urandom(32)
iv = os.urandom(32)

data += bytes(-len(data) % 16)

ige_encrypted = kuricrypt.ige256_encrypt(data, key, iv)
ige_decrypted = kuricrypt.ige256_decrypt(ige_encrypted, key, iv)

assert data == ige_decrypted
```

### CTR Mode (single chunk)

```python
import os

import kuricrypt

data = os.urandom(10 * 1024 * 1024)
key = os.urandom(32)

enc_iv = bytearray(os.urandom(16))
dec_iv = enc_iv.copy()
enc_state = bytearray(1)
dec_state = bytearray(1)

ctr_encrypted = kuricrypt.ctr256_encrypt(data, key, enc_iv, enc_state)
ctr_decrypted = kuricrypt.ctr256_decrypt(ctr_encrypted, key, dec_iv, dec_state)

assert data == ctr_decrypted
```

### CTR Mode (stream)

```python
import os
from io import BytesIO

import kuricrypt

data = BytesIO(os.urandom(10 * 1024 * 1024))
key = os.urandom(32)

enc_iv = bytearray(os.urandom(16))
dec_iv = enc_iv.copy()
enc_state = bytearray(1)
dec_state = bytearray(1)

encrypted_data = BytesIO()
decrypted_data = BytesIO()

while chunk := data.read(1024):
	encrypted_data.write(kuricrypt.ctr256_encrypt(chunk, key, enc_iv, enc_state))

encrypted_data.seek(0)
while chunk := encrypted_data.read(1024):
	decrypted_data.write(kuricrypt.ctr256_decrypt(chunk, key, dec_iv, dec_state))

assert data.getvalue() == decrypted_data.getvalue()
```

### CBC Mode

**Note**: Data must be non-empty and padded to a multiple of the block size (16 bytes).

```python
import os

import kuricrypt

data = os.urandom(10 * 1024 * 1024 + 7)
key = os.urandom(32)

enc_iv = bytearray(os.urandom(16))
dec_iv = enc_iv.copy()

data += bytes(-len(data) % 16)

cbc_encrypted = kuricrypt.cbc256_encrypt(data, key, enc_iv)
cbc_decrypted = kuricrypt.cbc256_decrypt(cbc_encrypted, key, dec_iv)

assert data == cbc_decrypted
```

## Testing

```bash
python -m pip install pytest
python -m pytest
```
