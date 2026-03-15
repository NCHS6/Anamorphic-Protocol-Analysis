
# Anamorphic Protocol Analysis

This project implements and evaluates **anamorphic cryptographic extensions** that embed covert communication channels within standard cryptographic protocols.

Two schemes are explored:

**Anamorphic AES-GCM (Covert-IV Scheme)**
Embeds covert data into the AES-GCM initialization vector (IV).

**Anamorphic Signal (Covert-Keyspace Scheme)**
Embeds covert data within the public key space of Signal’s Diffie–Hellman ratchet using rejection sampling.

The goal of this project is to evaluate the computational overhead and practical feasibility of these covert channels compared to their standard implementations.

The implementation is written in **Python** and uses the `cryptography` library for cryptographic primitives.

---

# Overview


## 1. Standard AES-GCM

A baseline implementation of AES-GCM using randomly generated IVs.

Operations:

* `Gen()` – generate a session key
* `Enc(m)` – encrypt a message
* `Dec(iv, c)` – decrypt a ciphertext

## 2. Anamorphic Covert-IV Extension

An extension that embeds a **covert message inside the IV** used by AES-GCM.

Instead of generating a random IV, the protocol:

1. Computes a pseudorandom mask using a PRF
2. XORs the mask with the covert message
3. Uses the result as the AES-GCM IV

Formally:

```
mask = PRF(dkey, ctr)
IV   = mask ⊕ m_c
```

Where:

* `dkey` is a key used for the pseudorandom function
* `ctr` is a 32-bit counter
* `m_c` is the covert message
* `IV` is the nonce passed to AES-GCM

The receiver can recover the covert message by recomputing the mask and reversing the XOR operation.

## 3. Standard Signal

A baseline implementation of Signal using AES-GCM for symmetric encryption.

Operations:

* `Gen()` – generate a session key
* `Send(m, asymmetric)` – encrypt a message
* `Recv(header, iv, c)` – decrypt a ciphertext

## 4. Anamorphic Covert-Keyspace Extension

This extension embeds covert messages into the Diffie–Hellman ratchet public key used in the Signal protocol.

The sender repeatedly generates candidate public keys until one satisfies:

```
PRF(dkey, pk) = m_c 
```

Where:

* `pk` is a candidate ratchet public key
* `dkey` is a covert key shared between communicating parties
* `m_c` is a covert message
---

# Project Structure

```
aes_gcm/
│
├── protocols/
│   ├── aes_gcm.py
│   └── covert_iv_extension.py
│
├── utils/
│   ├── prf.py
│   └── xor.py
│
├── experiments/
│   ├── benchmark.py
│   └── demo.py
│
signal/
│
├── protocols/
│   ├── signal.py
│   └── covert_keyspace_extension.py
│
├── utils/
│   ├── kdf.py
│   └── prf.py
│
├── experiments/
│   ├── benchmark.py
│   └── demo.py
│
plots.py
main.py
requirements.txt
README.md
```

### Key Components

# Protocols

**`aes_gcm/protocols/aes_gcm.py`**

Implements standard AES-GCM encryption and decryption.

**`aes_gcm/protocols/covert_iv_extension.py`**

Implements the anamorphic protocol:

```
aEnc(m, m_c)
aDec(iv, c)
```

**`signal/protocols/signal.py`**

Implements a simplified version of the Signal Double Ratchet protocol

**`signal/protocols/covert_keyspace_extension.py`**

Implements the anamorphic Signal extension:

```
aSend(m, m_c)
aRecv(header, iv, ciphertext)
```

Covert messages are embedded into the ratchet public key using rejection sampling.

# Utilities

**`aes_gcm/utils/prf.py`**

Defines the pseudorandom function:

```
PRF(dkey, ctr) = HMAC-SHA256(dkey, ctr)[:12]
```

The output is truncated to **12 bytes** to match the 96-bit IV requirement of AES-GCM.

**`aes_gcm/utils/xor.py`**

Provides helper utilities for XOR operations used in IV masking.

**`signal/utils/kdf.py`**

Implements key derivation functions used in the Signal ratchet.

**`signal/utils/prf.py`**

Defines the pseudorandom function used in rejection sampling. Truncates outputs to the length of the covert message.

# Experiments

**`experiments/demo.py`**

Provides simple demonstrations verifying that:

* overt messages decrypt correctly
* covert messages are recovered correctly

**`experiments/benchmark.py`**

Implements performance benchmarks comparing standard schemes to the anamorphic ones.

# Plots

`plots.py` generates visualizations of performance overhead, including:

* encryption timing comparisons
* decryption timing comparisons
* overhead introduced by covert channels

Plots are exported as PNG files.

---

# Running the experiments

Clone the repository and install dependencies:

```bash
pip install -r requirements.txt
```

Clone the repository and install dependencies:

Run the main evaluation script:
```
python main.py
```

Dependencies:

```
cryptography
matplotlib
numpy
```