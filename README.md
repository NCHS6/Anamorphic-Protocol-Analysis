# Anamorphic Protocol Analysis

This project implements and evaluates an **anamorphic extension of AES-GCM** that embeds a covert communication channel into the IV generation process. The goal is to compare the **performance overhead** introduced by the covert-IV construction with standard AES-GCM encryption and decryption.

The implementation is written in **Python** and uses the `cryptography` library for AES-GCM operations.

---

# Overview

Two protocols are implemented and compared.

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

---

# Project Structure

```
aes_gcm/
    protocols/
        aes_gcm.py
        covert_iv_extension.py
    utils/
        prf.py

experiments/
    benchmark.py
    demo.py

main.py
requirements.txt
README.md
```

### Key Components

**`aes_gcm/protocols/aes_gcm.py`**

Implements standard AES-GCM encryption and decryption.

**`aes_gcm/protocols/covert_iv_extension.py`**

Implements the anamorphic protocol:

```
aEnc(m, m_c)
aDec(iv, c)
```

**`aes_gcm/utils/prf.py`**

Defines the pseudorandom function:

```
PRF(dkey, ctr) = HMAC-SHA256(dkey, ctr)[:12]
```

The output is truncated to **12 bytes** to match the 96-bit IV requirement of AES-GCM.

**`experiments/demo.py`**

Provides simple demonstrations verifying that:

* overt messages decrypt correctly
* covert messages are recovered correctly

**`experiments/benchmark.py`**

Implements performance benchmarks comparing:

* standard AES-GCM
* the anamorphic covert-IV protocol

**`main.py`**

Runs the benchmarks across multiple message lengths and generates plots of the results.

---

# Installation

Clone the repository and install dependencies:

```bash
pip install -r requirements.txt
```

Dependencies:

```
cryptography
matplotlib
```
