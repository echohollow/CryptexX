# 🚀 CryptexX v2.1 — Stateless ATP Payload Encrypter

> **Built for adversarial automation. No locks. No limits. No barriers.**

---

## 🧬 Purpose

CryptexX v2.1 is a dual-layer encryption utility for payloads, optimized for red team deployment, autonomous dropper chains, and malware-as-a-service (MaaS) systems.

**Key Principles:**
- ❌ No HWID Locking
- ❌ No Loader Binding
- ❌ No Time Constraints
- ✅ Fully Stateless
- ✅ AES + XOR Obfuscation
- ✅ Deployment-Ready `.enc` Payloads

---

## 🔐 Encryption Stack

1. **AES-256-CBC**
    - Derived from PBKDF2-HMAC-SHA256 (200k iterations)
    - Unique Salt + IV per encryption

2. **XOR Layer**
    - Random 256-bit stream mask
    - Second-layer entropy against static scans

3. **Variable Padding**
    - Random byte noise + length byte
    - Prevents PKCS7 fingerprinting

4. **Compression**
    - Zlib pre-encryption compression to minimize IOCs

---

## 🛠️ Usage

```bash
$ python3 cryptexx_offensive.py

CryptexX v2.1 - Stateless Payload Encrypter
===========================================

Enter payload file path: loader.bin
Enter encryption password: *********
Confirm password: *********

[+] CryptexX v2.1 encryption successful!
    Salt: <hex>
    IV: <hex>
    XOR Key: <hex>
    Compressed: 124672 → 64310 bytes
    Final size: 64466 bytes
    Output: loader.bin.enc

[+] Stateless payload ready for deployment.
```

---

## ✅ Output Format

| Section        | Description                | Size    |
|----------------|----------------------------|---------|
| Magic Header   | Constant (0xC0DEDEAD)       | 4 bytes |
| Salt           | PBKDF2 Salt                | 16 bytes|
| IV             | AES IV                     | 16 bytes|
| XOR Key        | Random XOR stream          | 32 bytes|
| Payload        | AES + XOR encrypted binary | N bytes |

---

## 🧼 OPSEC Features

- RAM-wiped buffers post-encryption
- Stateless — decrypts anywhere
- Compatible with: `GhostInject`, `donut`, `Crypter`, `macro_dropper`

---

## 💥 Offensive Advantage

| Feature               | Status     |
|-----------------------|------------|
| HWID Lock             | ❌ Removed |
| Loader Hash Binding   | ❌ Removed |
| Time Window Restriction | ❌ Removed |
| AES-256 + XOR         | ✅ Enabled |
| Compression + Padding | ✅ Enabled |
| Secure RAM Wipe       | ✅ Enabled |

---

## 📎 Recommended Chain

```bash
CryptexX_Offensive → GhostStubBuilder → GhostInject.exe → dropper.py → payload.pdf
```

**GhostInject.exe** loads `.enc` in memory → decrypts → injects into `explorer.exe`

---

## 🧬 Final Thought

> Designed for **maximum execution, minimal forensics, and unlimited deployment flexibility**.

**You control the payload. Let nothing else decide where it runs.**
