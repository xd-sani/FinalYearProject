# 🔐 Secure Image Encryption and Transmission Using Visual Cryptography

> **Final Year Project | Computer Science and Engineering**

A client-side image encryption and secure transmission system that combines XOR-based Visual Cryptography, RGB Mean Calculation, Dynamic SHA-256, HKDF-SHA-256, AES-256-GCM, HMAC-SHA-256, and Replay Protection.

The project implements a Sender–Receiver architecture to encrypt colour images, securely transmit encrypted image shares, and reconstruct the original image after successful verification.

---

## 📋 Project Summary

This project focuses on secure image encryption and transmission using a combination of Visual Cryptography and modern cryptographic algorithms.

The sender accepts a colour image and processes its RGB pixel data. It generates two secret shares using XOR-based Visual Cryptography, calculates their RGB mean values, and generates cryptographic hashes.

A shared 256-bit master secret is used with HKDF-SHA-256 to derive separate cryptographic keys. Both shares are encrypted independently using AES-256-GCM.

The system then authenticates the package manifest using HMAC-SHA-256, creates a ZIP package, and transmits it to the receiver using TCP.

The receiver validates the package, verifies its authenticity, decrypts both shares, checks their RGB mean values, and reconstructs the original image using XOR.

Finally, SHA-256 verification confirms whether the reconstructed RGB data matches the original image.

---

## 🎯 Project Objectives

- [x] Implement XOR-based Visual Cryptography.
- [x] Generate two secret shares from an original colour image.
- [x] Calculate RGB mean values for both shares.
- [x] Calculate original image SHA-256 and MD5 hashes.
- [x] Implement Dynamic SHA-256 verification.
- [x] Derive cryptographic keys using HKDF-SHA-256.
- [x] Encrypt image shares using AES-256-GCM.
- [x] Authenticate the manifest using HMAC-SHA-256.
- [x] Package encrypted files using ZIP.
- [x] Transmit encrypted packages using TCP.
- [x] Implement replay protection.
- [x] Reconstruct the original image using XOR.
- [x] Verify reconstructed image integrity using SHA-256.

---

## 🏗️ System Architecture

The project consists of two primary modules.

| Module | Responsibility |
|---|---|
| Sender | Image processing, secret sharing, hashing, key derivation, encryption, packaging and transmission |
| Receiver | Package validation, authentication, decryption, share verification, reconstruction and integrity verification |

### 🔄 Overall Workflow

```text
                  SENDER
                    |
                    v
             Input Colour Image
                    |
                    v
              Decode Image
                    |
                    v
             Extract RGB Data
                    |
                    v
          Calculate Original Hashes
              SHA-256 and MD5
                    |
                    v
           Generate XOR Secret Shares
                    |
                    v
             Calculate RGB Means
                    |
                    v
             Dynamic SHA-256
                    |
                    v
             HKDF-SHA-256
                    |
                    v
              AES-256-GCM
                    |
                    v
             HMAC-SHA-256
                    |
                    v
              Create ZIP
                    |
                    v
             TCP Transmission
                    |
                    v
                  RECEIVER
                    |
                    v
             Receive ZIP Package
                    |
                    v
             Validate ZIP Structure
                    |
                    v
             Verify Manifest HMAC
                    |
                    v
              Replay Protection
                    |
                    v
             Verify Dynamic Digest
                    |
                    v
             Derive Decryption Keys
                    |
                    v
             AES-GCM Decryption
                    |
                    v
             Verify RGB Means
                    |
                    v
             XOR Reconstruction
                    |
                    v
           Calculate Final SHA-256
                    |
                    v
          Compare Original SHA-256
                    |
                    v
            Successful Verification
```

---

## ⚙️ Technologies and Algorithms

| Technology / Algorithm | Purpose |
|---|---|
| JavaScript | Main programming language |
| Node.js | Runtime environment |
| jpeg-js | JPEG image decoding |
| XOR Secret Sharing | Generate and reconstruct image shares |
| RGB Processing | Extract and process colour pixel data |
| RGB Mean Calculation | Additional share consistency verification |
| MD5 | Academic hash comparison |
| SHA-256 | Image integrity verification |
| Dynamic SHA-256 | Dynamic digest verification |
| HKDF-SHA-256 | Cryptographic key derivation |
| AES-256-GCM | Image share encryption and authentication |
| HMAC-SHA-256 | Manifest authentication |
| ZIP | Encrypted package creation and validation |
| TCP | Sender-to-receiver communication |

---

## 📁 Project Structure

```text
FinalYearProject/
│
├── node_modules/
│   └── jpeg-js/
│
├── common.js
│
├── sender.js
│
├── receiver.js
│
├── package.json
│
├── package-lock.json
│
├── photo.png
│
├── README.md
│
├── .gitignore
│
└── master.key              (Generated automatically; do not upload)
```

### File Responsibilities

| File / Directory | Description |
|---|---|
| `common.js` | Shared functions for cryptographic operations, image processing, hashing, key derivation and ZIP utilities |
| `sender.js` | Sender-side image processing, secret sharing, encryption, package creation and transmission |
| `receiver.js` | Receiver-side package validation, authentication, decryption, reconstruction and verification |
| `package.json` | Project configuration and dependency definitions |
| `package-lock.json` | Records the installed npm dependency versions |
| `node_modules/` | Installed Node.js dependencies |
| `jpeg-js/` | JPEG image decoding library |
| `photo.png` | Sample input colour image |
| `README.md` | Project documentation |
| `master.key` | Shared 256-bit master secret generated automatically when required |
| `.gitignore` | Excludes sensitive and generated files from Git |

---

## 💻 Installation and Setup

### Prerequisites

- Node.js
- npm
- Git (optional)

### Step 1: Clone the Repository

```bash
git clone https://github.com/xd-sani/FinalYearProject.git
```

### Step 2: Open the Project Directory

```bash
cd FinalYearProject
```

### Step 3: Install Dependencies

```bash
npm install
```

This installs the dependencies specified in `package.json`.

### Step 4: Master Key Setup

The project uses a shared 256-bit master secret.

- If `master.key` does not exist, the sender generates it automatically.
- If it already exists, the sender loads the existing key.
- The receiver must use the same master secret to derive the corresponding decryption keys.

**Important:** Never upload `master.key` to GitHub.

---

## 🚀 How to Run the Project

### Step 1: Start the Receiver

Open the first terminal:

```bash
node receiver.js
```

Expected output:

```text
RECEIVER listening on 127.0.0.1:5000
```

The receiver waits for an incoming encrypted package.

### Step 2: Start the Sender

Open a second terminal in the project directory:

```bash
node sender.js photo.png
```

The sender performs:

1. Image loading and decoding.
2. RGB data extraction.
3. Original SHA-256 and MD5 calculation.
4. XOR secret share generation.
5. RGB mean calculation.
6. Dynamic SHA-256 generation.
7. HKDF-SHA-256 key derivation.
8. AES-256-GCM encryption.
9. HMAC-SHA-256 manifest authentication.
10. ZIP package creation.
11. TCP transmission.

### Step 3: Receiver Verification

The receiver performs:

1. Package reception.
2. ZIP structure validation.
3. Manifest field validation.
4. HMAC-SHA-256 verification.
5. Replay protection.
6. Dynamic digest verification.
7. Key derivation.
8. AES-256-GCM decryption.
9. RGB mean verification.
10. XOR image reconstruction.
11. Final SHA-256 comparison.

If all checks pass, the receiver accepts the package and saves the reconstructed image.

---

## 🧪 Security and Attack Demonstrations

The project includes attack demonstration options.

### 1. Ciphertext Modification Attack

```bash
node sender.js photo.png --attack=flip
```

Purpose: Demonstrates AES-256-GCM ciphertext authentication.

Expected result: Receiver rejects the modified ciphertext because authentication fails.

### 2. Manifest Modification Attack

```bash
node sender.js photo.png --attack=manifest
```

Purpose: Demonstrates manifest authentication.

Expected result: Receiver rejects the package because HMAC verification fails.

### 3. Wrong Master Key Test

```bash
node sender.js photo.png --attack=wrongkey
```

Purpose: Demonstrates the requirement for the correct shared master secret.

Expected result: Receiver rejects the package during manifest HMAC verification.

### 4. Replay Attack Demonstration

```bash
node sender.js --resend
```

Purpose: Resends a previously saved encrypted package.

Expected result: Receiver rejects the package if its package ID has already been accepted.

> The above outcomes describe expected behaviour. Actual attack-test results should be recorded after executing the commands.

---

## 🔍 Verification and Security Checks

| No. | Verification | Purpose |
|---|---|---|
| 1 | ZIP Validation | Validates package structure and contents |
| 2 | Manifest Validation | Checks required metadata |
| 3 | HMAC-SHA-256 | Authenticates manifest integrity |
| 4 | Replay Protection | Rejects previously accepted package IDs |
| 5 | Dynamic SHA-256 | Verifies the dynamic digest |
| 6 | AES-256-GCM | Authenticates decrypted shares |
| 7 | RGB Mean Verification | Checks share consistency |
| 8 | Final SHA-256 | Verifies reconstructed image integrity |

---

## 📊 Sample Execution Results

A successful execution was performed using an 800 × 602 colour image.

### Original Image Information

| Parameter | Result |
|---|---|
| Image Width | 800 pixels |
| Image Height | 602 pixels |
| RGB Data Size | 1,444,800 bytes |
| Original SHA-256 | `f4183395e65cfcb0ff3048231fac9e9b4378e4a2f8faa9e61de3d1e17deef836` |
| Original MD5 | `432d6649bf2b3acb432484cc0e475a45` |

### Receiver Verification

| Verification | Result |
|---|---|
| ZIP Structure | PASS |
| Manifest Validation | PASS |
| Manifest HMAC | PASS |
| Replay Protection | PASS |
| Dynamic SHA-256 | PASS |
| AES-GCM Authentication | PASS |
| RGB Mean Verification | PASS |
| Final SHA-256 Comparison | PASS |

### Final Output

```text
RESULT SUCCESS: package accepted.

Reconstructed image SHA-256 matches.

All authenticity and integrity checks passed.
```

---

## 📂 Generated Output

The receiver stores the decrypted shares, reconstructed image and verification report in its runtime output directory.

Generated runtime files are excluded from the Git repository.

---

## 🔒 Security Considerations

- AES-256-GCM provides confidentiality and authentication for encrypted image shares.
- HMAC-SHA-256 authenticates the package manifest.
- HKDF-SHA-256 derives separate keys for different cryptographic purposes.
- Unique package IDs and persistent records provide replay protection.
- SHA-256 verifies the integrity of the reconstructed RGB image.
- RGB mean comparison provides an additional consistency check, not cryptographic authentication.
- MD5 is included for academic comparison and is not relied upon for security.

### Current Limitations

- The current implementation uses TCP rather than TLS.
- TLS 1.3 with certificate verification should be implemented before deployment over untrusted networks.
- Replay protection depends on preserving the receiver's accepted package ID database.
- The project is an academic prototype and has not undergone an independent security audit.

---

## 🛡️ GitHub Security Checklist

Before committing or publishing:

- [x] `.gitignore` excludes `master.key`.
- [x] `.gitignore` excludes `node_modules/`.
- [x] `.gitignore` excludes generated runtime files.
- [ ] Verify that no master secret exists in Git history.
- [ ] Verify that no passwords or sensitive information are committed.
- [ ] Confirm that the sample image can be publicly shared.

### Recommended `.gitignore`

```gitignore
# Dependencies
node_modules/

# Master encryption secret
master.key

# Generated output
runtime_output/

# Environment variables
.env
.env.*
```

**Important:** If `master.key` was committed previously, adding it to `.gitignore` does not remove it from Git history.

---

## 📚 Future Enhancements

- [ ] Browser extension integration.
- [ ] TLS 1.3 secure network communication.
- [ ] Secure master-key provisioning and rotation.
- [ ] Automated security and attack testing.
- [ ] Improved key management.
- [ ] Independent security audit.
- [ ] Graphical user interface for image encryption and transmission.

---

## 👨‍💻 Project Information

| Field | Details |
|---|---|
| Project Title | Client-Side End-to-End Image Encryption and Secure Transmission Using Visual Cryptography |
| Project Type | Final Year Project |
| Domain | Cybersecurity, Cryptography and Image Processing |
| Language | JavaScript |
| Runtime | Node.js |
| Architecture | Sender–Receiver |
| Image Sharing | XOR-Based Visual Cryptography |
| Encryption | AES-256-GCM |
| Key Derivation | HKDF-SHA-256 |
| Authentication | HMAC-SHA-256 |
| Integrity | SHA-256 |

---

## 🔗 GitHub Repository

**Source Code:** https://github.com/xd-sani/FinalYearProject

---

## ⭐ Acknowledgement

This project demonstrates the application of Visual Cryptography and modern cryptographic algorithms to develop a secure image encryption and transmission prototype.