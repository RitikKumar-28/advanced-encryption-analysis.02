# Cyber Security Suite - Advanced Encryption & Analysis

A secure file encryption/decryption tool and malware behavior analysis platform. Built with Python (Flask) and a premium modern UI.

## Features

- 🔐 **Advanced Encryption**: Supports AES (CBC, GCM, CTR, CFB, OFB) and ChaCha20-Poly1305.
- 🛡️ **Malware Sandbox**: Simulate file execution to monitor suspicious filesystem, network, and process activity.
- 🔑 **Secure Key Derivation**: Uses PBKDF2-HMAC-SHA256 with 100,000+ iterations.
- 🎨 **Premium UI**: Dynamic RGB animations, glassmorphism, and responsive dashboard.
- 🔒 **Privacy Focused**: No files are stored permanently; temporary files are wiped after download.

## Installation

### Prerequisites

- Python 3.8+
- pip

### Setup

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the application**:
   ```bash
   python backend/app.py
   ```

3. **Access the platform**:
   - Open your browser and go to `http://localhost:5000`

## Technical Details

### Encrypted File Format
The `.enc` files follow this binary structure:
`[1 byte: Algo ID] + [16 bytes: Salt] + [Variable: IV/Nonce] + [Variable: Encrypted Data (+ Tag)]`

### Performance & Security
- **Max File Size**: 100MB (default configuration to prevent OOM).
- **Auto-Cleanup**: Temporary processing files are automatically deleted after a 10-second window.
- **CORS Support**: Securely handles cross-origin requests from frontend servers.

## Disclaimer
This tool is for educational and legitimate use only. Always remember: **Recovering data without the password is impossible.**
