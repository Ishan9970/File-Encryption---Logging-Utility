Here’s a complete and well-structured **`README.md`** for your GitHub repository based on the Streamlit-based secure file tool you’ve developed. This documentation includes:

* Project overview
* Features
* Installation instructions
* How to use
* Security notes
* File structure
* License placeholder

You can copy and save this as your `README.md` file in your GitHub repository:

---

# 🔐 Secure File Tool with TOTP, AES Encryption & Logging

A secure, interactive **Streamlit-based GUI** for file encryption, decryption, compression, decompression, and encrypted logging with **TOTP (Time-Based OTP)** authentication and **AES-CBC** encryption.

---

## 🚀 Features

* 🔑 **AES-256 CBC** encryption & decryption with password-derived keys
* 📦 **File compression and decompression** using zlib
* 📜 **Encrypted activity logging** with timestamps
* 🔐 **TOTP 2FA** (Google Authenticator compatible)
* 🖥️ Simple and user-friendly **Streamlit GUI**
* 📁 Support for multiple file uploads

---

## 📁 Functionalities

| Operation  | Description                                                 |
| ---------- | ----------------------------------------------------------- |
| Encrypt    | Encrypt uploaded files using AES-CBC and a password         |
| Decrypt    | Decrypt previously encrypted files                          |
| Compress   | Compress uploaded files using zlib                          |
| Decompress | Decompress previously compressed files                      |
| View Logs  | Securely view encrypted logs of actions (requires password) |

---

## 🧰 Technologies Used

* `Python 3.x`
* `Streamlit`
* `cryptography`
* `pyotp`
* `qrcode`
* `zlib`
* `hashlib`

---

## 🛠️ Installation

1. **Clone this repo:**

```bash
git clone https://github.com/your-username/secure-file-tool.git
cd secure-file-tool
```

2. **Create a virtual environment (optional but recommended):**

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies:**

```bash
pip install -r requirements.txt
```

4. **Run the app:**

```bash
streamlit run app.py
```

---

## 🔐 TOTP Authentication Setup

* On first run, a TOTP secret is generated and saved in `totp_secret.txt`.
* A QR code is shown — scan it using **Google Authenticator** or any TOTP app.
* Enter the 6-digit code from the app to access functionalities.

---

## 📌 Usage Instructions

1. **Launch the app** using Streamlit.
2. **Authenticate** using the scanned TOTP.
3. **Choose an action** from the dropdown.
4. **Upload files** and provide passwords where required.
5. Download the processed files directly from the interface.

---

## 🔒 Security Notes

* Passwords are **not stored**; they are used to derive AES keys during runtime.
* Each encryption/decryption/compression action is **logged securely** in `secure_encryption_log.enc`.
* All logs are encrypted using a user-supplied log password.

> ⚠️ This app uses a **static salt for demo purposes**. 

---

## 📂 Project Structure

```
.
├── app.py                  # Main Streamlit application
├── totp_secret.txt         # Stores the TOTP base32 secret (auto-generated)
├── secure_encryption_log.enc # Encrypted activity logs
├── requirements.txt        # Python dependencies
└── README.md               # Documentation
```



