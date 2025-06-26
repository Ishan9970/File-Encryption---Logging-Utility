import os
import zlib
import pyotp
import qrcode
import streamlit as st
import hashlib
from io import BytesIO
from datetime import datetime
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Constants
LOG_FILE = "secure_encryption_log.enc"
BLOCK_SIZE = 128
ENCRYPTION_SIGNATURE = b'ENCRYPTED::'
STATIC_SALT = b'static_salt_for_demo'
SECRET_FILE = "totp_secret.txt"

# Derive AES key from password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Write encrypted log entry
def write_encrypted_log(password: str, message: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data = f"{timestamp} - {message}".encode()
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    with open(LOG_FILE, "ab") as f:
        f.write(salt + iv + encrypted + b'\n')

# Read encrypted logs
def read_encrypted_logs(password: str):
    if not os.path.exists(LOG_FILE):
        return ["[INFO] No log file found."]
    results = []
    with open(LOG_FILE, "rb") as f:
        lines = f.readlines()
    for i, line in enumerate(lines):
        try:
            salt = line[:16]
            iv = line[16:32]
            encrypted = line[32:].strip()
            key = derive_key(password, salt)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded = decryptor.update(encrypted) + decryptor.finalize()
            unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
            decrypted = unpadder.update(padded) + unpadder.finalize()
            results.append(decrypted.decode())
        except Exception as e:
            results.append(f"[ERROR] Failed to decrypt log entry #{i+1}: {e}")
    return results

# Check if a file is already encrypted
def is_file_encrypted(data: bytes) -> bool:
    return data.startswith(ENCRYPTION_SIGNATURE)

# Encrypt file content
def encrypt_content(content: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    padded = padder.update(content) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return ENCRYPTION_SIGNATURE + iv + encrypted

# Decrypt file content
def decrypt_content(content: bytes, key: bytes) -> bytes:
    iv = content[len(ENCRYPTION_SIGNATURE):len(ENCRYPTION_SIGNATURE)+16]
    encrypted = content[len(ENCRYPTION_SIGNATURE)+16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    return unpadder.update(decrypted_padded) + unpadder.finalize()

# Streamlit GUI setup
st.set_page_config(page_title="Secure File Tool", layout="centered")
st.title("🔐 Secure File Encryption/Decryption GUI")

# TOTP setup
if 'totp_secret' not in st.session_state:
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "r") as f:
            st.session_state['totp_secret'] = f.read().strip()
    else:
        st.session_state['totp_secret'] = pyotp.random_base32()
        with open(SECRET_FILE, "w") as f:
            f.write(st.session_state['totp_secret'])
totp = pyotp.TOTP(st.session_state['totp_secret'], interval=30, digits=6, digest=hashlib.sha1)
uri = totp.provisioning_uri(name="SecureApp", issuer_name="MyEncryptionTool")
img = qrcode.make(uri)
buf = BytesIO()
img.save(buf)
buf.seek(0)
st.session_state['qr_image'] = buf
if 'verified' not in st.session_state:
    st.session_state['verified'] = False

# TOTP verification
if not st.session_state['verified']:
    st.image(st.session_state['qr_image'], caption="Scan this QR in your Authenticator App")
    code = st.text_input("Enter 6-digit code from Authenticator", max_chars=6)
    if st.button("Verify TOTP"):
        if totp.verify(code, valid_window=2):
            st.session_state['verified'] = True
            st.success("TOTP verification passed!")
        else:
            st.error("Invalid code. Please try again.")
    st.stop()

# Log password input
log_password = st.text_input("Log Password", type="password", value="abc123")

# Select operation
action = st.selectbox("Choose Action", ["Encrypt", "Decrypt", "Compress", "Decompress", "View Logs"])

# Handle file uploads (except for log viewing)
if action != "View Logs":
    uploaded_files = st.file_uploader("Upload files", type=None, accept_multiple_files=True)
    if uploaded_files:
        if action == "Encrypt":
            enc_password = st.text_input("Encryption Password", type="password")
            for i, uploaded_file in enumerate(uploaded_files):
                content = uploaded_file.read()
                filename = uploaded_file.name
                if st.button(f"Encrypt: {filename}", key=f"enc_{i}"):
                    try:
                        key = derive_key(enc_password, STATIC_SALT)
                        if is_file_encrypted(content):
                            st.warning(f"{filename} is already encrypted.")
                            write_encrypted_log(log_password, f"Encrypt - {filename} - Skipped (Already encrypted)")
                        else:
                            encrypted = encrypt_content(content, key)
                            st.download_button("Download Encrypted File", encrypted, file_name=filename + ".enc", key=f"download_enc_{i}")
                            st.success(f"{filename} encrypted successfully.")
                            write_encrypted_log(log_password, f"Encrypt - {filename} - Success")
                    except Exception as e:
                        st.error(str(e))
                        write_encrypted_log(log_password, f"Encrypt - {filename} - Failed: {e}")

        elif action == "Decrypt":
            dec_password = st.text_input("Decryption Password", type="password")
            for i, uploaded_file in enumerate(uploaded_files):
                content = uploaded_file.read()
                filename = uploaded_file.name
                if st.button(f"Decrypt: {filename}", key=f"dec_{i}"):
                    try:
                        key = derive_key(dec_password, STATIC_SALT)
                        if not is_file_encrypted(content):
                            st.warning(f"{filename} is not encrypted.")
                            write_encrypted_log(log_password, f"Decrypt - {filename} - Skipped (Not encrypted)")
                        else:
                            decrypted = decrypt_content(content, key)
                            clean_name = filename.replace(".enc", "")
                            st.download_button("Download Decrypted File", decrypted, file_name=clean_name, key=f"download_dec_{i}")
                            st.success(f"{filename} decrypted successfully.")
                            write_encrypted_log(log_password, f"Decrypt - {filename} - Success")
                    except Exception as e:
                        st.error(str(e))
                        write_encrypted_log(log_password, f"Decrypt - {filename} - Failed: {e}")

        elif action == "Compress":
            for i, uploaded_file in enumerate(uploaded_files):
                content = uploaded_file.read()
                filename = uploaded_file.name
                if st.button(f"Compress: {filename}", key=f"compress_{i}"):
                    try:
                        compressed = zlib.compress(content)
                        # Adjust filename based on whether the input is encrypted
                        if filename.endswith(".enc"):
                            compressed_filename = filename.replace(".enc", ".enc.zip")
                        else:
                            compressed_filename = filename + ".zip"
                        st.download_button("Download Compressed File", compressed, file_name=compressed_filename, key=f"download_comp_{i}")
                        st.success(f"{filename} compressed successfully.")
                        write_encrypted_log(log_password, f"Compress - {filename} - Success")
                    except Exception as e:
                        st.error(str(e))
                        write_encrypted_log(log_password, f"Compress - {filename} - Failed: {e}")

        elif action == "Decompress":
            for i, uploaded_file in enumerate(uploaded_files):
                content = uploaded_file.read()
                filename = uploaded_file.name
                if st.button(f"Decompress: {filename}", key=f"decompress_{i}"):
                    try:
                        decompressed = zlib.decompress(content)
                        # Adjust filename: remove .zip, and check if the result is encrypted
                        clean_name = filename.replace(".zip", "")
                        if is_file_encrypted(decompressed):
                            st.warning(f"Decompressed file {clean_name} is encrypted. Decrypt it to view the original content.")
                            clean_name = clean_name if clean_name.endswith(".enc") else clean_name + ".enc"
                        st.download_button("Download Decompressed File", decompressed, file_name=clean_name, key=f"download_decomp_{i}")
                        st.success(f"{filename} decompressed successfully.")
                        write_encrypted_log(log_password, f"Decompress - {filename} - Success")
                    except Exception as e:
                        st.error(str(e))
                        write_encrypted_log(log_password, f"Decompress - {filename} - Failed: {e}")

# View logs
elif action == "View Logs":
    view_pass = st.text_input("Password to View Logs", type="password")
    if st.button("Show Logs"):
        logs = read_encrypted_logs(view_pass)
        for log in logs:
            st.text(log)