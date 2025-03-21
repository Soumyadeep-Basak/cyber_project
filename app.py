import streamlit as st
import base64
import os
import hashlib
import struct

# Set page configuration
st.set_page_config(
    page_title="RC5-CBC Cipher-Decipher Tool",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# RC5 Implementation (Pure Python)
class RC5:
    def __init__(self, key, rounds=12, w=32):
        self.rounds = rounds
        self.w = w
        self.mod = 2 ** w
        self.S = self._key_expansion(key)

    def _key_expansion(self, key):
        """Key schedule for RC5."""
        key_length = len(key)
        L = list(struct.unpack('<' + 'I' * (key_length // 4), key.ljust(16, b'\x00')))
        P, Q = 0xB7E15163, 0x9E3779B9
        S = [(P + i * Q) % self.mod for i in range(2 * (self.rounds + 1))]

        A = B = i = j = 0
        for _ in range(3 * max(len(L), len(S))):
            A = S[i] = ((S[i] + A + B) % self.mod) << 3
            B = L[j] = ((L[j] + A + B) % self.mod) << (A + B) % self.w
            i = (i + 1) % len(S)
            j = (j + 1) % len(L)
        return S

    def _left_rotate(self, value, shift):
        """Left circular shift."""
        return ((value << shift) & (self.mod - 1)) | (value >> (self.w - shift))

    def _right_rotate(self, value, shift):
        """Right circular shift."""
        return (value >> shift) | ((value << (self.w - shift)) & (self.mod - 1))

    def encrypt_block(self, data):
        """Encrypts an 8-byte block using RC5."""
        A, B = struct.unpack('<II', data)
        A = (A + self.S[0]) % self.mod
        B = (B + self.S[1]) % self.mod

        for i in range(1, self.rounds + 1):
            A = (self._left_rotate((A ^ B), B % self.w) + self.S[2 * i]) % self.mod
            B = (self._left_rotate((B ^ A), A % self.w) + self.S[2 * i + 1]) % self.mod

        return struct.pack('<II', A, B)

    def decrypt_block(self, data):
        """Decrypts an 8-byte block using RC5."""
        A, B = struct.unpack('<II', data)

        for i in range(self.rounds, 0, -1):
            B = self._right_rotate((B - self.S[2 * i + 1]) % self.mod, A % self.w) ^ A
            A = self._right_rotate((A - self.S[2 * i]) % self.mod, B % self.w) ^ B

        B = (B - self.S[1]) % self.mod
        A = (A - self.S[0]) % self.mod

        return struct.pack('<II', A, B)

# Derive key from password
def derive_key(password, key_length):
    key_bytes = key_length // 8
    return hashlib.sha256(password.encode()).digest()[:key_bytes]

# Generate a random IV
def generate_random_iv():
    return os.urandom(8)  # 64-bit IV for RC5

# XOR function for CBC mode
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# RC5 Encryption (CBC Mode)
def encrypt_text(plaintext, password, iv, key_length):
    try:
        key = derive_key(password, key_length)
        rc5 = RC5(key)
        
        # Padding
        pad_len = 8 - (len(plaintext) % 8)
        padded_plaintext = plaintext + chr(pad_len) * pad_len

        ciphertext = b""
        prev_block = iv
        for i in range(0, len(padded_plaintext), 8):
            block = padded_plaintext[i:i+8].encode()
            block = xor_bytes(block, prev_block)  # CBC XOR
            encrypted_block = rc5.encrypt_block(block)
            ciphertext += encrypted_block
            prev_block = encrypted_block  # Update previous block
        
        return base64.b64encode(iv + ciphertext).decode('utf-8')
    except Exception as e:
        return f"Encryption Error: {str(e)}"

# RC5 Decryption (CBC Mode)
def decrypt_text(ciphertext, password, key_length):
    try:
        key = derive_key(password, key_length)
        rc5 = RC5(key)

        raw_data = base64.b64decode(ciphertext)
        iv, raw_ciphertext = raw_data[:8], raw_data[8:]

        decrypted_text = b""
        prev_block = iv

        for i in range(0, len(raw_ciphertext), 8):
            encrypted_block = raw_ciphertext[i:i+8]
            decrypted_block = rc5.decrypt_block(encrypted_block)
            decrypted_block = xor_bytes(decrypted_block, prev_block)  # CBC XOR
            decrypted_text += decrypted_block
            prev_block = encrypted_block  # Update previous block

        # Remove padding
        pad_len = decrypted_text[-1]
        return decrypted_text[:-pad_len].decode()
    except Exception as e:
        return f"Decryption Error: {str(e)}"

# Streamlit UI
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Home", "Encryption", "Decryption"])

if page == "Home":
    st.title("RC5-CBC Cipher-Decipher Tool")
    st.markdown("""
    ### Welcome to the RC5-CBC Cipher-Decipher Tool
    
    This tool provides encryption and decryption using the RC5 algorithm in CBC mode.
    
    **Features:**
    - Text encryption and decryption
    - File encryption and decryption (coming soon)
    - Multiple key lengths (128-bit, 192-bit, 256-bit)
    """)

elif page == "Encryption":
    st.title("Encryption")
    plaintext = st.text_area("Enter plaintext to encrypt:", height=150)
    password = st.text_input("Enter encryption key:", type="password")
    key_length = st.selectbox("Select key length:", [128, 192, 256], index=0)
    iv = generate_random_iv()

    if st.button("Encrypt Text"):
        if plaintext and password:
            encrypted_text = encrypt_text(plaintext, password, iv, key_length)
            st.success("Encryption completed!")
            st.text_area("Encrypted text (Base64):", value=encrypted_text, height=100)
        else:
            st.warning("Please provide both plaintext and password.")

elif page == "Decryption":
    st.title("Decryption")
    ciphertext = st.text_area("Enter encrypted text (Base64):", height=150)
    password = st.text_input("Enter decryption key:", type="password")
    key_length = st.selectbox("Select key length:", [128, 192, 256], index=0)

    if st.button("Decrypt Text"):
        if ciphertext and password:
            decrypted_text = decrypt_text(ciphertext, password, key_length)
            st.success("Decryption completed!")
            st.text_area("Decrypted text:", value=decrypted_text, height=100)
        else:
            st.warning("Please provide both ciphertext and password.")
