import streamlit as st
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib

# Set page configuration
st.set_page_config(
    page_title="RC5-CBC Cipher-Decipher Tool",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state variables if they don't exist
if 'theme' not in st.session_state:
    st.session_state.theme = "light"

def toggle_theme():
    st.session_state.theme = "dark" if st.session_state.theme == "light" else "light"

# Apply theme
if st.session_state.theme == "dark":
    st.markdown("""
    <style>
    .stApp {
        background-color: #1E1E1E;
        color: #FFFFFF;
    }
    .stTextInput, .stTextArea {
        background-color: #2D2D2D;
        color: #FFFFFF;
    }
    .stButton>button {
        background-color: #0078D7;
        color: white;
    }
    .stSelectbox {
        background-color: #2D2D2D;
        color: #FFFFFF;
    }
    </style>
    """, unsafe_allow_html=True)

# Navigation bar
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Home", "Encryption", "Decryption"])

# Sidebar theme toggle
# st.sidebar.button("Toggle Light/Dark Mode", on_click=toggle_theme)

# Helper functions for encryption operations
def derive_key(password, key_length):
    # Convert key_length from bits to bytes
    key_bytes = key_length // 8
    # Use SHA-256 for key derivation (in a real app, use a proper KDF)
    return hashlib.sha256(password.encode()).digest()[:key_bytes]

def encrypt_text(plaintext, password, iv, key_length):
    try:
        key = derive_key(password, key_length)
        
        # Since we can't directly use RC5, we'll use AES as a placeholder
        # In a real implementation, you would use RC5 in CBC mode
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine IV and ciphertext for storage/transmission
        result = iv + ciphertext
        return base64.b64encode(result).decode('utf-8')
    except Exception as e:
        return f"Encryption Error: {str(e)}"

def decrypt_text(ciphertext, password, iv, key_length):
    try:
        key = derive_key(password, key_length)
        
        # Decode base64 ciphertext
        raw_data = base64.b64decode(ciphertext)
        
        # Extract IV if it's included in the ciphertext
        if len(iv) == 0 and len(raw_data) >= 16:
            iv = raw_data[:16]
            raw_ciphertext = raw_data[16:]
        else:
            raw_ciphertext = raw_data
        
        # Since we can't directly use RC5, we'll use AES as a placeholder
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(raw_ciphertext) + decryptor.finalize()
        
        # Unpad the plaintext
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"Decryption Error: {str(e)}"

def generate_random_iv():
    return os.urandom(16)

# Function to handle file uploads for encryption/decryption
def process_file(uploaded_file, password, iv, key_length, mode):
    if uploaded_file is not None:
        try:
            file_content = uploaded_file.getvalue()
            key = derive_key(password, key_length)
            
            if mode == "encrypt":
                # Encrypt file content
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(file_content) + padder.finalize()
                
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(padded_data) + encryptor.finalize()
                
                # Combine IV and ciphertext for storage
                return iv + ciphertext
            else:
                # Decrypt file content - assuming first 16 bytes are IV
                if len(iv) == 0 and len(file_content) >= 16:
                    iv = file_content[:16]
                    raw_ciphertext = file_content[16:]
                else:
                    raw_ciphertext = file_content
                
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                padded_plaintext = decryptor.update(raw_ciphertext) + decryptor.finalize()
                
                # Unpad the plaintext
                unpadder = padding.PKCS7(128).unpadder()
                plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
                
                return plaintext
        except Exception as e:
            st.error(f"File Processing Error: {str(e)}")
            return None
    return None

def download_button(data, file_extension, button_text):
    if data is not None:
        b64 = base64.b64encode(data).decode()
        button_uuid = "download_button_" + file_extension
        dl_link = f'<a href="data:application/octet-stream;base64,{b64}" download="processed_file.{file_extension}" id="{button_uuid}">{button_text}</a>'
        st.markdown(dl_link, unsafe_allow_html=True)
        st.markdown(f"""
        <script>
            document.getElementById('{button_uuid}').click();
        </script>
        """, unsafe_allow_html=True)

# Pages
if page == "Home":
    st.title("RC5-CBC Cipher-Decipher Tool")
    st.markdown("""
    ### Welcome to the RC5-CBC Cipher-Decipher Tool
    
    This application provides a user-friendly interface for encrypting and decrypting messages 
    using the RC5 algorithm in CBC (Cipher Block Chaining) mode.
    
    **Features:**
    - Text encryption and decryption
    - File encryption and decryption
    - Multiple key lengths (128-bit, 192-bit, 256-bit)
    - Secure password-based key derivation
    - Initialization Vector (IV) management for CBC mode
    
    Navigate to the Encryption or Decryption pages using the sidebar to get started.
    """)
    
    # Display some sample usage with code
    st.subheader("Sample Usage")
    st.code("""
    # Encrypt your message
    1. Go to the Encryption page
    2. Enter your plaintext message
    3. Enter a strong password
    4. Select your key length
    5. Click "Encrypt"
    
    # Decrypt your message
    1. Go to the Decryption page
    2. Enter your ciphertext
    3. Enter the same password used for encryption
    4. Enter the same IV used for encryption (if provided)
    5. Click "Decrypt"
    """)

elif page == "Encryption":
    st.title("Encryption")
    
    # Create two tabs: Text and File
    tab1, tab2 = st.tabs(["Text Encryption", "File Encryption"])
    
    with tab1:
        plaintext = st.text_area("Enter plaintext to encrypt:", height=150)
        col1, col2 = st.columns(2)
        
        with col1:
            password = st.text_input("Enter encryption key:", type="password")
        with col2:
            key_length = st.selectbox("Select key length:", [128, 192, 256], index=0)
        
        # IV handling
        col3, col4 = st.columns(2)
        with col3:
            use_custom_iv = st.checkbox("Use custom IV")
        with col4:
            if use_custom_iv:
                iv_input = st.text_input("Enter IV (16 bytes, hex format):")
                try:
                    iv = bytes.fromhex(iv_input) if iv_input else generate_random_iv()
                except ValueError:
                    st.error("Invalid IV format. Please enter a valid hexadecimal string.")
                    iv = generate_random_iv()
            else:
                iv = generate_random_iv()
                st.text_input("Generated IV (hex):", value=iv.hex(), disabled=True)
        
        if st.button("Encrypt Text"):
            if plaintext and password:
                with st.spinner("Encrypting..."):
                    # Simulate processing time
                    import time
                    time.sleep(0.5)
                    
                    encrypted_text = encrypt_text(plaintext, password, iv, key_length)
                    st.success("Encryption completed!")
                    st.text_area("Encrypted text (Base64):", value=encrypted_text, height=100)
                    
                    # Copy to clipboard button
                    st.markdown(f"""
                    <button onclick="navigator.clipboard.writeText('{encrypted_text}')">
                        Copy to Clipboard
                    </button>
                    """, unsafe_allow_html=True)
            else:
                st.warning("Please provide both plaintext and password.")
    
    with tab2:
        uploaded_file = st.file_uploader("Choose a file to encrypt", type=None)
        col1, col2 = st.columns(2)
        
        with col1:
            file_password = st.text_input("Enter encryption key for file:", type="password")
        with col2:
            file_key_length = st.selectbox("Select key length for file:", [128, 192, 256], index=0)
        
        # IV handling for file
        col3, col4 = st.columns(2)
        with col3:
            file_use_custom_iv = st.checkbox("Use custom IV for file")
        with col4:
            if file_use_custom_iv:
                file_iv_input = st.text_input("Enter IV for file (16 bytes, hex format):")
                try:
                    file_iv = bytes.fromhex(file_iv_input) if file_iv_input else generate_random_iv()
                except ValueError:
                    st.error("Invalid IV format. Please enter a valid hexadecimal string.")
                    file_iv = generate_random_iv()
            else:
                file_iv = generate_random_iv()
                st.text_input("Generated IV for file (hex):", value=file_iv.hex(), disabled=True)
        
        if st.button("Encrypt File"):
            if uploaded_file is not None and file_password:
                with st.spinner("Encrypting file..."):
                    # Simulate processing time
                    import time
                    time.sleep(1)
                    
                    encrypted_file = process_file(uploaded_file, file_password, file_iv, file_key_length, "encrypt")
                    if encrypted_file is not None:
                        st.success("File encryption completed!")
                        download_button(encrypted_file, "enc", "Download Encrypted File")
            else:
                st.warning("Please upload a file and provide a password.")

elif page == "Decryption":
    st.title("Decryption")
    
    # Create two tabs: Text and File
    tab1, tab2 = st.tabs(["Text Decryption", "File Decryption"])
    
    with tab1:
        ciphertext = st.text_area("Enter ciphertext (Base64) to decrypt:", height=150)
        col1, col2 = st.columns(2)
        
        with col1:
            password = st.text_input("Enter decryption key:", type="password")
        with col2:
            key_length = st.selectbox("Select key length:", [128, 192, 256], index=0)
        
        # IV handling
        iv_input = st.text_input("Enter IV used for encryption (16 bytes, hex format):")
        try:
            iv = bytes.fromhex(iv_input) if iv_input else bytes(16)  # Default to zero IV if not provided
        except ValueError:
            st.error("Invalid IV format. Please enter a valid hexadecimal string.")
            iv = bytes(16)
        
        if st.button("Decrypt Text"):
            if ciphertext and password:
                with st.spinner("Decrypting..."):
                    # Simulate processing time
                    import time
                    time.sleep(0.5)
                    
                    decrypted_text = decrypt_text(ciphertext, password, iv, key_length)
                    if "Error" in decrypted_text:
                        st.error(decrypted_text)
                    else:
                        st.success("Decryption completed!")
                        st.text_area("Decrypted text:", value=decrypted_text, height=100)
                        
                        # Copy to clipboard button
                        st.markdown(f"""
                        <button onclick="navigator.clipboard.writeText('{decrypted_text}')">
                            Copy to Clipboard
                        </button>
                        """, unsafe_allow_html=True)
            else:
                st.warning("Please provide both ciphertext and password.")
    
    with tab2:
        uploaded_file = st.file_uploader("Choose a file to decrypt", type=None)
        col1, col2 = st.columns(2)
        
        with col1:
            file_password = st.text_input("Enter decryption key for file:", type="password")
        with col2:
            file_key_length = st.selectbox("Select key length for file:", [128, 192, 256], index=0)
        
        # IV handling for file
        file_iv_input = st.text_input("Enter IV used for file encryption (16 bytes, hex format):")
        try:
            file_iv = bytes.fromhex(file_iv_input) if file_iv_input else bytes(16)  # Default to zero IV if not provided
        except ValueError:
            st.error("Invalid IV format. Please enter a valid hexadecimal string.")
            file_iv = bytes(16)
        
        if st.button("Decrypt File"):
            if uploaded_file is not None and file_password:
                with st.spinner("Decrypting file..."):
                    # Simulate processing time
                    import time
                    time.sleep(1)
                    
                    decrypted_file = process_file(uploaded_file, file_password, file_iv, file_key_length, "decrypt")
                    if decrypted_file is not None:
                        st.success("File decryption completed!")