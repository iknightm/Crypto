import streamlit as st
from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key()

def load_key():
    try:
        return open("secret.key", "rb").read()
    except FileNotFoundError:
        key = generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
        return key

def encrypt(text, fernet):
    return fernet.encrypt(text.encode()).decode()

def decrypt(text, fernet):
    try:
        return fernet.decrypt(text.encode()).decode()
    except Exception as e:
        return str(e)

def main():
    st.title('Text Encryption/Decryption App')
    st.write("Use this app to encrypt or decrypt your text.")

    text = st.text_area("Enter Text:")

    key = load_key()
    fernet = Fernet(key)

    action = st.radio("Select Action:", ('Encrypt', 'Decrypt'))

    if st.button("Submit"):
        if action == 'Encrypt':
            encrypted_text = encrypt(text, fernet)
            st.write('Encrypted Text:')
            st.code(encrypted_text)
        elif action == 'Decrypt':
            decrypted_text = decrypt(text, fernet)
            st.write('Decrypted Text:')
            st.code(decrypted_text)

if __name__ == '__main__':
    main()
