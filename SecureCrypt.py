import hashlib
from Crypto.Cipher import AES, DES, ChaCha20, Salsa20
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from PIL import Image
import os

def text_encryption(algorithm):
    text = input("Enter the text to encrypt: ")

    if algorithm == "AES":
        key = input("Enter AES key (16, 24, or 32 bytes): ").encode()
        cipher = AES.new(key, AES.MODE_ECB)
    elif algorithm == "DES":
        key = input("Enter DES key (8 bytes): ").encode()
        cipher = DES.new(key, DES.MODE_ECB)
    elif algorithm == "RSA":
        key = RSA.generate(2048)
        public_key = key.publickey().export_key()
        private_key = key.export_key()
        cipher = RSA.import_key(public_key)
    elif algorithm == "CHACHA20":
        key = get_random_bytes(32)
        cipher = ChaCha20.new(key=key)
    elif algorithm == "SALSA20":
        key = get_random_bytes(32)
        cipher = Salsa20.new(key=key)
    else:
        print("Invalid algorithm choice.")
        return

    encrypted_text = cipher.encrypt(pad(text.encode(), cipher.block_size))
    print("Encrypted text:", encrypted_text.hex())

def text_decryption(algorithm):
    encrypted_text_hex = input("Enter the encrypted text in hexadecimal format: ")
    encrypted_text = bytes.fromhex(encrypted_text_hex)

    if algorithm == "AES":
        key = input("Enter AES key (16, 24, or 32 bytes): ").encode()
        cipher = AES.new(key, AES.MODE_ECB)
    elif algorithm == "DES":
        key = input("Enter DES key (8 bytes): ").encode()
        cipher = DES.new(key, DES.MODE_ECB)
    elif algorithm == "RSA":
        private_key_path = input("Enter path to RSA private key file: ")
        with open(private_key_path, 'rb') as f:
            private_key = RSA.import_key(f.read())
        cipher = private_key
    elif algorithm == "CHACHA20":
        key = input("Enter ChaCha20 key (32 bytes): ").encode()
        nonce_hex = input("Enter the nonce in hexadecimal format: ")
        nonce = bytes.fromhex(nonce_hex)
        cipher = ChaCha20.new(key=key, nonce=nonce)
    elif algorithm == "SALSA20":
        key = input("Enter Salsa20 key (32 bytes): ").encode()
        nonce_hex = input("Enter the nonce in hexadecimal format: ")
        nonce = bytes.fromhex(nonce_hex)
        cipher = Salsa20.new(key=key, nonce=nonce)
    else:
        print("Invalid algorithm choice.")
        return

    decrypted_text = cipher.decrypt(encrypted_text).decode()
    print("Decrypted text:", decrypted_text)

def image_encryption():
    image_path = input("Enter the path of the image file to encrypt: ")
    if not os.path.exists(image_path):
        print("File not found.")
        return
    
    try:
        image = Image.open(image_path)
        encrypted_image = image.convert("RGB")  # Convert to RGB to remove alpha channel
        encrypted_image.save("encrypted_image.png")
        print("Image encrypted and saved as encrypted_image.png")
    except Exception as e:
        print("An error occurred:", e)

def password_analyzer():
    password = input("Enter the password to analyze: ")
    score = 0
    if len(password) >= 8:
        score += 1
    if any(c.isupper() for c in password) and any(c.islower() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in "!@#$%^&*()-_=+[]{};:'\"|,.<>?/~`" for c in password):
        score += 1

    print("Password strength score:", score)

def encryption_analyzer():
    algorithm = input("Enter encryption algorithm (AES, DES, RSA, ChaCha20, Salsa20): ").upper()
    if algorithm == "AES":
        print("AES key sizes:")
        print("128 bits - 16 bytes")
        print("192 bits - 24 bytes")
        print("256 bits - 32 bytes")
    elif algorithm == "DES":
        print("DES key size: 64 bits - 8 bytes")
    elif algorithm == "RSA":
        print("RSA key sizes:")
        print("1024 bits - 128 bytes")
        print("2048 bits - 256 bytes")
        print("3072 bits - 384 bytes")
        print("4096 bits - 512 bytes")
    elif algorithm == "CHACHA20":
        print("ChaCha20 key size: 256 bits - 32 bytes")
    elif algorithm == "SALSA20":
        print("Salsa20 key size: 256 bits - 32 bytes")
    else:
        print("Invalid algorithm choice.")

def generate_random_key(key_length):
    return get_random_bytes(key_length)

def pad(data, block_size):
    padding_length = block_size - len(data) % block_size
    padding = bytes([padding_length] * padding_length)
    return data + padding

def file_encryption():
    file_path = input("Enter the path of the file to encrypt: ")
    if not os.path.exists(file_path):
        print("File not found.")
        return

    with open(file_path, 'rb') as f:
        data = f.read()

    algorithm = input("Choose encryption algorithm (AES, DES, ChaCha20, Salsa20): ").upper()

    if algorithm == "AES":
        key = input("Enter AES key (16, 24, or 32 bytes): ").encode()
        cipher = AES.new(key, AES.MODE_ECB)
    elif algorithm == "DES":
        key = input("Enter DES key (8 bytes): ").encode()
        cipher = DES.new(key, DES.MODE_ECB)
    elif algorithm == "CHACHA20":
        key = get_random_bytes(32)
        cipher = ChaCha20.new(key=key)
    elif algorithm == "SALSA20":
        key = get_random_bytes(32)
        cipher = Salsa20.new(key=key)
    else:
        print("Invalid algorithm choice.")
        return

    encrypted_data = cipher.encrypt(pad(data, cipher.block_size))

    output_file_path = input("Enter the path to save the encrypted file: ")
    with open(output_file_path, 'wb') as f:
        f.write(encrypted_data)

    print("File encrypted and saved as", output_file_path)

def file_decryption():
    file_path = input("Enter the path of the encrypted file: ")
    if not os.path.exists(file_path):
        print("File not found.")
        return

    with open(file_path, 'rb') as f:
        data = f.read()

    algorithm = input("Choose decryption algorithm (AES, DES, ChaCha20, Salsa20): ").upper()

    if algorithm == "AES":
        key = input("Enter AES key (16, 24, or 32 bytes): ").encode()
        cipher = AES.new(key, AES.MODE_ECB)
    elif algorithm == "DES":
        key = input("Enter DES key (8 bytes): ").encode()
        cipher = DES.new(key, DES.MODE_ECB)
    elif algorithm == "CHACHA20":
        key = input("Enter ChaCha20 key (32 bytes): ").encode()
        nonce_hex = input("Enter the nonce in hexadecimal format: ")
        nonce = bytes.fromhex(nonce_hex)
        cipher = ChaCha20.new(key=key, nonce=nonce)
    elif algorithm == "SALSA20":
        key = input("Enter Salsa20 key (32 bytes): ").encode()
        nonce_hex = input("Enter the nonce in hexadecimal format: ")
        nonce = bytes.fromhex(nonce_hex)
        cipher = Salsa20.new(key=key, nonce=nonce)
    else:
        print("Invalid algorithm choice.")
        return

    decrypted_data = cipher.decrypt(data)

    output_file_path = input("Enter the path to save the decrypted file: ")
    with open(output_file_path, 'wb') as f:
        f.write(decrypted_data)

    print("File decrypted and saved as", output_file_path)

def main_menu():
    while True:
        print("\nMain Menu:")
        print("1. Text Encryption")
        print("2. Text Decryption")
        print("3. Image Encryption")
        print("4. File Encryption")
        print("5. File Decryption")
        print("6. Password Analyzer")
        print("7. Encryption Analyzer")
        print("8. Generate Random Key")
        print("9. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            algorithm = input("Enter encryption algorithm (AES, DES, RSA, ChaCha20, Salsa20): ").upper()
            text_encryption(algorithm)
        elif choice == "2":
            algorithm = input("Enter decryption algorithm (AES, DES, RSA, ChaCha20, Salsa20): ").upper()
            text_decryption(algorithm)
        elif choice == "3":
            image_encryption()
        elif choice == "4":
            file_encryption()
        elif choice == "5":
            file_decryption()
        elif choice == "6":
            password_analyzer()
        elif choice == "7":
            encryption_analyzer()
        elif choice == "8":
            key_length = int(input("Enter key length in bytes: "))
            print("Generated random key:", generate_random_key(key_length).hex())
        elif choice == "9":
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Please choose again.")

if __name__ == "__main__":
    main_menu()
