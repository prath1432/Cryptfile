import os
import stat
import hashlib
import logging
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.backends import default_backend


logging.basicConfig(
    filename='cryptofile.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def derive_key(password: str, salt: bytes, algorithm: str):
    logging.info(f"Deriving key using algorithm: {algorithm}")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32 if algorithm == 'AES' else 24,  
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def generate_hmac(key: bytes, data: bytes) -> bytes:
    """Generate HMAC for the given data using the provided key."""
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

def verify_hmac(key: bytes, data: bytes, expected_hmac: bytes):
    """Verify the HMAC of the given data against the expected value."""
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    h.verify(expected_hmac)



#Encrypt file function
def encrypt_file(file_path: str, password: str, algorithm: str = 'AES'):
    """Encrypt a file and save it as an encrypted file."""

    logging.info(f"Started encryption for file: {file_path}")

    if file_path.endswith('.enc'):
        logging.error(f"Error: The file '{file_path}' is already encrypted.")
        print(f"Error: The file '{file_path}' is already encrypted.")
        return

    folder_name = os.path.splitext(file_path)[0]
    encrypted_file_path = os.path.join(folder_name, f"{os.path.basename(file_path)}.enc")

    # Ensure the variable is defined before the logging statement
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()
    except Exception as e:
        logging.error(f"Error reading file: {e}")
        print(f"Error reading file: {e}")
        return

    # Encryption process...
    try:
        salt = os.urandom(16)
        key = derive_key(password, salt, algorithm)

        if algorithm == 'AES':
            iv = os.urandom(16)  # 16 bytes for AES
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        elif algorithm == 'DES':
            iv = os.urandom(8)  # 8 bytes for DES
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        else:
            raise ValueError("Unsupported algorithm. Choose 'AES' or 'DES'.")

        padder = padding.PKCS7(cipher.algorithm.block_size).padder()
        padded_data = padder.update(file_data) + padder.finalize()

        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        hmac_value = generate_hmac(key, encrypted_data)

        original_extension = os.path.splitext(file_path)[1].encode('utf-8')

        encrypted_data = (
            algorithm.encode('utf-8') + b'|' +
            salt + iv +
            len(original_extension).to_bytes(1, 'big') +
            original_extension +
            encrypted_data +
            hmac_value
        )

        os.makedirs(folder_name, exist_ok=True)

        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)

        secret_key = urlsafe_b64encode(key).decode('utf-8')
        secret_key_path = os.path.join(folder_name, "secret.key")

        with open(secret_key_path, 'w') as secret_file:
            secret_file.write(secret_key)

        os.chmod(encrypted_file_path, stat.S_IREAD)
        os.chmod(secret_key_path, stat.S_IREAD)
        print(f"\nFile successfully encrypted and saved as: {encrypted_file_path} 😊")
        print(f"Secret key saved as: {secret_key_path}")
        print("Both files have been set to read-only mode.\n")
        
        logging.info(f"File successfully encrypted: {encrypted_file_path}")

    except PermissionError:
        logging.error(f"Permission error: Unable to write to file '{encrypted_file_path}'. Check file permissions.")
        print(f"Permission error: Unable to write to file '{encrypted_file_path}'. Check file permissions.")
    except Exception as e:
        logging.error(f"Error during encryption: {e}")
        print(f"Error during encryption: {e}")



#decrypt file function
def decrypt_file(encrypted_file_path: str, password: str = None, secret_key: str = None, algorithm: str = 'AES'):
    """Decrypt an encrypted file using either a password or a secret key."""
    if not encrypted_file_path.endswith('.enc'):
        print(f"Error: The file '{encrypted_file_path}' is not encrypted.")
        return

    # Read the encrypted file content
    with open(encrypted_file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()

    # Extract metadata
    file_algorithm, encrypted_data = encrypted_data.split(b'|', 1)
    file_algorithm = file_algorithm.decode('utf-8')

    if file_algorithm != algorithm:
        print(f"Decryption failed: Encryption algorithm ({file_algorithm}) does not match the chosen decryption algorithm ({algorithm}).")
        return

    # Extract components from encrypted data
    salt = encrypted_data[:16]
    iv_length = 16 if algorithm == 'AES' else 8
    iv = encrypted_data[16:16 + iv_length]
    ext_length = encrypted_data[16 + iv_length]
    original_extension = encrypted_data[17 + iv_length:17 + iv_length + ext_length].decode('utf-8')
    hmac_value = encrypted_data[-32:]
    actual_encrypted_data = encrypted_data[17 + iv_length + ext_length:-32]

    # Derive or decode the key
    if password:
        key = derive_key(password, salt, algorithm)
    elif secret_key:
        try:
            key = urlsafe_b64decode(secret_key)
        except Exception as e:
            print(f"Error decoding secret key: {e}")
            return
    else:
        print("Decryption failed: No password or secret key provided.")
        return

    # Verify the HMAC
    try:
        verify_hmac(key, actual_encrypted_data, hmac_value)
    except Exception:
        print("Decryption failed: The file has been tampered with or the key is incorrect.")
        return

    # Initialize cipher and decrypt data
    if algorithm == 'AES':
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    elif algorithm == 'DES':
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    else:
        raise ValueError("Unsupported algorithm. Choose 'AES' or 'DES'.")

    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(actual_encrypted_data) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(cipher.algorithm.block_size).unpadder()
    try:
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    except ValueError:
        print("Decryption failed: Invalid padding. The key or password may be incorrect.")
        return

    # Write decrypted data to a new file
    decrypted_file_path = os.path.join(
        os.path.dirname(encrypted_file_path),
        f"{os.path.splitext(os.path.basename(encrypted_file_path))[0]}{original_extension}"
    )
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

    print(f"\nFile successfully decrypted and saved as: {decrypted_file_path} 😊")
    print("Enjoy your decrypted file! 👋\n")

    logging.info(f"Started decryption for file: {encrypted_file_path}")

    # Rest of the function...

    logging.info(f"File successfully decrypted: {decrypted_file_path}")

#welcome message function
def print_welcome_message():
    """Print the welcome message for the CryptoFile utility."""
    welcome_message = """
    ==========================================
               Welcome to CryptoFile
    ==========================================
    A command-line tool for encrypting and decrypting files
    using AES or DES algorithms.
    """
    print(welcome_message)

def get_non_empty_input(prompt: str) -> str:
    """Prompt the user for input and ensure it is not empty."""
    while True:
        user_input = input(prompt).strip()
        if user_input:
            return user_input
        else:
            print("Error: This field cannot be empty. Please enter the required data.")

def main():
    print_welcome_message()

    while True:
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Exit")
        choice = get_non_empty_input("Enter your choice (1/2/3): ").strip()
        print()  # Print an extra line for better readability

        if choice == '1':
            file_path = get_non_empty_input("Enter the path of the file to encrypt: ").strip().strip('"')
            password = get_non_empty_input("Enter the encryption password: ")
            algorithm = get_non_empty_input("Choose the encryption algorithm (AES/DES): ").upper()
            if algorithm in ['AES', 'DES']:
                encrypt_file(file_path, password, algorithm)
            else:
                print("Invalid algorithm choice. Please choose AES or DES.")
        elif choice == '2':
            file_path = get_non_empty_input("Enter the path of the file to decrypt: ").strip().strip('"')
            method = get_non_empty_input("Do you want to decrypt using password or secret key? (Enter 'password' or 'secret'): ").strip().lower()
            algorithm = get_non_empty_input("Choose the decryption algorithm (AES/DES): ").upper()
            if method == 'password':
                password = get_non_empty_input("Enter the decryption password: ")
                decrypt_file(file_path, password=password, algorithm=algorithm)
            elif method == 'secret':
                secret_key_path = get_non_empty_input("Enter the path to the secret key file: ").strip().strip('"')
                try:
                    with open(secret_key_path, 'r') as secret_file:
                        secret_key = secret_file.read().strip()
                    decrypt_file(file_path, secret_key=secret_key, algorithm=algorithm)
                except FileNotFoundError:
                    print("Error: Secret key file not found.")
            else:
                print("Invalid method choice. Please enter 'password' or 'secret'.")
        elif choice == '3':
            print("Exiting CryptoFile Utility. Goodbye! 👋")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")
            print()  

if __name__ == "__main__":
    main()
