# CRYPTFILE: File Encryption and Decryption Utility

## Overview

**CRYPTFILE** is a secure and user-friendly utility designed for encrypting and decrypting files using robust cryptographic algorithms such as **AES (Advanced Encryption Standard)** and **DES (Data Encryption Standard)**. The tool ensures data confidentiality by offering flexible decryption options via password or secret key and automatically logs all operations for complete traceability.

## Installation

1. Clone this repository:  
   ```bash
   git clone https://github.com/prath1432/CRYPTFILE.git
   ```
2. Navigate to the project directory:  
   ```bash
   cd CRYPTFILE
   ```
3. Install required dependencies:  
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the tool:  
   ```bash
   python cryptfile.py
   ```
2. Follow the prompts to:  
   - Encrypt or decrypt files.  
   - Choose encryption algorithms and provide passwords or secret keys.
     
## Key Features

1. **File Encryption and Decryption**  
   - Supports encryption and decryption of various file types, including documents and images.  
   - Offers flexibility by allowing decryption with either a secret key or password.

2. **Automatic Folder Creation**  
   - Each encryption creates a folder containing the encrypted file and a human-readable secret key for easy decryption.

3. **Encryption Algorithms**  
   - **AES**: Provides strong encryption with key sizes of 128, 192, or 256 bits.  
   - **DES**: Offers basic encryption with a 56-bit key for simplicity and compatibility.

4. **Decryption Options**  
   - **Password**: Users can set a password for added security.  
   - **Secret Key**: Allows decryption using a generated secret key stored securely in the folder.

5. **Log File Generation**  
   - Maintains detailed logs of all encryption and decryption operations, including file names, algorithms used, and timestamps, for security auditing.

## License

This project is licensed under the [MIT License](LICENSE).

## Contribution

Contributions are welcome! Feel free to fork this repository, create a feature branch, and submit a pull request.
