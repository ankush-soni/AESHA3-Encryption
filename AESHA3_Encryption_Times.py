import time
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from aesha3_keygeneration import generate_keys
from SHA_3_1600_variableInput_Final import Keccak_1600_custom

# Constants
PASSPHRASE = "The quick brown fox jumps over the lazy dog"
AES_VERSIONS = [128, 192, 256]
TEXT_SIZES = [1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216]  # From 1KB to 16MB

def pad(data):
    padding_length = 16 - len(data) % 16
    return data + bytes([padding_length] * padding_length)

def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

def encrypt_ecb(plaintext, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def encrypt_decrypt(input_string, key):
    # Prepare the plaintext
    plaintext = pad(input_string)
    # Encrypt
    encrypted = encrypt_ecb(plaintext, key)
    return encrypted

def run_encryption_tests(aes_version, key, text_size):
    test_data = os.urandom(text_size)  # Generate random text of 'text_size'
    total_time = 0

    for _ in range(10000):  # Run 100 iterations
        start_time = time.time()
        encrypted = encrypt_decrypt(test_data, key)
        end_time = time.time()
        total_time += (end_time - start_time) * 1000  # Convert time to milliseconds
    
    average_time = total_time / 10000
    return average_time

def main():
    # Initialize Keccak for SHA3-based key generation
    keccak = Keccak_1600_custom(576)

    for aes_version in AES_VERSIONS:
        # Generate keys using the fixed passphrase
        keys = generate_keys(keccak, PASSPHRASE, aes_version)
        key_hex = keys["K1"]  # Use the first key for encryption
        key = bytes.fromhex(key_hex)

        print(f"Testing AES-{aes_version}...")

        for size in TEXT_SIZES:
            avg_time = run_encryption_tests(aes_version, key, size)
            print(f"AESHA3-{aes_version}, Size: {size // 1024} KB, Average Encryption Time: {avg_time*1000:} ms")

if __name__ == "__main__":
    main()
