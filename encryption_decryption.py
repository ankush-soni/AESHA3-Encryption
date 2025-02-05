# encryption_decryption.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from aesha3_keygeneration import generate_keys
from SHA_3_1600_variableInput_Final import *

def encrypt_ecb(plaintext, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def decrypt_ecb(ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def pad(data):
    padding_length = 16 - len(data) % 16
    return data + bytes([padding_length] * padding_length)

def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

def encrypt_decrypt(input_string, keys):
    key = bytes.fromhex(keys["K1"])
    plaintext = pad(input_string.encode('utf-8'))
    encrypted = encrypt_ecb(plaintext, key)
    decrypted = unpad(decrypt_ecb(encrypted, key))
    return encrypted, decrypted.decode('utf-8')

def main():
    aes_version = int(input("Enter AES version (128, 192, 256): "))
    user_passphrase = input("Enter the passphrase: ")
    keccak = Keccak_1600_custom(576)
    
    # Generate keys and get the SHA3 output
    keys = generate_keys(keccak, user_passphrase, aes_version)
    sha3_output = keccak.get_hash_of(user_passphrase.encode('utf-8')).decode('utf-8')

    # Print the SHA3 output
    print("SHA3 Output (hex):", sha3_output.encode('utf-8').hex())

    # Print the keys in hexadecimal form
    print("Generated Keys in Hexadecimal:")
    for key_name, key_value in keys.items():
        print(f"{key_name}: {key_value}")
    
    # Convert keys to binary for encryption (already provided in hex format)
    binary_keys = {key: bin(int(value, 16))[2:].zfill(128) for key, value in keys.items()}
    print("Keys in Binary form are:", binary_keys)

    input_string = input("Enter a string to encrypt: ")
    encrypted, decrypted = encrypt_decrypt(input_string, keys)
    print("Encrypted string (hex):", encrypted.hex())
    print("Decrypted string:", decrypted)

if __name__ == "__main__":
    main()