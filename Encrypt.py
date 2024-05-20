from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pyDes import des, CBC, PAD_PKCS5
import os
import uuid

def generate_random_key_hex():
    # Generate a random key of length 16 bytes for AES-128
    key_bytes = get_random_bytes(16)
    key_hex = key_bytes.hex()
    return key_hex

def generate_random_iv_hex():
    # Generate a random IV of length 16 bytes (AES block size)
    iv_bytes = get_random_bytes(16)
    iv_hex = iv_bytes.hex()
    return iv_hex

def generate_random_key():
    # Generate a random key of length 8 bytes
    return os.urandom(8)

def pad_data(data):
    # Pad the data using PKCS7 padding
    padding_length = 16 - (len(data) % 16)
    return data + bytes([padding_length] * padding_length)

def aes_encrypt(input_data, key_bytes):
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad_data(input_data))
    return cipher.iv, ciphertext

def blowfish_encrypt(input_data, key):
    cipher = des(key, mode=CBC, IV=b'\0\0\0\0\0\0\0\0', padmode=PAD_PKCS5)
    encrypted = cipher.encrypt(input_data)
    return encrypted

def des_encrypt(input_data, key):
    cipher = des(key, mode=2, padmode=PAD_PKCS5)
    encrypted = cipher.encrypt(input_data)
    return encrypted

def get_input():
    input_file = input("Enter the input file path: ")
    if not os.path.exists(input_file):
        print("Input file does not exist.")
        exit(1)
    return input_file

def get_method_order():
    method_order = []
    print("Enter encryption methods (AES, Blowfish, DES) in the desired order, separated by commas:")
    methods = input("Methods: ").strip().lower().split(',')
    for method in methods:
        if method.strip() not in {'aes', 'blowfish', 'des'}:
            print(f"Invalid encryption method '{method.strip()}'.")
            exit(1)
        method_order.append(method.strip())
    return method_order

def save_key(method, key):
    folder = "keys"
    if not os.path.exists(folder):
        os.makedirs(folder)
    with open(os.path.join(folder, f"key_{method}.txt"), 'w') as f:
        f.write(key.hex())

def main():
    input_file = get_input()
    method_order = get_method_order()

    input_data = None
    with open(input_file, 'rb') as f:
        input_data = f.read()

    for method in method_order:
        if method == 'aes':
            key_bytes = bytes.fromhex(generate_random_key_hex())
            iv, ciphertext = aes_encrypt(input_data, key_bytes)
            input_data = iv + ciphertext
            save_key(method, key_bytes)
        elif method == 'blowfish':
            key = generate_random_key()
            input_data = blowfish_encrypt(input_data, key)
            save_key(method, key)
        elif method == 'des':
            key = generate_random_key()
            input_data = des_encrypt(input_data, key)
            save_key(method, key)
    
    output_file = f"encrypted_combined_{str(uuid.uuid4())}.txt"

    with open(output_file, 'wb') as f:
        f.write(input_data)

    print("Combined Encryption complete. Output written to", output_file)

if _name_ == "_main_":
    main()
