from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pyDes import des, CBC, PAD_PKCS5
import os

def aes_decrypt(input_data, key_bytes, iv):
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(input_data)
    return plaintext

def blowfish_decrypt(input_data, key):
    cipher = des(key, mode=CBC, IV=b'\0\0\0\0\0\0\0\0', padmode=PAD_PKCS5)
    decrypted = cipher.decrypt(input_data)
    return decrypted

def des_decrypt(input_data, key):
    cipher = des(key, mode=2, padmode=PAD_PKCS5)
    decrypted = cipher.decrypt(input_data)
    return decrypted

def get_input():
    input_file = input("Enter the input file path: ")
    if not os.path.exists(input_file):
        print("Input file does not exist.")
        exit(1)
    return input_file

def get_method_order():
    method_order = []
    print("Enter decryption methods (AES, Blowfish, DES) in the desired order, separated by commas:")
    methods = input("Methods: ").strip().lower().split(',')
    for method in methods:
        if method.strip() not in {'aes', 'blowfish', 'des'}:
            print(f"Invalid decryption method '{method.strip()}'.")
            exit(1)
        method_order.append(method.strip())
    return method_order

def get_keys_folder():
    keys_folder = input("Enter the folder path where all the keys are stored: ")
    if not os.path.exists(keys_folder):
        print("Keys folder does not exist.")
        exit(1)
    return keys_folder

def get_key(method, keys_folder):
    key_file = os.path.join(keys_folder, f"key_{method}.txt")
    if not os.path.exists(key_file):
        print(f"Key file for {method.upper()} does not exist.")
        exit(1)
    with open(key_file, 'r') as f:
        key_hex = f.read().strip()
        key_bytes = bytes.fromhex(key_hex)
    return key_bytes

def main():
    input_file = get_input()
    method_order = get_method_order()
    method_order.reverse()
    keys_folder = get_keys_folder()

    input_data = None
    with open(input_file, 'rb') as f:
        input_data = f.read()

    for method in method_order:
        if method == 'aes':
            iv = input_data[:16]
            input_data = aes_decrypt(input_data[16:], get_key(method, keys_folder), iv)
        elif method == 'blowfish':
            input_data = blowfish_decrypt(input_data, get_key(method, keys_folder))
        elif method == 'des':
            input_data = des_decrypt(input_data, get_key(method, keys_folder))
    
    output_file = "decrypted_combined.txt"

    with open(output_file, 'wb') as f:
        f.write(input_data)

    print("Combined Decryption complete. Output written to", output_file)

if _name_ == "_main_":
    main()
