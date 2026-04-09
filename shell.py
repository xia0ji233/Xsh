import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def aes_encrypt_cbc(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return ciphertext

def send_encrypted_data(data, ip, port):
    key = b'xia0ji233_wants_'
    iv = b'a_girlfriend!!!!'

    encrypted_data = aes_encrypt_cbc(data, key, iv)
    print("Encrypted Data (hex):", encrypted_data.hex())

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(encrypted_data, (ip, port))

if __name__ == "__main__":
    plaintext = "xia0ji233"
    destination_ip = "172.29.183.66"
    destination_port = 23456

    send_encrypted_data(plaintext, destination_ip, destination_port)
