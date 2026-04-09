#!/usr/bin/env python3
"""
client.py - 主动连接 Xsh ServeFlagUDP 获取并解密 flag
用法:
    python client.py <target_ip> [port]           # 单次获取
    python client.py <target_ip> [port] --loop 5  # 每5秒循环获取
    python client.py targets.txt [port]            # 批量（文件每行一个IP）
"""
import socket
import sys
import time
import os
from Crypto.Cipher import AES

# ── RSA 私钥参数（与 s.py / rsa.h 一致）──────────────────
RSA_P = 11679259364010918784758290882414518292115868673941449502313037545027907756756935918123248114754632221624675140284629665352060909313012883070233445519087679
RSA_Q = 12332831314816099901782197924342413459207219741782169598239430101893069594819378581787412110459570449341825355568960474510429329872630518746837943609585643
RSA_N = RSA_P * RSA_Q
RSA_E = 65537
RSA_D = pow(RSA_E, -1, (RSA_P - 1) * (RSA_Q - 1))

AES_KEY = b'xia0ji233_wants_'
AES_IV  = b'a_girlfriend!!!!'

DEFAULT_PORT = 6666
TIMEOUT = 3


def rsa_decrypt(data: bytes) -> bytes:
    c = int.from_bytes(data, 'big')
    m = pow(c, RSA_D, RSA_N)
    return m.to_bytes(128, 'big')


def decrypt_flag(data: bytes) -> str:
    if len(data) != 128:
        raise ValueError(f"expected 128 bytes, got {len(data)}")
    aes_ct = rsa_decrypt(data)
    aes_ct = aes_ct.lstrip(b'\x00')
    pad_len = (16 - len(aes_ct) % 16) % 16
    aes_ct = b'\x00' * pad_len + aes_ct
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    plain = cipher.decrypt(aes_ct)
    return plain.replace(b'\x00', b'').replace(b'\n', b'').decode('utf-8')


def fetch_flag(ip: str, port: int) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.sendto(b'\x00', (ip, port))
        data, _ = sock.recvfrom(256)
        return decrypt_flag(data)
    finally:
        sock.close()


def main():
    if len(sys.argv) < 2:
        print(f"用法: python {sys.argv[0]} <ip|targets.txt> [port] [--loop seconds]")
        sys.exit(1)

    target = sys.argv[1]
    port = DEFAULT_PORT
    loop_interval = 0

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--loop':
            loop_interval = int(sys.argv[i + 1])
            i += 2
        else:
            port = int(sys.argv[i])
            i += 1

    # 判断是单个IP还是文件
    targets = []
    if os.path.isfile(target):
        with open(target, 'r') as f:
            for line in f:
                ip = line.strip()
                if ip:
                    targets.append(ip)
        print(f"[*] 从 {target} 加载 {len(targets)} 个目标")
    else:
        targets.append(target)

    seen = set()

    while True:
        for ip in targets:
            try:
                flag = fetch_flag(ip, port)
                tag = "NEW" if flag not in seen else "DUP"
                seen.add(flag)
                t = time.strftime("%H:%M:%S")
                print(f"[{t}][{tag}] {ip}:{port} -> {flag}")
            except socket.timeout:
                print(f"[!] {ip}:{port} 超时")
            except Exception as e:
                print(f"[!] {ip}:{port} 错误: {e}")

        if loop_interval <= 0:
            break
        time.sleep(loop_interval)


if __name__ == '__main__':
    main()
