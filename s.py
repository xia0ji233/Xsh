import socket
import threading
from requests import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
import base64

URL='https://ctf.bugku.com/pvp/submit.html'
token='AAA'
paramter={"flag":'',"token":token}
flagset=set()
flagset_lock=threading.Lock()

# RSA 私钥参数（p, q 用于解密）
RSA_P = 11679259364010918784758290882414518292115868673941449502313037545027907756756935918123248114754632221624675140284629665352060909313012883070233445519087679
RSA_Q = 12332831314816099901782197924342413459207219741782169598239430101893069594819378581787412110459570449341825355568960474510429329872630518746837943609585643
RSA_N = RSA_P * RSA_Q
RSA_E = 65537
RSA_D = pow(RSA_E, -1, (RSA_P - 1) * (RSA_Q - 1))

AES_KEY = b'xia0ji233_wants_'
AES_IV  = b'a_girlfriend!!!!'

def rsa_decrypt(data):
    """RSA 私钥解密 128 字节密文"""
    c = int.from_bytes(data, 'big')
    m = pow(c, RSA_D, RSA_N)
    # 还原为字节，去掉前导零
    m_bytes = m.to_bytes(128, 'big')
    return m_bytes

def decrypt_flag(data):
    """先 RSA 解密，再 AES-CBC 解密"""
    if len(data) == 128:
        # RSA + AES 双层加密
        aes_ct = rsa_decrypt(data)
        # 去掉前导零，AES 密文是 16 字节对齐的
        # 找到最后一个非零块的结尾
        aes_ct = aes_ct.lstrip(b'\x00')
        # 补齐到 16 的倍数
        pad_len = (16 - len(aes_ct) % 16) % 16
        aes_ct = b'\x00' * pad_len + aes_ct
    else:
        # 兼容旧的纯 AES 模式
        aes_ct = data

    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    flag = cipher.decrypt(aes_ct)
    return flag.replace(b'\0',b'').replace(b'\n',b'').decode('UTF-8')

def submitflag(flag):
    paramter['flag']=flag
    p=get(URL,params=paramter)
    print(f'submit flag:{flag}\nresult is:',end='')
    print(p.text)

def handle_flag(data, source):
    try:
        print(f'[-]recv {len(data)} bytes from {source}: {data[:32].hex()}...')
        flag = decrypt_flag(data)
    except Exception as e:
        print(f'[!]decrypt error: {e}')
        return
    if not flag:
        return
    with flagset_lock:
        if flag in flagset:
            return
        flagset.add(flag)
    print(f'[+]flag: {flag}')
    #submitflag(flag)

def udp_server():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_socket.bind(('', 9999))
    print(f"[*]UDP Listen: 9999")
    try:
        while True:
            data, addr = udp_socket.recvfrom(4096)
            handle_flag(data, addr)
    except KeyboardInterrupt:
        pass
    finally:
        udp_socket.close()

def tcp_server():
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_socket.bind(('', 9999))
    tcp_socket.listen(16)
    print(f"[*]TCP Listen: 9999")
    try:
        while True:
            conn, addr = tcp_socket.accept()
            data = b''
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            conn.close()
            if data:
                handle_flag(data, addr)
    except KeyboardInterrupt:
        pass
    finally:
        tcp_socket.close()

if __name__ == "__main__":
    # 验证密钥正确性
    assert RSA_N == RSA_P * RSA_Q
    assert pow(pow(12345, RSA_E, RSA_N), RSA_D, RSA_N) == 12345
    print(f"[*]RSA-1024 key OK (n={RSA_N:#x})")

    t_udp = threading.Thread(target=udp_server, daemon=True)
    t_tcp = threading.Thread(target=tcp_server, daemon=True)
    t_udp.start()
    t_tcp.start()
    print("[*]Press Ctrl+C to stop")
    try:
        t_udp.join()
        t_tcp.join()
    except KeyboardInterrupt:
        print("\n[*]Stopped")
