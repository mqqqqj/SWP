from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from hashlib import sha256
import hmac

debug = False

key1 = b'computer|Science'
key2 = b'nankaiuniversity'

aes1 = AES.new(key1, AES.MODE_ECB)  # 创建一个aes对象,用于第一层加密
def expand16B(data):
    if len(data) < 16:
        data += '0' * (16 - len(data))
    return data

def unexpand(data):
    assert len(data) == 16
    res = ''
    i = 0
    while i < 16 and data[i] != '0':
        res += data[i]
        i += 1
    return res


def Bxor(bytes_a, bytes_b):
    parts = []
    for b1, b2 in zip(bytes_a, bytes_b):
        parts.append(bytes([b1 ^ b2]))
    return b''.join(parts)

with open("data.txt", 'r') as data_file:
    word_list = data_file.readline().split()

n = len(word_list)   # 文件单词数
random_flow = []    # 伪随机流S
encrypt_1st = []    # 第一层加密结果
encrypt_2nd = []    # 第二层加密结果
encrypt_data = []   # 加密后的数据

if __name__ == '__main__':
    # 第一层加密
    for i in range(n):
        temp = expand16B(word_list[i])
        encrypt_1st_i = temp.encode()
        assert len(encrypt_1st_i) == 16
        encrypt_1st.append(aes1.encrypt(encrypt_1st_i))
        if debug:
            print("encrypt_1st_i:", encrypt_1st[0])

    # 第二层加密
    for i in range(n):
        random_flow_i = get_random_bytes(8) # 伪随机流S
        random_flow.append(random_flow_i)
        K_i = hmac.new(key2, encrypt_1st[i][:8], digestmod = sha256).digest()[:16]    # 伪随机函数f生成的密钥
        F_ks_i = hmac.new(K_i, random_flow_i, digestmod = sha256).digest()[:8]   #第二层的右半部分
        encrypt_2nd_i = random_flow_i + F_ks_i  # 左半部分和右半部分拼接
        encrypt_2nd.append(encrypt_2nd_i)
        if debug:
            print("random_flow_i:", random_flow_i)
            print("K_i:", K_i)
            print("F_ks_i:", F_ks_i)
            print("encrypt_2nd_i:", encrypt_2nd_i)

    # 生成加密数据
    for i in range(n):
        encrypt_data_i = Bxor(encrypt_1st[i], encrypt_2nd[i])
        encrypt_data.append(encrypt_data_i)
        if debug:
            print("encrypt_data_i:",encrypt_data_i)

    
    key_word = input("Input key word:")
    print(key_word)
    # trapdoor生成
    E = aes1.encrypt(expand16B(key_word).encode())
    if len(E) != 16:
        raise("Key word too long.")
    K = hmac.new(key2, E[:8], digestmod = sha256).digest()[:16]
    if debug:
        print("E:", E)
        print("K:", K)
    # 检索
    is_found = False
    for i in range(n):
        temp = Bxor(encrypt_data[i], E)
        S = temp[:8]
        T = temp[8:]
        F = hmac.new(K, S, digestmod = sha256).digest()[:8]
        if F == T:
            print("Find keyword.")
            is_found = True
            break
    # 解密
    if is_found:
        decrypt_file = []
        for i in range(n):
            C = encrypt_data[i]
            cl = C[:8]
            cr = C[8:]
            l = Bxor(random_flow[i], cl)
            ki = hmac.new(key2, l, digestmod = sha256).digest()[:16]
            f_ks = hmac.new(ki, random_flow[i], digestmod = sha256).digest()[:8]
            r = Bxor(f_ks, cr)
            e = l + r
            if debug:
                print(encrypt_1st[i], e)
            decrypt_data = aes1.decrypt(e).decode()
            decrypt_file.append(unexpand(decrypt_data))
        print(decrypt_file)







