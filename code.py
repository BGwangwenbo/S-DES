import itertools
import time
import tkinter as tk
from tkinter import messagebox


# 以下为密钥扩展部分，将10bit密钥转换为两个8bit密钥--------------------------
def permute(key, permutation):
    """对密钥进行置换"""
    return [key[i - 1] for i in permutation]


def left_shift(bits, shifts):
    """对比特串进行左移"""
    return bits[shifts:] + bits[:shifts]


def key_expansion(key):
    P_10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    P_8 = [6, 3, 7, 4, 8, 5, 10, 9]
    Leftshift1 = 1
    Leftshift2 = 2

    permuted_key = permute(key, P_10)
    left_half = permuted_key[:5]
    right_half = permuted_key[5:]

    left_half1 = left_shift(left_half, Leftshift1)
    right_half1 = left_shift(right_half, Leftshift1)
    combined1 = left_half1 + right_half1
    key1 = permute(combined1, P_8)

    left_half2 = left_shift(left_half, Leftshift2)
    right_half2 = left_shift(right_half, Leftshift2)
    combined2 = left_half2 + right_half2
    key2 = permute(combined2, P_8)

    return key1, key2
# 以上为密钥扩展部分----------------------------


# 加密部分如下-------------------------------------
# 扩展置换
def expand(bits, EPbox):
    return [bits[i - 1] for i in EPbox]


# 轮函数F中的替换盒
def sbox_lookup(bits, sbox):
    row = (bits[0] << 1) + bits[3]
    col = (bits[1] << 1) + bits[2]
    return [int(x) for x in format(sbox[row][col], '02b')]


# 加密函数需要的轮函数F
def f_function(left, right, key):
    EPbox = (4, 1, 2, 3, 2, 3, 4, 1)
    expanded_right = expand(right, EPbox)
    xor_result = [b ^ k for b, k in zip(expanded_right, key)]

    Sbox1 = [(1, 0, 3, 2), (3, 2, 1, 0), (0, 2, 1, 3), (3, 1, 0, 2)]
    Sbox2 = [(0, 1, 2, 3), (2, 3, 1, 0), (3, 0, 1, 2), (2, 1, 0, 3)]
    SPbox = (2, 4, 3, 1)
    left_sbox = sbox_lookup(xor_result[:4], Sbox1)
    right_sbox = sbox_lookup(xor_result[4:], Sbox2)

    combined = left_sbox + right_sbox
    sp_left = permute(combined, SPbox)
    final_left = [b ^ k for b, k in zip(left, sp_left)]

    return final_left


# 加密函数输入明文（8bit），密钥1，密钥2，输出密文
def encrypt(data, key1, key2, mode):  # 0加密 1解密
    IP = (2, 6, 3, 1, 4, 8, 5, 7)
    IP_1 = (4, 1, 3, 5, 7, 2, 8, 6)
    
    permuted_data = permute(data, IP)
    left = permuted_data[:4]
    right = permuted_data[4:]

    # 第一次F函数
    left = f_function(left, right, [key1, key2][mode])
    # sw操作
    left, right = right, left
    # 第二次F函数
    left = f_function(left, right, [key2, key1][mode])

    final_data = left + right
    ciphertext = permute(final_data, IP_1)

    return ciphertext


# 字符串加密函数，将一串字符串加密（对每一个字符转换为8位ascii码后执行encrypt函数）后返回乱码
def encrypt_string(plaintext, key, mode):
    key_bits = [int(bit) for bit in key]
    key1, key2 = key_expansion(key_bits)

    encrypted_list = ""
    encrypted_bits_list = []
    
    for char in plaintext:
        ascii_val = ord(char)
        binary_val = [int(bit) for bit in format(ascii_val, '08b')]
        encrypted_bits = encrypt(binary_val, key1, key2, mode)
        
        encrypted_bits_list.append(encrypted_bits)
        # print(encrypted_bits_list)
        # 将二进制ascii序列转为字符串,例如（1，0，0，1，0，0，1，0）转为‘10010010’
        binary_string = ''.join(map(str, encrypted_bits))
        # 将二进制字符串转为ascii整数
        ascii_value = int(binary_string, 2)
        # 将ascii整数转换为对应的字符
        char = chr(ascii_value)
        encrypted_list += char
    
    return encrypted_list
# 加密部分如上--------------------------------------------


# 暴力破解--------------------------------------
def generate_keys():
    return [''.join(bits) for bits in itertools.product('01', repeat=10)]


def brute_force_decrypt(known_plaintext, known_ciphertext):
    key_list = ""
    for key in generate_keys():
        # 使用当前密钥加密明文
        encrypted_text = encrypt_string(known_plaintext, key, 0)

        # 比较加密结果
        if encrypted_text == known_ciphertext:
            key_string = ''.join(map(str,key))
            if key_list == '':
                key_list += key_string
            else:
                key_list += '或'+key_string
            print(key_list)
    if key_list != "":
        return key_list
    else:
        return 0  # 如果没有找到密钥


# GUI部分，接受用户输入字符串，与10bit密钥，然后调用上面加密函数
def handle_encrypt():
    plaintext = plaintext_entry.get()
    key = key_entry.get()

    if len(key) != 10 or not all(c in '01' for c in key):
        messagebox.showerror("输入错误", "请输入有效的10位二进制密钥")
        return

    encrypted_text = encrypt_string(plaintext, key, 0)
    ciphertext_entry.delete(0,tk.END)
    ciphertext_entry.insert(0, encrypted_text)


def handle_decrypt():
    ciphertext = ciphertext_entry.get()
    key = key_entry.get()

    if len(key) != 10 or not all(c in '01' for c in key):
        messagebox.showerror("输入错误", "请输入有效的10位二进制密钥")
        return

    encrypted_text = encrypt_string(ciphertext, key, 1)
    plaintext_entry.delete(0, tk.END)
    plaintext_entry.insert(0, encrypted_text)


def handle_force():
    time_start = time.time()
    known_plaintext = plaintext_entry.get()
    known_ciphertext = ciphertext_entry.get()
    key_text = brute_force_decrypt(known_plaintext, known_ciphertext)
    key_entry.delete(0, tk.END)
    key_entry.insert(0,key_text)
    time_end = time.time()
    time_use = time_end - time_start
    print(f'用时:{time_use}秒')


# 创建GUI窗口
window = tk.Tk()
window.title("字符串加密算法")

tk.Label(window, text="输入明文:").grid(row=0, column=0, padx=10, pady=10)
plaintext_entry = tk.Entry(window)
plaintext_entry.grid(row=0, column=1)

tk.Label(window, text="输入10位密钥 (二进制):").grid(row=1, column=0, padx=10, pady=10)
key_entry = tk.Entry(window)
key_entry.grid(row=1, column=1)

tk.Label(window, text="密文: ").grid(row=2, column=0, padx=10, pady=10)
ciphertext_entry = tk.Entry(window)
ciphertext_entry.grid(row=2, column=1)

encrypt_button = tk.Button(window, text="加密", command=handle_encrypt)
encrypt_button.grid(row=3, column=0, padx=10, pady=10)
ciphertext_button = tk.Button(window, text="解密", command=handle_decrypt)
ciphertext_button.grid(row=3, column=1, padx=10, pady=10)
force_ciphertext_button = tk.Button(window, text="暴力破解", command=handle_force)
force_ciphertext_button.grid(row=3, column=2, padx=10, pady=10)

window.mainloop()
