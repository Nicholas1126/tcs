#!/usr/bin/env python3

import subprocess
import os
import sys

def run_helloworld():
    """运行 helloworld 二进制文件"""
    binary_path = "v1.0/helloworld"
    
    # 检查文件是否存在
    if not os.path.exists(binary_path):
        print(f"[-] 错误：找不到文件 {binary_path}")
        sys.exit(1)
    
    # 检查文件是否可执行
    if not os.access(binary_path, os.X_OK):
        print(f"[*] 添加执行权限...")
        os.chmod(binary_path, 0o755)
    
    print(f"[*] 正在运行: {binary_path}")
    print("=" * 50)
    
    try:
        # 运行二进制文件
        result = subprocess.run(
            [binary_path],
            capture_output=False,
            text=True
        )
        
        print("=" * 50)
        print(f"[*] 程序退出，返回码: {result.returncode}")
        
    except Exception as e:
        print(f"[-] 运行失败: {e}")
        sys.exit(1)

if __name__ == "__main__":
    run_helloworld()
