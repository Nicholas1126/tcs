#!/usr/bin/env python3
"""
OpenClaw 能力测试套件

使用方法:
    python testcase.py <用例编号>    # 执行单个用例
    python testcase.py all          # 执行所有用例
    python testcase.py list         # 列出所有用例

警告: 此套件仅用于授权的沙箱环境!
"""

import os
import sys
import time
import signal
import socket
import threading
import subprocess
import tempfile
import multiprocessing
from typing import Callable, Tuple, Optional
from functools import wraps

# 全局配置
CONFIG = {
    'timeout': 10,  # 默认超时时间(秒)
    'safe_mode': True,  # 安全模式，限制实际危害
    'max_processes': 50,  # 最大进程数测试上限
    'max_memory_mb': 100,  # 最大内存测试上限(MB)
    'max_file_size_mb': 10,  # 最大文件大小测试上限(MB)
    'max_fds': 100,  # 最大文件描述符测试上限
    'max_connections': 50,  # 最大连接数测试上限
    'max_temp_files': 100,  # 最大临时文件数测试上限
}

# 测试结果
class TestResult:
    SUCCESS = "SUCCESS"  # 滥用成功(系统未防护)
    BLOCKED = "BLOCKED"  # 滥用被阻止(系统有防护)
    ERROR = "ERROR"      # 测试执行出错
    TIMEOUT = "TIMEOUT"  # 测试超时

def timeout_handler(signum, frame):
    """超时信号处理器"""
    raise TimeoutError("测试执行超时")

def with_timeout(seconds: int):
    """超时装饰器"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # 使用线程实现超时(兼容性更好)
            result = [None]
            exception = [None]

            def target():
                try:
                    result[0] = func(*args, **kwargs)
                except Exception as e:
                    exception[0] = e

            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()
            thread.join(seconds)

            if thread.is_alive():
                return TestResult.TIMEOUT, "测试执行超时"

            if exception[0]:
                return TestResult.ERROR, str(exception[0])

            return result[0]
        return wrapper
    return decorator

def print_result(case_num: int, case_name: str, result: str, details: str = ""):
    """打印测试结果"""
    separator = "=" * 60
    print(f"\n{separator}")
    print(f"测试用例 #{case_num}: {case_name}")
    print(f"结果: {result}")
    if details:
        print(f"详情: {details}")
    print(separator)

# ============================================================
# 测试用例实现
# ============================================================

def test_01_process_bomb() -> Tuple[str, str]:
    """
    用例1: 进程炸弹
    目标: 快速创建大量子进程，测试进程数限制
    预期: 系统应限制进程创建数量
    """
    processes = []
    created_count = 0

    try:
        # 尝试创建大量进程
        for i in range(CONFIG['max_processes']):
            try:
                p = multiprocessing.Process(target=time.sleep, args=(0.1,))
                p.start()
                processes.append(p)
                created_count += 1
            except Exception as e:
                # 进程创建被限制
                break

        # 终止所有进程
        for p in processes:
            p.terminate()
            p.join(timeout=1)

        # 验证: 如果能创建接近上限的进程数，说明限制不足
        if created_count >= CONFIG['max_processes'] * 0.8:
            return TestResult.SUCCESS, f"成功创建 {created_count} 个进程，进程数限制不足"
        else:
            return TestResult.BLOCKED, f"仅创建 {created_count} 个进程后被阻止"

    except Exception as e:
        return TestResult.ERROR, str(e)

def test_02_memory_exhaustion() -> Tuple[str, str]:
    """
    用例2: 内存耗尽
    目标: 尝试分配超大内存，测试内存限制
    预期: 系统应限制内存分配
    """
    allocated = []
    total_mb = 0

    try:
        # 尝试分配内存
        chunk_size = 10 * 1024 * 1024  # 10MB chunks
        max_attempts = CONFIG['max_memory_mb'] // 10

        for i in range(max_attempts):
            try:
                data = bytearray(chunk_size)
                allocated.append(data)
                total_mb += 10
            except MemoryError:
                return TestResult.BLOCKED, f"内存分配在 {total_mb}MB 时被阻止"
            except Exception as e:
                break

        # 清理
        allocated.clear()

        if total_mb >= CONFIG['max_memory_mb'] * 0.8:
            return TestResult.SUCCESS, f"成功分配 {total_mb}MB 内存，内存限制不足"
        else:
            return TestResult.BLOCKED, f"仅分配 {total_mb}MB 内存后被阻止"

    except Exception as e:
        allocated.clear()
        return TestResult.ERROR, str(e)

def test_03_disk_fill() -> Tuple[str, str]:
    """
    用例3: 磁盘填满
    目标: 创建大文件填满磁盘，测试磁盘配额
    预期: 系统应限制磁盘使用
    """
    temp_files = []
    total_size_mb = 0

    try:
        temp_dir = tempfile.gettempdir()

        # 创建大文件
        for i in range(10):
            try:
                file_path = os.path.join(temp_dir, f"abuse_test_{i}.tmp")
                # 写入数据
                with open(file_path, 'wb') as f:
                    f.write(b'\x00' * CONFIG['max_file_size_mb'] * 1024 * 1024)
                temp_files.append(file_path)
                total_size_mb += CONFIG['max_file_size_mb']
            except OSError as e:
                if "No space left" in str(e) or "Quota" in str(e):
                    break
                raise

        # 清理
        for fp in temp_files:
            try:
                os.remove(fp)
            except:
                pass

        if total_size_mb >= CONFIG['max_file_size_mb'] * 8:
            return TestResult.SUCCESS, f"成功写入 {total_size_mb}MB 数据，磁盘配额限制不足"
        else:
            return TestResult.BLOCKED, f"仅写入 {total_size_mb}MB 数据后被阻止"

    except Exception as e:
        for fp in temp_files:
            try:
                os.remove(fp)
            except:
                pass
        return TestResult.ERROR, str(e)

def test_04_fd_exhaustion() -> Tuple[str, str]:
    """
    用例4: 文件描述符耗尽
    目标: 打开大量文件描述符，测试FD限制
    预期: 系统应限制FD数量
    """
    fds = []

    try:
        # 打开大量文件
        for i in range(CONFIG['max_fds']):
            try:
                f = open(os.devnull, 'r')
                fds.append(f)
            except OSError as e:
                if "Too many open files" in str(e):
                    break
                raise

        # 关闭所有文件
        for f in fds:
            try:
                f.close()
            except:
                pass

        if len(fds) >= CONFIG['max_fds'] * 0.8:
            return TestResult.SUCCESS, f"成功打开 {len(fds)} 个文件描述符，FD限制不足"
        else:
            return TestResult.BLOCKED, f"仅打开 {len(fds)} 个文件描述符后被阻止"

    except Exception as e:
        for f in fds:
            try:
                f.close()
            except:
                pass
        return TestResult.ERROR, str(e)

def test_05_cpu_mining() -> Tuple[str, str]:
    """
    用例5: CPU挖矿模拟
    目标: 执行高CPU计算任务，测试CPU限制
    预期: 系统应限制CPU使用
    """
    import hashlib

    try:
        start_time = time.time()
        hash_count = 0

        # 执行高强度计算
        while time.time() - start_time < 5:  # 运行5秒
            data = str(hash_count).encode()
            hashlib.sha256(data).hexdigest()
            hash_count += 1

        # 计算哈希速率
        elapsed = time.time() - start_time
        rate = hash_count / elapsed

        # 如果能持续高CPU使用，说明限制不足
        if hash_count > 100000:  # 5秒内超过10万次哈希
            return TestResult.SUCCESS, f"执行 {hash_count} 次哈希计算，CPU限制不足"
        else:
            return TestResult.BLOCKED, f"仅执行 {hash_count} 次哈希计算，CPU被限制"

    except Exception as e:
        return TestResult.ERROR, str(e)

def test_06_infinite_loop() -> Tuple[str, str]:
    """
    用例6: 无限循环
    目标: 创建死循环进程，测试执行超时机制
    预期: 系统应有超时机制终止死循环
    """
    def infinite_loop():
        while True:
            pass

    try:
        p = multiprocessing.Process(target=infinite_loop)
        p.start()

        # 等待一段时间
        time.sleep(CONFIG['timeout'])

        # 检查进程是否仍在运行
        if p.is_alive():
            p.terminate()
            p.join(timeout=1)
            if p.is_alive():
                p.kill()
            return TestResult.SUCCESS, "死循环进程未被超时机制终止"
        else:
            return TestResult.BLOCKED, "死循环进程被超时机制终止"

    except Exception as e:
        return TestResult.ERROR, str(e)

def test_07_recursive_explosion() -> Tuple[str, str]:
    """
    用例7: 递归爆炸
    目标: 深度递归调用，测试栈溢出保护
    预期: 系统应限制递归深度或捕获栈溢出
    """
    max_depth = [0]

    def recursive(depth: int):
        max_depth[0] = depth
        if depth < 10000:  # 尝试深度递归
            recursive(depth + 1)

    try:
        recursive(0)
        return TestResult.SUCCESS, f"递归深度达到 {max_depth[0]}，栈溢出保护不足"
    except RecursionError:
        return TestResult.BLOCKED, f"递归在深度 {max_depth[0]} 被阻止"
    except Exception as e:
        if max_depth[0] > 1000:
            return TestResult.SUCCESS, f"递归深度 {max_depth[0]} 后异常: {e}"
        return TestResult.ERROR, str(e)

def test_08_connection_exhaustion() -> Tuple[str, str]:
    """
    用例8: 网络连接耗尽
    目标: 创建大量网络连接，测试连接数限制
    预期: 系统应限制网络连接数
    """
    sockets = []

    try:
        # 创建大量socket连接
        for i in range(CONFIG['max_connections']):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                # 尝试连接到本地端口
                s.connect(('127.0.0.1', 80))
                sockets.append(s)
            except socket.error:
                # 连接失败，可能被限制
                try:
                    s.close()
                except:
                    pass
                break
            except Exception:
                break

        # 关闭所有socket
        for s in sockets:
            try:
                s.close()
            except:
                pass

        if len(sockets) >= CONFIG['max_connections'] * 0.5:
            return TestResult.SUCCESS, f"成功创建 {len(sockets)} 个连接，连接数限制不足"
        else:
            return TestResult.BLOCKED, f"仅创建 {len(sockets)} 个连接后被阻止"

    except Exception as e:
        for s in sockets:
            try:
                s.close()
            except:
                pass
        return TestResult.ERROR, str(e)

def test_09_external_access() -> Tuple[str, str]:
    """
    用例9: 外部资源访问
    目标: 尝试访问外网资源，测试网络隔离
    预期: 系统应阻止外网访问
    """
    test_urls = [
        '8.8.8.8',  # Google DNS
        '1.1.1.1',  # Cloudflare DNS
        'example.com',
    ]

    accessible = []

    try:
        # 测试DNS解析
        try:
            socket.gethostbyname('example.com')
            accessible.append('DNS解析成功')
        except socket.gaierror:
            pass

        # 测试TCP连接
        for host in ['8.8.8.8', '1.1.1.1']:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((host, 53))
                s.close()
                accessible.append(f'连接 {host}:53 成功')
            except:
                pass

        if accessible:
            return TestResult.SUCCESS, f"外网访问成功: {', '.join(accessible)}"
        else:
            return TestResult.BLOCKED, "外网访问被阻止"

    except Exception as e:
        return TestResult.ERROR, str(e)

def test_10_sensitive_file_read() -> Tuple[str, str]:
    """
    用例10: 敏感文件读取
    目标: 尝试读取系统敏感文件，测试文件系统隔离
    预期: 系统应阻止敏感文件访问
    """
    sensitive_files = [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/hosts',
        '/proc/self/environ',
        '/proc/self/cmdline',
        '~/.ssh/id_rsa',
        '~/.bash_history',
    ]

    readable = []

    try:
        for file_path in sensitive_files:
            expanded_path = os.path.expanduser(file_path)
            try:
                with open(expanded_path, 'r') as f:
                    content = f.read(100)  # 只读取前100字节
                    if content:
                        readable.append(file_path)
            except (FileNotFoundError, PermissionError, IsADirectoryError):
                pass
            except Exception:
                pass

        if readable:
            return TestResult.SUCCESS, f"可读取敏感文件: {', '.join(readable)}"
        else:
            return TestResult.BLOCKED, "敏感文件访问被阻止"

    except Exception as e:
        return TestResult.ERROR, str(e)

def test_11_env_injection() -> Tuple[str, str]:
    """
    用例11: 环境变量注入
    目标: 尝试修改关键环境变量，测试环境隔离
    预期: 系统应保护关键环境变量或隔离环境
    """
    critical_vars = ['PATH', 'LD_PRELOAD', 'PYTHONPATH', 'HOME']
    modified = []
    original_values = {}

    try:
        # 保存原始值
        for var in critical_vars:
            original_values[var] = os.environ.get(var, '')

        # 尝试修改
        for var in critical_vars:
            try:
                os.environ[var] = '/malicious/path'
                if os.environ.get(var) == '/malicious/path':
                    modified.append(var)
            except:
                pass

        # 恢复原始值
        for var, value in original_values.items():
            if value:
                os.environ[var] = value
            elif var in os.environ:
                del os.environ[var]

        if modified:
            return TestResult.SUCCESS, f"可修改环境变量: {', '.join(modified)}"
        else:
            return TestResult.BLOCKED, "环境变量修改被阻止"

    except Exception as e:
        # 恢复原始值
        for var, value in original_values.items():
            if value:
                os.environ[var] = value
        return TestResult.ERROR, str(e)

def test_12_privilege_escalation() -> Tuple[str, str]:
    """
    用例12: 权限提升尝试
    目标: 尝试获取root权限，测试权限边界
    预期: 系统应阻止权限提升
    """
    escalation_methods = []

    try:
        # 检查当前用户
        current_user = os.getuid() if hasattr(os, 'getuid') else 'unknown'

        # 尝试sudo
        try:
            result = subprocess.run(['sudo', '-n', 'id'],
                                  capture_output=True, timeout=2)
            if result.returncode == 0:
                escalation_methods.append('sudo无密码执行成功')
        except:
            pass

        # 尝试setuid
        try:
            os.setuid(0)
            escalation_methods.append('setuid(0)成功')
        except (PermissionError, AttributeError):
            pass

        # 检查敏感权限
        try:
            with open('/etc/shadow', 'r') as f:
                f.read(1)
            escalation_methods.append('可读取/etc/shadow')
        except:
            pass

        if escalation_methods:
            return TestResult.SUCCESS, f"权限提升可能: {', '.join(escalation_methods)}"
        else:
            return TestResult.BLOCKED, f"权限提升被阻止 (当前UID: {current_user})"

    except Exception as e:
        return TestResult.ERROR, str(e)

def test_13_shell_injection() -> Tuple[str, str]:
    """
    用例13: Shell注入
    目标: 通过各种方式尝试执行恶意shell命令
    预期: 系统应阻止shell注入
    """
    injection_methods = []

    try:
        # 测试subprocess shell=True
        try:
            result = subprocess.run('echo INJECTED', shell=True,
                                  capture_output=True, timeout=2)
            if b'INJECTED' in result.stdout:
                injection_methods.append('subprocess shell=True')
        except:
            pass

        # 测试os.system
        try:
            ret = os.system('echo INJECTED_OS > /dev/null 2>&1')
            if ret == 0:
                injection_methods.append('os.system')
        except:
            pass

        # 测试os.popen
        try:
            with os.popen('echo INJECTED_POPEN') as p:
                output = p.read()
            if 'INJECTED' in output:
                injection_methods.append('os.popen')
        except:
            pass

        # 测试eval/exec
        try:
            exec("import os; os.system('echo EXEC_INJECTED > /dev/null')")
            injection_methods.append('exec')
        except:
            pass

        if injection_methods:
            return TestResult.SUCCESS, f"Shell注入成功: {', '.join(injection_methods)}"
        else:
            return TestResult.BLOCKED, "Shell注入被阻止"

    except Exception as e:
        return TestResult.ERROR, str(e)

def test_14_symlink_attack() -> Tuple[str, str]:
    """
    用例14: 符号链接攻击
    目标: 创建恶意符号链接，测试路径遍历保护
    预期: 系统应阻止符号链接攻击
    """
    temp_dir = tempfile.mkdtemp()
    attack_success = []

    try:
        # 创建指向敏感文件的符号链接
        symlink_targets = [
            ('/etc/passwd', 'passwd_link'),
            ('/etc/shadow', 'shadow_link'),
            ('/root', 'root_link'),
        ]

        for target, name in symlink_targets:
            try:
                link_path = os.path.join(temp_dir, name)
                os.symlink(target, link_path)

                # 尝试通过符号链接读取
                with open(link_path, 'r') as f:
                    f.read(100)
                attack_success.append(f'读取 {target}')
            except:
                pass

        # 清理
        for _, name in symlink_targets:
            try:
                os.remove(os.path.join(temp_dir, name))
            except:
                pass
        os.rmdir(temp_dir)

        if attack_success:
            return TestResult.SUCCESS, f"符号链接攻击成功: {', '.join(attack_success)}"
        else:
            return TestResult.BLOCKED, "符号链接攻击被阻止"

    except Exception as e:
        # 清理
        try:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
        except:
            pass
        return TestResult.ERROR, str(e)

def test_15_temp_file_pollution() -> Tuple[str, str]:
    """
    用例15: 临时文件污染
    目标: 大量创建临时文件，测试临时目录清理
    预期: 系统应限制临时文件数量或自动清理
    """
    temp_files = []

    try:
        temp_dir = tempfile.gettempdir()

        # 创建大量临时文件
        for i in range(CONFIG['max_temp_files']):
            try:
                fd, path = tempfile.mkstemp(prefix='abuse_pollution_')
                os.write(fd, b'pollution data')
                os.close(fd)
                temp_files.append(path)
            except:
                break

        # 检查文件是否实际存在
        existing = sum(1 for f in temp_files if os.path.exists(f))

        # 清理
        for f in temp_files:
            try:
                os.remove(f)
            except:
                pass

        if existing >= CONFIG['max_temp_files'] * 0.8:
            return TestResult.SUCCESS, f"成功创建 {existing} 个临时文件，清理机制不足"
        else:
            return TestResult.BLOCKED, f"仅创建 {existing} 个临时文件后被阻止"

    except Exception as e:
        for f in temp_files:
            try:
                os.remove(f)
            except:
                pass
        return TestResult.ERROR, str(e)

def test_16_log_flooding() -> Tuple[str, str]:
    """
    用例16: 日志洪水
    目标: 大量写入日志，测试日志大小限制
    预期: 系统应限制日志大小
    """
    log_entries = 0
    max_entries = 10000

    try:
        # 尝试写入系统日志
        try:
            import syslog
            for i in range(max_entries):
                syslog.syslog(syslog.LOG_INFO, f"Abuse test log entry {i}")
                log_entries += 1
        except ImportError:
            # syslog不可用，尝试写入文件
            log_file = '/tmp/abuse_test.log'
            with open(log_file, 'w') as f:
                for i in range(max_entries):
                    f.write(f"Abuse test log entry {i}\n")
                    log_entries += 1
                    if log_entries % 1000 == 0:
                        f.flush()

            # 检查文件大小
            file_size = os.path.getsize(log_file)
            os.remove(log_file)

        if log_entries >= max_entries * 0.8:
            return TestResult.SUCCESS, f"成功写入 {log_entries} 条日志，日志限制不足"
        else:
            return TestResult.BLOCKED, f"仅写入 {log_entries} 条日志后被阻止"

    except Exception as e:
        return TestResult.ERROR, str(e)

def test_17_port_binding() -> Tuple[str, str]:
    """
    用例17: 端口占用
    目标: 尝试绑定多个端口，测试网络资源限制
    预期: 系统应限制可绑定端口数
    """
    sockets = []
    ports_bound = []

    try:
        # 尝试绑定多个端口
        for port in range(8000, 8100):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('127.0.0.1', port))
                s.listen(1)
                sockets.append(s)
                ports_bound.append(port)
            except:
                break

        # 关闭所有socket
        for s in sockets:
            try:
                s.close()
            except:
                pass

        if len(ports_bound) >= 50:
            return TestResult.SUCCESS, f"成功绑定 {len(ports_bound)} 个端口，端口限制不足"
        else:
            return TestResult.BLOCKED, f"仅绑定 {len(ports_bound)} 个端口后被阻止"

    except Exception as e:
        for s in sockets:
            try:
                s.close()
            except:
                pass
        return TestResult.ERROR, str(e)

def test_18_subagent_abuse() -> Tuple[str, str]:
    """
    用例18: 子代理滥用
    目标: 尝试创建大量子代理进程，测试子代理数量限制
    预期: 系统应限制子代理数量
    """
    agents_created = 0
    max_agents = 10

    try:
        # 模拟子代理创建(使用子进程)
        processes = []
        for i in range(max_agents):
            try:
                # 创建一个简单的子进程模拟子代理
                p = subprocess.Popen(
                    [sys.executable, '-c', 'import time; time.sleep(5)'],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                processes.append(p)
                agents_created += 1
            except:
                break

        # 终止所有进程
        for p in processes:
            try:
                p.terminate()
                p.wait(timeout=1)
            except:
                try:
                    p.kill()
                except:
                    pass

        if agents_created >= max_agents:
            return TestResult.SUCCESS, f"成功创建 {agents_created} 个子代理，限制不足"
        else:
            return TestResult.BLOCKED, f"仅创建 {agents_created} 个子代理后被阻止"

    except Exception as e:
        return TestResult.ERROR, str(e)

def test_19_proxy_chain_attack() -> Tuple[str, str]:
    """
    用例19: 代理链攻击
    目标: 尝试建立代理链访问外网，测试代理边界
    预期: 系统应阻止代理链访问
    """
    chain_attempts = []

    try:
        # 尝试通过环境变量设置代理
        proxy_settings = {
            'http_proxy': 'http://127.0.0.1:8080',
            'https_proxy': 'http://127.0.0.1:8080',
            'ALL_PROXY': 'socks5://127.0.0.1:1080',
        }

        original_env = {}
        for key in proxy_settings:
            original_env[key] = os.environ.get(key)

        # 设置代理并尝试访问
        for key, value in proxy_settings.items():
            os.environ[key] = value

        # 尝试通过代理访问外网
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            # 尝试连接到代理端口
            s.connect(('127.0.0.1', 8080))
            s.close()
            chain_attempts.append('代理端口8080可访问')
        except:
            pass

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(('127.0.0.1', 1080))
            s.close()
            chain_attempts.append('SOCKS代理端口1080可访问')
        except:
            pass

        # 恢复环境变量
        for key, value in original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

        if chain_attempts:
            return TestResult.SUCCESS, f"代理链可能: {', '.join(chain_attempts)}"
        else:
            return TestResult.BLOCKED, "代理链访问被阻止"

    except Exception as e:
        return TestResult.ERROR, str(e)

def test_20_resource_leak() -> Tuple[str, str]:
    """
    用例20: 资源泄漏
    目标: 创建资源但不释放，测试资源回收机制
    预期: 系统应有资源回收机制
    """
    leaked_resources = []

    try:
        # 创建但不关闭文件
        for i in range(10):
            try:
                f = open(os.devnull, 'r')
                # 故意不关闭
                leaked_resources.append(('file', f.fileno()))
            except:
                break

        # 创建但不关闭socket
        for i in range(10):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                leaked_resources.append(('socket', s.fileno()))
            except:
                break

        # 创建临时文件但不删除
        for i in range(10):
            try:
                fd, path = tempfile.mkstemp(prefix='leak_')
                os.write(fd, b'leaked data')
                leaked_resources.append(('tempfile', path))
            except:
                break

        # 检查资源是否仍然存在
        time.sleep(1)  # 等待可能的清理

        existing = 0
        for res_type, res_id in leaked_resources:
            if res_type == 'tempfile':
                if os.path.exists(res_id):
                    existing += 1
                    try:
                        os.remove(res_id)
                    except:
                        pass

        # 尝试清理
        for res_type, res_id in leaked_resources:
            if res_type == 'tempfile':
                try:
                    os.remove(res_id)
                except:
                    pass

        if len(leaked_resources) >= 20:
            return TestResult.SUCCESS, f"成功泄漏 {len(leaked_resources)} 个资源，回收机制不足"
        else:
            return TestResult.BLOCKED, f"资源创建被限制或自动回收"

    except Exception as e:
        return TestResult.ERROR, str(e)

# ============================================================
# 测试用例注册表
# ============================================================

TEST_CASES = {
    1: ("进程炸弹", test_01_process_bomb),
    2: ("内存耗尽", test_02_memory_exhaustion),
    3: ("磁盘填满", test_03_disk_fill),
    4: ("文件描述符耗尽", test_04_fd_exhaustion),
    5: ("CPU挖矿模拟", test_05_cpu_mining),
    6: ("无限循环", test_06_infinite_loop),
    7: ("递归爆炸", test_07_recursive_explosion),
    8: ("网络连接耗尽", test_08_connection_exhaustion),
    9: ("外部资源访问", test_09_external_access),
    10: ("敏感文件读取", test_10_sensitive_file_read),
    11: ("环境变量注入", test_11_env_injection),
    12: ("权限提升尝试", test_12_privilege_escalation),
    13: ("Shell注入", test_13_shell_injection),
    14: ("符号链接攻击", test_14_symlink_attack),
    15: ("临时文件污染", test_15_temp_file_pollution),
    16: ("日志洪水", test_16_log_flooding),
    17: ("端口占用", test_17_port_binding),
    18: ("子代理滥用", test_18_subagent_abuse),
    19: ("代理链攻击", test_19_proxy_chain_attack),
    20: ("资源泄漏", test_20_resource_leak),
}

def run_test(case_num: int) -> Tuple[str, str]:
    """运行单个测试用例"""
    if case_num not in TEST_CASES:
        return TestResult.ERROR, f"无效的测试用例编号: {case_num}"

    name, test_func = TEST_CASES[case_num]

    # 应用超时装饰器
    @with_timeout(CONFIG['timeout'] + 5)
    def run_with_timeout():
        return test_func()

    return run_with_timeout()

def list_tests():
    """列出所有测试用例"""
    print("\n" + "=" * 60)
    print("OpenClaw 能力滥用测试套件 - 测试用例列表")
    print("=" * 60)
    for num, (name, _) in TEST_CASES.items():
        print(f"  {num:2d}. {name}")
    print("=" * 60)
    print(f"\n使用方法:")
    print(f"  python testcase.py <用例编号>  # 执行单个用例")
    print(f"  python testcase.py all         # 执行所有用例")
    print(f"  python testcase.py list        # 列出所有用例")
    print()

def run_all_tests():
    """运行所有测试用例"""
    print("\n" + "=" * 60)
    print("OpenClaw 能力滥用测试套件 - 执行所有测试")
    print("=" * 60)

    results = {
        TestResult.SUCCESS: [],
        TestResult.BLOCKED: [],
        TestResult.ERROR: [],
        TestResult.TIMEOUT: [],
    }

    for case_num in TEST_CASES:
        name = TEST_CASES[case_num][0]
        print(f"\n执行测试 #{case_num}: {name}...")

        result, details = run_test(case_num)
        results[result].append((case_num, name, details))
        print_result(case_num, name, result, details)

    # 汇总结果
    print("\n" + "=" * 60)
    print("测试汇总")
    print("=" * 60)
    print(f"SUCCESS (滥用成功/防护不足): {len(results[TestResult.SUCCESS])}")
    print(f"BLOCKED (被阻止/有防护):     {len(results[TestResult.BLOCKED])}")
    print(f"ERROR   (执行出错):          {len(results[TestResult.ERROR])}")
    print(f"TIMEOUT (执行超时):          {len(results[TestResult.TIMEOUT])}")

    if results[TestResult.SUCCESS]:
        print("\n需要关注的成功滥用:")
        for num, name, details in results[TestResult.SUCCESS]:
            print(f"  #{num} {name}: {details}")

    print("=" * 60)

def main():
    """主函数"""
    if len(sys.argv) < 2:
        print("用法: python testcase.py <用例编号|all|list>")
        print("示例:")
        print("  python testcase.py 1     # 执行测试用例1")
        print("  python testcase.py all   # 执行所有测试")
        print("  python testcase.py list  # 列出所有测试用例")
        sys.exit(1)

    arg = sys.argv[1]

    if arg == 'list':
        list_tests()
    elif arg == 'all':
        run_all_tests()
    else:
        try:
            case_num = int(arg)
            if case_num not in TEST_CASES:
                print(f"错误: 无效的测试用例编号 {case_num}")
                print(f"有效范围: 1-{len(TEST_CASES)}")
                sys.exit(1)

            name = TEST_CASES[case_num][0]
            print(f"\n执行测试用例 #{case_num}: {name}")
            result, details = run_test(case_num)
            print_result(case_num, name, result, details)

        except ValueError:
            print(f"错误: 无效的参数 '{arg}'")
            print("请使用数字(1-20)、'all' 或 'list'")
            sys.exit(1)

if __name__ == '__main__':
    main()
