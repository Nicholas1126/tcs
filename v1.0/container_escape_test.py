#!/usr/bin/env python3
"""
OpenClaw 沙箱容器隔离边界测试模块

用途：
    验证容器隔离是否有效，检测容器逃逸风险

测试原理：
    通过检查容器环境配置、权限设置、命名空间隔离等，
    验证容器是否正确限制了访问能力。如果测试发现配置
    缺陷，攻击者可能突破容器边界，获取宿主机控制权。

测试项目：
    1. 容器环境识别 - 确认运行在容器中
    2. 权限提升测试 - 检查是否以 root 运行
    3. 文件系统访问 - 检查是否能访问敏感文件
    4. Docker Socket 访问 - 检查是否能控制 Docker
    5. 网络命名空间 - 检查网络隔离
    6. 进程命名空间 - 检查进程隔离
    7. 挂载点逃逸 - 检查宿主机目录挂载

风险等级：
    - Critical: 可逃逸到宿主机或获得 root 权限
    - High: 可访问敏感资源或突破部分隔离
    - Medium: 配置不当但利用难度较高

输出：
    - 控制台输出测试过程
    - JSON 格式测试结果
"""

import os
import subprocess
import json
import time
from typing import Dict, List, Tuple


class ContainerEscapeTest:
    """
    容器逃逸测试类
    
    用于验证容器的隔离是否有效，检测以下风险：
    - 容器逃逸：可能获得宿主机控制权
    - 权限提升：可能获得 root 权限
    - 数据泄露：可能访问宿主机敏感数据
    - 资源滥用：可能滥用宿主机资源
    
    属性：
        results: 测试结果列表，存储每项测试的详细结果
    """
    
    def __init__(self):
        """初始化测试类，创建空的结果列表"""
        self.results: List[Dict] = []
    
    def log_result(self, test_name: str, success: bool, details: str, risk: str = "Medium"):
        """
        记录测试结果
        
        参数：
            test_name: 测试项目名称
            success: 测试是否通过（True=安全，False=存在风险）
            details: 测试结果详情
            risk: 风险等级（Critical/High/Medium/Low）
        
        说明：
            success=True 表示隔离有效，测试通过
            success=False 表示存在风险，需要修复
        """
        result = {
            "test": test_name,
            "success": success,
            "details": details,
            "risk": risk,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.results.append(result)
        
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"[{status}] {test_name}: {details}")
    
    def run_command(self, cmd: str) -> Tuple[int, str, str]:
        """
        执行 shell 命令并返回结果
        
        参数：
            cmd: 要执行的 shell 命令
        
        返回：
            Tuple[int, str, str]: (返回码, 标准输出, 标准错误)
        
        说明：
            使用 subprocess.Popen 执行命令，设置超时为 10 秒
        """
        try:
            proc = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = proc.communicate(timeout=10)
            return proc.returncode, stdout.decode('utf-8', errors='ignore'), stderr.decode('utf-8', errors='ignore')
        except subprocess.TimeoutExpired:
            return -1, "", "Command timeout"
        except Exception as e:
            return -1, "", str(e)
    
    def test_container_environment(self) -> bool:
        """
        测试容器环境识别
        
        测试原理：
            检查 /.dockerenv 文件和 /proc/1/cgroup 内容，
            确认当前进程运行在容器环境中。如果无法确认
            容器环境，可能已在宿主机上运行，风险极高。
        
        检查项：
            - /.dockerenv 文件是否存在
            - /proc/1/cgroup 是否包含 docker/kubepods 关键字
            - hostname 是否为容器 ID 格式
        
        返回：
            bool: True=确认在容器中，False=可能不在容器中
        """
        print("\n[TEST] 容器环境识别")
        print("原理: 检查 /.dockerenv 和 cgroup 信息，确认运行在容器中")
        
        # 检查 /.dockerenv 文件
        dockerenv_exists = os.path.exists("/.dockerenv")
        
        # 检查 cgroup 信息
        returncode, stdout, stderr = self.run_command("cat /proc/1/cgroup 2>/dev/null | head -5")
        cgroup_info = stdout if returncode == 0 else "N/A"
        
        # 检查容器 ID
        returncode, stdout, stderr = self.run_command("hostname")
        hostname = stdout.strip() if returncode == 0 else "unknown"
        
        print(f"  - .dockerenv 存在: {dockerenv_exists}")
        print(f"  - 主机名: {hostname}")
        print(f"  - Cgroup 信息:\n{cgroup_info}")
        
        if dockerenv_exists or "docker" in cgroup_info.lower() or "kubepods" in cgroup_info.lower():
            self.log_result(
                "容器环境",
                True,
                f"运行在容器环境中 (hostname: {hostname})"
            )
            return True
        else:
            self.log_result(
                "容器环境",
                False,
                "无法确认容器环境，可能已在宿主机",
                "Critical"
            )
            return False
    
    def test_privilege_escalation(self) -> bool:
        """
        测试权限提升风险
        
        测试原理：
            检查容器是否以 root 用户运行，以及是否具有
            sudo 权限或危险的 capabilities。如果容器以
            root 运行，一旦被攻破，攻击者可立即获得
            宿主机 root 权限（在某些配置下）。
        
        检查项：
            - 当前用户是否为 root
            - sudo 权限配置
            - capabilities 设置
        
        返回：
            bool: True=权限安全，False=存在提权风险
        """
        print("\n[TEST] 权限提升测试")
        print("原理: 检查是否以 root 运行，验证权限隔离是否有效")
        
        # 检查当前用户
        returncode, stdout, stderr = self.run_command("whoami")
        current_user = stdout.strip() if returncode == 0 else "unknown"
        
        # 检查是否是 root
        is_root = current_user == "root"
        
        # 检查 sudo 权限
        returncode, stdout, stderr = self.run_command("sudo -l 2>&1 | head -5")
        sudo_info = stdout if returncode == 0 else "无 sudo 权限"
        
        # 检查 capabilities
        returncode, stdout, stderr = self.run_command("capsh --print 2>/dev/null || cat /proc/self/status | grep Cap")
        caps_info = stdout if returncode == 0 else "无法获取 capabilities"
        
        print(f"  - 当前用户: {current_user}")
        print(f"  - Root 权限: {is_root}")
        print(f"  - Sudo 权限: {sudo_info[:100]}...")
        print(f"  - Capabilities: {caps_info[:100]}...")
        
        if is_root:
            self.log_result(
                "权限提升",
                False,
                "容器以 root 权限运行，存在提权风险",
                "Critical"
            )
            return False
        else:
            self.log_result(
                "权限提升",
                True,
                f"以非 root 用户运行 ({current_user})"
            )
            return True
    
    def test_filesystem_access(self) -> bool:
        """
        测试文件系统访问
        
        测试原理：
            尝试访问容器内的敏感文件路径，如 /etc/shadow、
            /root/.ssh 等。如果能够访问这些文件，说明
            文件系统权限配置不当，可能泄露敏感信息。
        
        检查项：
            - /etc/shadow (密码文件)
            - /etc/passwd (用户文件)
            - /root/.ssh (SSH 密钥)
            - /var/run/docker.sock (Docker Socket)
            - /proc/1/root (宿主机根文件系统)
            - /sys/class (系统设备信息)
        
        返回：
            bool: True=文件系统安全，False=可访问敏感文件
        """
        print("\n[TEST] 文件系统访问测试")
        print("原理: 尝试访问敏感文件路径，验证文件系统权限隔离")
        
        # 检查敏感路径
        sensitive_paths = [
            "/etc/shadow",
            "/etc/passwd",
            "/root/.ssh",
            "/var/run/docker.sock",
            "/proc/1/root",
            "/sys/class"
        ]
        
        accessible = []
        for path in sensitive_paths:
            if os.path.exists(path):
                try:
                    # 尝试读取
                    if os.path.isfile(path):
                        with open(path, 'r') as f:
                            content = f.read(100)
                            accessible.append(path)
                            print(f"  - {path} -> 可读取")
                    elif os.path.isdir(path):
                        files = os.listdir(path)
                        accessible.append(path)
                        print(f"  - {path} -> 可列出 ({len(files)} 项)")
                except PermissionError:
                    print(f"  - {path} -> 权限拒绝")
                except Exception as e:
                    print(f"  - {path} -> 异常: {e}")
            else:
                print(f"  - {path} -> 不存在")
        
        if len(accessible) > 0:
            self.log_result(
                "文件系统访问",
                False,
                f"可访问 {len(accessible)} 个敏感路径: {', '.join(accessible)}",
                "Critical"
            )
            return False
        else:
            self.log_result(
                "文件系统访问",
                True,
                "无法访问敏感路径"
            )
            return True
    
    def test_docker_socket(self) -> bool:
        """
        测试 Docker Socket 访问
        
        测试原理：
            检查 /var/run/docker.sock 是否存在且可访问。
            如果能够访问 Docker Socket，攻击者可以通过
            Docker API 创建特权容器，完全控制宿主机。
        
        风险影响：
            - 可创建特权容器逃逸到宿主机
            - 可读取宿主机任意文件
            - 可修改宿主机配置
        
        返回：
            bool: True=Docker Socket 安全，False=可访问 Socket
        """
        print("\n[TEST] Docker Socket 访问测试")
        print("原理: 检查 Docker Socket 是否可访问，验证 Docker 控制权隔离")
        
        docker_sock = "/var/run/docker.sock"
        
        if os.path.exists(docker_sock):
            print(f"  - Docker Socket 存在: {docker_sock}")
            
            # 尝试通过 curl 访问 Docker API
            returncode, stdout, stderr = self.run_command(
                "curl --unix-socket /var/run/docker.sock http://localhost/containers/json 2>/dev/null | head -100"
            )
            
            if returncode == 0 and stdout:
                self.log_result(
                    "Docker Socket",
                    False,
                    "Docker Socket 可访问，可控制宿主机 Docker",
                    "Critical"
                )
                return False
            else:
                self.log_result(
                    "Docker Socket",
                    True,
                    "Docker Socket 存在但无法访问 API"
                )
                return True
        else:
            self.log_result(
                "Docker Socket",
                True,
                "Docker Socket 不存在"
            )
            return True
    
    def test_network_namespace(self) -> bool:
        """
        测试网络命名空间隔离
        
        测试原理：
            检查网络接口和路由表，判断容器是否使用了独立的
            网络命名空间。如果使用 host 网络模式，容器可以
            访问宿主机的所有网络接口和端口。
        
        检查项：
            - 网络接口列表
            - 路由表配置
            - 是否使用 host 网络模式
        
        返回：
            bool: True=网络隔离有效，False=网络未隔离
        """
        print("\n[TEST] 网络命名空间测试")
        print("原理: 检查网络接口和路由，验证网络命名空间隔离")
        
        # 检查网络接口
        returncode, stdout, stderr = self.run_command("ip addr 2>/dev/null || ifconfig 2>/dev/null")
        network_info = stdout if returncode == 0 else "无法获取网络信息"
        
        # 检查路由表
        returncode, stdout, stderr = self.run_command("ip route 2>/dev/null || route -n 2>/dev/null")
        route_info = stdout if returncode == 0 else "无法获取路由信息"
        
        # 检查是否能访问宿主机网络
        has_host_network = "eth0" not in network_info and "docker" not in network_info.lower()
        
        print(f"  - 网络接口:\n{network_info[:200]}...")
        print(f"  - 路由表:\n{route_info[:200]}...")
        
        if "host" in network_info.lower() or has_host_network:
            self.log_result(
                "网络命名空间",
                False,
                "可能使用 host 网络模式，网络未隔离",
                "High"
            )
            return False
        else:
            self.log_result(
                "网络命名空间",
                True,
                "使用独立网络命名空间"
            )
            return True
    
    def test_process_namespace(self) -> bool:
        """
        测试进程命名空间隔离
        
        测试原理：
            检查容器可见的进程数量和类型。如果容器能够
            看到大量宿主机进程（如 systemd、init），
            说明 PID 命名空间未正确隔离。
        
        检查项：
            - 可见进程数量
            - 是否存在宿主机进程（systemd、init、docker）
        
        返回：
            bool: True=进程隔离有效，False=进程未隔离
        """
        print("\n[TEST] 进程命名空间测试")
        print("原理: 检查可见进程数量和类型，验证 PID 命名空间隔离")
        
        # 检查可见进程
        returncode, stdout, stderr = self.run_command("ps aux 2>/dev/null | wc -l")
        process_count = int(stdout.strip()) if returncode == 0 else 0
        
        # 检查是否有宿主机进程
        returncode, stdout, stderr = self.run_command("ps aux 2>/dev/null | grep -E 'systemd|init|docker' | head -5")
        host_processes = stdout if returncode == 0 else ""
        
        print(f"  - 可见进程数: {process_count}")
        print(f"  - 宿主机进程: {host_processes[:100] if host_processes else '无'}...")
        
        if process_count > 50 or host_processes:
            self.log_result(
                "进程命名空间",
                False,
                f"可见 {process_count} 个进程，可能共享 PID 命名空间",
                "High"
            )
            return False
        else:
            self.log_result(
                "进程命名空间",
                True,
                f"进程命名空间隔离有效 ({process_count} 个进程)"
            )
            return True
    
    def test_mount_escape(self) -> bool:
        """
        测试挂载点逃逸风险
        
        测试原理：
            检查容器的挂载点，查找是否有宿主机目录被挂载
            到容器中。如果宿主机的敏感目录（如 /、/root、
            /etc）被挂载，攻击者可以直接访问或修改宿主机
            文件。
        
        检查项：
            - mount 命令输出，查找可疑挂载点
            - df 命令输出，检查磁盘使用情况
        
        返回：
            bool: True=无危险挂载，False=存在宿主机目录挂载
        """
        print("\n[TEST] 挂载点逃逸测试")
        print("原理: 检查是否有宿主机目录挂载到容器中")
        
        # 检查挂载点
        returncode, stdout, stderr = self.run_command("mount 2>/dev/null | grep -E '/host|/root|/var|/etc'")
        suspicious_mounts = stdout if returncode == 0 else ""
        
        # 检查是否有宿主机目录挂载
        returncode, stdout, stderr = self.run_command("df -h 2>/dev/null")
        mount_info = stdout if returncode == 0 else "无法获取挂载信息"
        
        print(f"  - 可疑挂载点:\n{suspicious_mounts[:200] if suspicious_mounts else '无'}...")
        print(f"  - 磁盘使用:\n{mount_info[:200]}...")
        
        if suspicious_mounts:
            self.log_result(
                "挂载点逃逸",
                False,
                f"发现可疑挂载点，可能可访问宿主机文件",
                "Critical"
            )
            return False
        else:
            self.log_result(
                "挂载点逃逸",
                True,
                "未发现宿主机目录挂载"
            )
            return True
    
    def run_all_tests(self) -> Dict:
        """
        运行所有容器隔离测试
        
        执行顺序：
            1. 容器环境识别
            2. 权限提升测试
            3. 文件系统访问测试
            4. Docker Socket 访问测试
            5. 网络命名空间测试
            6. 进程命名空间测试
            7. 挂载点逃逸测试
        
        返回：
            dict: 包含以下字段的测试结果
                - total: 总测试数
                - passed: 通过数（安全）
                - failed: 失败数（存在风险）
                - results: 详细结果列表
        """
        print("=" * 60)
        print("OpenClaw 沙箱容器隔离边界测试")
        print("=" * 60)
        
        # 按顺序执行所有测试
        self.test_container_environment()
        self.test_privilege_escalation()
        self.test_filesystem_access()
        self.test_docker_socket()
        self.test_network_namespace()
        self.test_process_namespace()
        self.test_mount_escape()
        
        # 汇总结果
        print("\n" + "=" * 60)
        print("测试结果汇总")
        print("=" * 60)
        
        total = len(self.results)
        passed = sum(1 for r in self.results if r["success"])
        failed = total - passed
        
        print(f"总计: {total} 项测试")
        print(f"通过: {passed} 项 (安全)")
        print(f"失败: {failed} 项 (存在风险)")
        
        if failed > 0:
            print("\n⚠️  高危发现:")
            for r in self.results:
                if not r["success"]:
                    print(f"  - [{r['risk']}] {r['test']}: {r['details']}")
        
        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "results": self.results
        }


if __name__ == "__main__":
    # 独立运行时的测试入口
    tester = ContainerEscapeTest()
    results = tester.run_all_tests()
    
    # 输出 JSON 结果
    print("\n" + "=" * 60)
    print("JSON 结果输出")
    print("=" * 60)
    print(json.dumps(results, indent=2, ensure_ascii=False))