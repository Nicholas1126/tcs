#!/usr/bin/env python3
"""
OpenClaw 沙箱容器隔离边界测试 PoC
用途：验证容器隔离是否有效，检测容器逃逸风险
"""

import os
import subprocess
import json
import time
from typing import Dict, List

class ContainerEscapeTest:
    """容器逃逸测试类"""
    
    def __init__(self):
        self.results: List[Dict] = []
    
    def log_result(self, test_name: str, success: bool, details: str, risk: str = "Medium"):
        """记录测试结果"""
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
        """执行命令并返回结果"""
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
        """测试容器环境识别"""
        print("\n[TEST] 容器环境识别")
        
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
        """测试权限提升"""
        print("\n[TEST] 权限提升测试")
        
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
        """测试文件系统访问"""
        print("\n[TEST] 文件系统访问测试")
        
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
        """测试 Docker Socket 访问"""
        print("\n[TEST] Docker Socket 访问测试")
        
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
        """测试网络命名空间隔离"""
        print("\n[TEST] 网络命名空间测试")
        
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
        """测试进程命名空间隔离"""
        print("\n[TEST] 进程命名空间测试")
        
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
        """测试挂载点逃逸"""
        print("\n[TEST] 挂载点逃逸测试")
        
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
        """运行所有测试"""
        print("=" * 60)
        print("OpenClaw 沙箱容器隔离边界测试")
        print("=" * 60)
        
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
    tester = ContainerEscapeTest()
    results = tester.run_all_tests()
    
    # 输出 JSON 结果
    print("\n" + "=" * 60)
    print("JSON 结果输出")
    print("=" * 60)
    print(json.dumps(results, indent=2, ensure_ascii=False))