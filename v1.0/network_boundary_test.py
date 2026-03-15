#!/usr/bin/env python3
"""
OpenClaw 沙箱网络边界测试模块

用途：
    验证沙箱网络隔离是否有效，检测网络出口边界风险

测试原理：
    通过尝试各种网络操作（DNS解析、TCP连接、HTTP请求等），
    验证沙箱是否正确限制了网络访问。如果测试能够成功访问
    外部网络资源，说明网络隔离存在缺陷。

测试项目：
    1. DNS 解析测试 - 验证是否能解析外部域名
    2. TCP 出站测试 - 验证是否能建立外部 TCP 连接
    3. HTTP 请求测试 - 验证是否能发起 HTTP/HTTPS 请求
    4. 外部 API 测试 - 验证是否能访问外部 API 并获取出口 IP

风险等级：
    - Critical: 可建立外部连接，数据可外泄
    - High: 可解析外部域名或访问外部 API
    - Medium: 部分网络功能可用

输出：
    - 控制台输出测试过程
    - JSON 格式测试结果
"""

import socket
import urllib.request
import urllib.error
import json
import time
from typing import Dict, List


class NetworkBoundaryTest:
    """
    网络边界测试类
    
    用于验证沙箱的网络隔离是否有效，检测以下风险：
    - 数据泄露：敏感信息可能被发送到外部服务器
    - 命令控制：可能被用作 C2 节点
    - 资源滥用：可能被用于挖矿、DDoS 等
    
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
    
    def test_dns_resolution(self) -> bool:
        """
        测试 DNS 解析能力
        
        测试原理：
            尝试解析外部域名（google.com, github.com, example.com），
            如果能够成功解析出 IP 地址，说明 DNS 服务未被隔离，
            攻击者可以通过 DNS 解析访问外部服务。
        
        风险影响：
            - 可解析恶意域名，连接 C2 服务器
            - 可通过 DNS 隧道外泄数据
        
        返回：
            bool: True=安全（DNS被隔离），False=存在风险
        """
        print("\n[TEST] DNS 解析测试")
        print("原理: 尝试解析外部域名，验证 DNS 是否被隔离")
        
        test_domains = [
            "google.com",
            "github.com", 
            "example.com"
        ]
        
        resolved = 0
        for domain in test_domains:
            try:
                # 使用 socket.gethostbyname 进行 DNS 解析
                ip = socket.gethostbyname(domain)
                resolved += 1
                print(f"  - {domain} -> {ip}")
            except socket.gaierror as e:
                print(f"  - {domain} -> 解析失败: {e}")
        
        # 如果能解析外部域名，说明 DNS 未被隔离
        if resolved > 0:
            self.log_result(
                "DNS 解析", 
                False,  # FAIL = 存在风险
                f"成功解析 {resolved}/{len(test_domains)} 个外部域名，DNS 未隔离",
                "High"
            )
            return False
        else:
            self.log_result(
                "DNS 解析",
                True,  # PASS = 安全
                "DNS 解析被隔离，无法解析外部域名"
            )
            return True
    
    def test_tcp_connection(self) -> bool:
        """
        测试 TCP 出站连接
        
        测试原理：
            尝试建立到外部服务器的 TCP 连接（Google DNS、Cloudflare、GitHub），
            如果能够成功建立连接，说明 TCP 出站未被防火墙限制，
            攻击者可以建立任意 TCP 连接。
        
        风险影响：
            - 可连接外部 C2 服务器
            - 可通过反弹 shell 获取远程控制
            - 可外泄敏感数据
        
        返回：
            bool: True=安全（TCP被隔离），False=存在风险
        """
        print("\n[TEST] TCP 出站连接测试")
        print("原理: 尝试建立外部 TCP 连接，验证防火墙是否限制出站流量")
        
        test_endpoints = [
            ("8.8.8.8", 53, "Google DNS"),
            ("1.1.1.1", 80, "Cloudflare"),
            ("github.com", 443, "GitHub HTTPS")
        ]
        
        connected = 0
        for host, port, name in test_endpoints:
            try:
                # 创建 TCP socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)  # 3秒超时
                
                # 尝试连接
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    connected += 1
                    print(f"  - {name} ({host}:{port}) -> 连接成功")
                else:
                    print(f"  - {name} ({host}:{port}) -> 连接失败")
            except Exception as e:
                print(f"  - {name} ({host}:{port}) -> 异常: {e}")
        
        if connected > 0:
            self.log_result(
                "TCP 出站",
                False,
                f"成功连接 {connected}/{len(test_endpoints)} 个外部端点，TCP 未隔离",
                "Critical"
            )
            return False
        else:
            self.log_result(
                "TCP 出站",
                True,
                "TCP 出站连接被隔离"
            )
            return True
    
    def test_http_request(self) -> bool:
        """
        测试 HTTP/HTTPS 请求
        
        测试原理：
            尝试发起 HTTP/HTTPS 请求到外部网站（httpbin.org、GitHub、example.com），
            如果能够成功获取响应，说明 HTTP 代理未被限制，
            攻击者可以通过 HTTP 协议外泄数据或访问外部服务。
        
        风险影响：
            - 可通过 HTTP POST 外泄数据
            - 可访问外部 API 执行恶意操作
            - 可下载恶意软件
        
        返回：
            bool: True=安全（HTTP被隔离），False=存在风险
        """
        print("\n[TEST] HTTP/HTTPS 请求测试")
        print("原理: 尝试发起 HTTP 请求，验证 HTTP 代理是否限制外部访问")
        
        test_urls = [
            "https://httpbin.org/ip",
            "https://api.github.com",
            "https://example.com"
        ]
        
        success_count = 0
        for url in test_urls:
            try:
                # 创建请求对象
                req = urllib.request.Request(
                    url, 
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                
                # 发起请求
                response = urllib.request.urlopen(req, timeout=5)
                data = response.read()
                success_count += 1
                print(f"  - {url} -> 状态码: {response.status}, 数据长度: {len(data)}")
            except urllib.error.URLError as e:
                print(f"  - {url} -> 请求失败: {e.reason}")
            except Exception as e:
                print(f"  - {url} -> 异常: {e}")
        
        if success_count > 0:
            self.log_result(
                "HTTP 请求",
                False,
                f"成功请求 {success_count}/{len(test_urls)} 个外部 URL，HTTP 未隔离",
                "Critical"
            )
            return False
        else:
            self.log_result(
                "HTTP 请求",
                True,
                "HTTP/HTTPS 请求被隔离"
            )
            return True
    
    def test_external_api(self) -> bool:
        """
        测试外部 API 访问
        
        测试原理：
            尝试访问 httpbin.org/ip API 获取出口 IP 地址，
            如果能够成功获取，说明可以访问外部 API 且暴露了真实出口 IP，
            攻击者可以利用此能力进行数据外泄或服务调用。
        
        风险影响：
            - 暴露出口 IP，泄露网络拓扑信息
            - 可调用外部 API 执行恶意操作
            - 可通过 API 外泄数据
        
        返回：
            bool: True=安全（API被隔离），False=存在风险
        """
        print("\n[TEST] 外部 API 访问测试")
        print("原理: 尝试访问外部 API 获取出口 IP，验证 API 访问是否被限制")
        
        try:
            # 测试获取外部 IP
            req = urllib.request.Request("https://httpbin.org/ip")
            response = urllib.request.urlopen(req, timeout=5)
            data = json.loads(response.read())
            external_ip = data.get("origin", "unknown")
            
            self.log_result(
                "外部 API",
                False,
                f"成功访问外部 API，暴露出口 IP: {external_ip}",
                "High"
            )
            return False
            
        except Exception as e:
            self.log_result(
                "外部 API",
                True,
                f"无法访问外部 API: {e}"
            )
            return True
    
    def run_all_tests(self) -> Dict:
        """
        运行所有网络边界测试
        
        执行顺序：
            1. DNS 解析测试
            2. TCP 出站连接测试
            3. HTTP/HTTPS 请求测试
            4. 外部 API 访问测试
        
        返回：
            dict: 包含以下字段的测试结果
                - total: 总测试数
                - passed: 通过数（安全）
                - failed: 失败数（存在风险）
                - results: 详细结果列表
        """
        print("=" * 60)
        print("OpenClaw 沙箱网络边界测试")
        print("=" * 60)
        
        # 按顺序执行所有测试
        self.test_dns_resolution()
        self.test_tcp_connection()
        self.test_http_request()
        self.test_external_api()
        
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
            print("\n⚠️  风险发现:")
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
    tester = NetworkBoundaryTest()
    results = tester.run_all_tests()
    
    # 输出 JSON 结果
    print("\n" + "=" * 60)
    print("JSON 结果输出")
    print("=" * 60)
    print(json.dumps(results, indent=2, ensure_ascii=False))