#!/usr/bin/env python3
"""
OpenClaw 沙箱网络边界测试 PoC
用途：验证沙箱网络隔离是否有效
"""

import socket
import urllib.request
import urllib.error
import json
import time
from typing import Dict, List, Tuple

class NetworkBoundaryTest:
    """网络边界测试类"""
    
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
    
    def test_dns_resolution(self) -> bool:
        """测试 DNS 解析能力"""
        print("\n[TEST] DNS 解析测试")
        
        test_domains = [
            "google.com",
            "github.com", 
            "example.com"
        ]
        
        resolved = 0
        for domain in test_domains:
            try:
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
        """测试 TCP 出站连接"""
        print("\n[TEST] TCP 出站连接测试")
        
        test_endpoints = [
            ("8.8.8.8", 53, "Google DNS"),
            ("1.1.1.1", 80, "Cloudflare"),
            ("github.com", 443, "GitHub HTTPS")
        ]
        
        connected = 0
        for host, port, name in test_endpoints:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
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
        """测试 HTTP/HTTPS 请求"""
        print("\n[TEST] HTTP/HTTPS 请求测试")
        
        test_urls = [
            "https://httpbin.org/ip",
            "https://api.github.com",
            "https://example.com"
        ]
        
        success_count = 0
        for url in test_urls:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
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
        """测试外部 API 访问"""
        print("\n[TEST] 外部 API 访问测试")
        
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
        """运行所有测试"""
        print("=" * 60)
        print("OpenClaw 沙箱网络边界测试")
        print("=" * 60)
        
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
    tester = NetworkBoundaryTest()
    results = tester.run_all_tests()
    
    # 输出 JSON 结果
    print("\n" + "=" * 60)
    print("JSON 结果输出")
    print("=" * 60)
    print(json.dumps(results, indent=2, ensure_ascii=False))