#!/usr/bin/env python3
"""
OpenClaw 沙箱安全测试主程序

用途：
    一键运行所有安全测试并生成报告
    
功能：
    1. 网络边界测试 - 验证沙箱网络隔离
    2. 容器隔离测试 - 验证容器逃逸风险
    3. 生成安全评估报告

输出：
    - openclaw_security_report.txt (文本报告)
    - openclaw_security_results.json (JSON结果)

使用：
    python3 run_all_tests.py

注意：
    本测试套件仅用于已授权的安全测试
"""

import sys
import os
import json

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from network_boundary_test import NetworkBoundaryTest
from container_escape_test import ContainerEscapeTest
from security_report_generator import SecurityReportGenerator


def print_banner():
    """打印程序横幅"""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    OpenClaw 沙箱安全测试套件 v1.1                            ║
║                    Security Test Suite for OpenClaw Sandbox                  ║
╚══════════════════════════════════════════════════════════════════════════════╝

⚠️  授权声明: 本测试套件仅用于已授权的安全测试，严禁用于未授权的系统
⚠️  Legal Notice: This test suite is for authorized security testing only

""")


def run_network_tests(report_generator: SecurityReportGenerator) -> dict:
    """
    运行网络边界测试
    
    测试内容：
        - DNS 解析能力
        - TCP 出站连接
        - HTTP/HTTPS 请求
        - 外部 API 访问
    
    参数：
        report_generator: 报告生成器实例
    
    返回：
        dict: 测试结果
    """
    print("\n" + "=" * 80)
    print("第一阶段: 网络边界测试")
    print("=" * 80)
    
    tester = NetworkBoundaryTest()
    results = tester.run_all_tests()
    report_generator.load_test_results("network_boundary", results)
    
    return results


def run_container_tests(report_generator: SecurityReportGenerator) -> dict:
    """
    运行容器隔离测试
    
    测试内容：
        - 容器环境识别
        - 权限提升风险
        - 文件系统访问
        - Docker Socket 访问
        - 网络命名空间隔离
        - 进程命名空间隔离
        - 挂载点逃逸风险
    
    参数：
        report_generator: 报告生成器实例
    
    返回：
        dict: 测试结果
    """
    print("\n" + "=" * 80)
    print("第二阶段: 容器隔离测试")
    print("=" * 80)
    
    tester = ContainerEscapeTest()
    results = tester.run_all_tests()
    report_generator.load_test_results("container_escape", results)
    
    return results


def generate_reports(report_generator: SecurityReportGenerator, 
                    network_results: dict, 
                    container_results: dict):
    """
    生成测试报告
    
    输出文件：
        - openclaw_security_report.txt: 文本格式完整报告
        - openclaw_security_results.json: JSON格式测试结果
    
    参数：
        report_generator: 报告生成器实例
        network_results: 网络测试结果
        container_results: 容器测试结果
    """
    print("\n" + "=" * 80)
    print("生成安全评估报告")
    print("=" * 80)
    
    # 生成文本报告
    report = report_generator.save_report("openclaw_security_report.txt")
    
    # 生成 JSON 结果
    json_output = {
        "test_suite": "OpenClaw Sandbox Security Test",
        "version": "1.1",
        "network_boundary": network_results,
        "container_escape": container_results,
        "risk_score": report_generator.calculate_risk_score(),
        "risk_level": report_generator.get_risk_level(
            report_generator.calculate_risk_score()
        )
    }
    
    with open("openclaw_security_results.json", 'w', encoding='utf-8') as f:
        json.dump(json_output, f, indent=2, ensure_ascii=False)
    
    print("\n✅ 测试完成!")
    print(f"  - 文本报告: openclaw_security_report.txt")
    print(f"  - JSON 结果: openclaw_security_results.json")


def main():
    """
    主测试流程
    
    执行步骤：
        1. 打印程序横幅
        2. 运行网络边界测试
        3. 运行容器隔离测试
        4. 生成综合报告
    """
    # 打印横幅
    print_banner()
    
    print("🚀 开始安全测试...\n")
    
    # 初始化报告生成器
    report_generator = SecurityReportGenerator()
    
    # 运行测试
    network_results = run_network_tests(report_generator)
    container_results = run_container_tests(report_generator)
    
    # 生成报告
    generate_reports(report_generator, network_results, container_results)


if __name__ == "__main__":
    main()