#!/usr/bin/env python3
"""
OpenClaw 沙箱安全测试主程序
用途：一键运行所有安全测试并生成报告
"""

import sys
import os

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from network_boundary_test import NetworkBoundaryTest
from container_escape_test import ContainerEscapeTest
from security_report_generator import SecurityReportGenerator

def main():
    """主测试流程"""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    OpenClaw 沙箱安全测试套件                                  ║
║                    Security Test Suite for OpenClaw Sandbox                  ║
╚══════════════════════════════════════════════════════════════════════════════╝

⚠️  授权声明: 本测试套件仅用于已授权的安全测试，严禁用于未授权的系统
⚠️  Legal Notice: This test suite is for authorized security testing only

""")
    
    # 确认授权
    confirm = input("请确认您已获得测试授权 (yes/no): ")
    if confirm.lower() != "yes":
        print("测试已取消")
        return
    
    print("\n开始安全测试...\n")
    
    # 初始化报告生成器
    report_generator = SecurityReportGenerator()
    
    # 1. 网络边界测试
    print("\n" + "=" * 80)
    print("第一阶段: 网络边界测试")
    print("=" * 80)
    network_tester = NetworkBoundaryTest()
    network_results = network_tester.run_all_tests()
    report_generator.load_test_results("network_boundary", network_results)
    
    # 2. 容器隔离测试
    print("\n" + "=" * 80)
    print("第二阶段: 容器隔离测试")
    print("=" * 80)
    container_tester = ContainerEscapeTest()
    container_results = container_tester.run_all_tests()
    report_generator.load_test_results("container_escape", container_results)
    
    # 3. 生成综合报告
    print("\n" + "=" * 80)
    print("生成安全评估报告")
    print("=" * 80)
    report = report_generator.save_report("openclaw_security_report.txt")
    
    # 4. 输出 JSON 结果
    json_output = {
        "network_boundary": network_results,
        "container_escape": container_results,
        "risk_score": report_generator.calculate_risk_score(),
        "risk_level": report_generator.get_risk_level(report_generator.calculate_risk_score())
    }
    
    with open("openclaw_security_results.json", 'w', encoding='utf-8') as f:
        json.dump(json_output, f, indent=2, ensure_ascii=False)
    
    print("\n测试完成!")
    print(f"  - 文本报告: openclaw_security_report.txt")
    print(f"  - JSON 结果: openclaw_security_results.json")


if __name__ == "__main__":
    main()