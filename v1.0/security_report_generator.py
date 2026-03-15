#!/usr/bin/env python3
"""
OpenClaw 沙箱安全测试综合报告生成器
用途：整合所有测试结果，生成完整的安全评估报告
"""

import json
import time
from typing import Dict, List

class SecurityReportGenerator:
    """安全报告生成器"""
    
    def __init__(self):
        self.all_results: Dict = {
            "network_boundary": None,
            "container_escape": None,
            "summary": {}
        }
    
    def load_test_results(self, test_type: str, results: Dict):
        """加载测试结果"""
        self.all_results[test_type] = results
    
    def calculate_risk_score(self) -> int:
        """计算风险评分 (0-100)"""
        score = 100  # 满分
        
        # 根据失败测试扣分
        for test_type in ["network_boundary", "container_escape"]:
            if self.all_results[test_type]:
                for result in self.all_results[test_type].get("results", []):
                    if not result["success"]:
                        risk = result.get("risk", "Medium")
                        if risk == "Critical":
                            score -= 20
                        elif risk == "High":
                            score -= 10
                        elif risk == "Medium":
                            score -= 5
                        else:
                            score -= 2
        
        return max(0, score)
    
    def get_risk_level(self, score: int) -> str:
        """获取风险等级"""
        if score >= 80:
            return "低风险"
        elif score >= 60:
            return "中风险"
        elif score >= 40:
            return "高风险"
        else:
            return "极高风险"
    
    def generate_report(self) -> str:
        """生成完整报告"""
        score = self.calculate_risk_score()
        risk_level = self.get_risk_level(score)
        
        report = f"""
================================================================================
                    OpenClaw 沙箱安全评估报告
================================================================================

报告生成时间: {time.strftime("%Y-%m-%d %H:%M:%S")}
测试环境: Kubernetes 容器内 OpenClaw 沙箱

================================================================================
                            风险评估摘要
================================================================================

综合风险评分: {score}/100
风险等级: {risk_level}

评分说明:
  80-100: 低风险 - 沙箱隔离有效
  60-79:  中风险 - 存在部分隔离缺陷
  40-59:  高风险 - 多项隔离措施失效
  0-39:   极高风险 - 沙箱几乎无隔离效果

================================================================================
                            详细测试结果
================================================================================

"""
        
        # 网络边界测试结果
        if self.all_results["network_boundary"]:
            report += "【网络边界测试】\n"
            for r in self.all_results["network_boundary"].get("results", []):
                status = "✅ 安全" if r["success"] else f"❌ 风险 [{r['risk']}]"
                report += f"  {status} - {r['test']}: {r['details']}\n"
            report += "\n"
        
        # 容器逃逸测试结果
        if self.all_results["container_escape"]:
            report += "【容器隔离测试】\n"
            for r in self.all_results["container_escape"].get("results", []):
                status = "✅ 安全" if r["success"] else f"❌ 风险 [{r['risk']}]"
                report += f"  {status} - {r['test']}: {r['details']}\n"
            report += "\n"
        
        # 修复建议
        report += self.generate_remediation()
        
        return report
    
    def generate_remediation(self) -> str:
        """生成修复建议"""
        remediation = """
================================================================================
                            修复建议
================================================================================

【网络隔离加固】
1. 配置 NetworkPolicy 限制 Pod 出站流量
   示例:
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: deny-external
   spec:
     podSelector: {}
     policyTypes:
     - Egress
     egress:
     - to:
       - ipBlock:
           cidr: 10.0.0.0/8  # 仅允许内网

2. 使用 Service Mesh (Istio/Linkerd) 实现细粒度网络控制

3. 配置 DNS 策略限制外部域名解析
   dnsPolicy: Default
   或使用内部 DNS 服务器

【容器隔离加固】
1. 禁止容器以 root 权限运行
   securityContext:
     runAsNonRoot: true
     runAsUser: 1000

2. 移除不必要的 capabilities
   securityContext:
     capabilities:
       drop: ["ALL"]

3. 启用 Pod Security Standards (Restricted)
   pod-security.kubernetes.io/enforce: restricted

4. 禁止挂载 Docker Socket
   # 不要在 volumeMounts 中包含:
   # - name: docker-sock
   #   mountPath: /var/run/docker.sock

5. 使用只读根文件系统
   securityContext:
     readOnlyRootFilesystem: true

【OpenClaw 配置加固】
1. 限制 exec 工具权限
   在 OpenClaw 配置中设置:
   exec:
     allowlist: ["/usr/bin/safe-command"]
     denylist: ["*"]

2. 禁用网络访问工具
   tools:
     disabled: ["browser", "web_fetch"]

3. 配置资源限制
   resources:
     limits:
       cpu: "500m"
       memory: "512Mi"

4. 启用审计日志
   audit:
     enabled: true
     logPath: /var/log/openclaw/audit.log

【监控与告警】
1. 配置 Falco 规则监控异常行为
2. 启用 Kubernetes Audit Log
3. 设置 Prometheus 告警规则

================================================================================
                            参考资料
================================================================================

1. Kubernetes Security Best Practices:
   https://kubernetes.io/docs/concepts/security/

2. OWASP Container Security:
   https://owasp.org/www-project-container-security/

3. CIS Kubernetes Benchmark:
   https://www.cisecurity.org/benchmark/kubernetes

================================================================================
"""
        return remediation
    
    def save_report(self, filename: str = "security_report.txt"):
        """保存报告到文件"""
        report = self.generate_report()
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"报告已保存至: {filename}")
        return report


if __name__ == "__main__":
    # 示例用法
    generator = SecurityReportGenerator()
    
    # 模拟加载测试结果
    network_results = {
        "total": 4,
        "passed": 2,
        "failed": 2,
        "results": [
            {"test": "DNS 解析", "success": False, "details": "DNS 未隔离", "risk": "High"},
            {"test": "TCP 出站", "success": False, "details": "TCP 未隔离", "risk": "Critical"},
            {"test": "HTTP 请求", "success": True, "details": "HTTP 被隔离"},
            {"test": "外部 API", "success": True, "details": "API 被隔离"}
        ]
    }
    
    container_results = {
        "total": 7,
        "passed": 5,
        "failed": 2,
        "results": [
            {"test": "容器环境", "success": True, "details": "运行在容器中"},
            {"test": "权限提升", "success": False, "details": "以 root 运行", "risk": "Critical"},
            {"test": "文件系统访问", "success": True, "details": "无法访问敏感路径"},
            {"test": "Docker Socket", "success": True, "details": "Socket 不存在"},
            {"test": "网络命名空间", "success": False, "details": "使用 host 网络", "risk": "High"},
            {"test": "进程命名空间", "success": True, "details": "PID 隔离有效"},
            {"test": "挂载点逃逸", "success": True, "details": "无宿主机挂载"}
        ]
    }
    
    generator.load_test_results("network_boundary", network_results)
    generator.load_test_results("container_escape", container_results)
    
    report = generator.save_report()
    print(report)