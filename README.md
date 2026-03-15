# TCS - Test Container Security

OpenClaw 沙箱安全测试套件

## ⚠️ 授权声明

本测试套件**仅用于已授权的安全测试**。使用前必须确认：
1. 测试环境为您拥有或已获得明确授权
2. 测试目的是发现风险并加固，而非实际攻击
3. 测试结果不会用于非法目的

**严禁在未授权环境下使用！**

---

## 📋 项目简介

TCS (Test Container Security) 是一套用于测试 OpenClaw 在 Kubernetes 容器沙箱中安全隔离边界的工具集。

### 测试范围

| 测试项 | 测试目的 | 风险等级 |
|--------|----------|----------|
| 网络出口边界 | 验证沙箱是否有网络隔离 | High |
| 容器隔离边界 | 验证是否能访问容器外资源 | Critical |
| 命令执行边界 | 验证是否能执行任意系统命令 | Critical |
| 软件安装边界 | 验证是否能安装任意软件包 | High |
| 文件系统边界 | 验证是否能访问宿主机文件系统 | Critical |

---

## 🚀 快速开始

```bash
# 克隆仓库
git clone https://github.com/Nicholas1126/tcs.git
cd tcs/v1.0

# 一键运行所有测试（无需确认）
python3 run_all_tests.py
```

---

## 📁 版本历史

### v1.1 (2026-03-15)

优化版本：
- ✅ 移除不必要的 input 确认，实现一键自动运行
- ✅ 增强所有测试函数的注释，清晰表达测试原理
- ✅ 优化代码结构和文档

### v1.0 (2026-03-15)

初始版本，包含：
- 网络边界测试 (`network_boundary_test.py`)
- 容器逃逸测试 (`container_escape_test.py`)
- 报告生成器 (`security_report_generator.py`)
- 一键运行脚本 (`run_all_tests.py`)

---

## 📊 风险评分

| 分数范围 | 风险等级 | 说明 |
|----------|----------|------|
| 80-100 | 低风险 | 沙箱隔离有效 |
| 60-79 | 中风险 | 存在部分隔离缺陷 |
| 40-59 | 高风险 | 多项隔离措施失效 |
| 0-39 | 极高风险 | 沙箱几乎无隔离效果 |

---

## 🛡️ 修复建议

详见 [v1.0/README.md](v1.0/README.md)

---

## 📝 License

MIT License

---

## 👤 Author

Web Security Agent (WSA) 🛡️