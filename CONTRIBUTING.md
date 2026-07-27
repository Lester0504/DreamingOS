# 参与 DreamingOS

感谢你愿意为 DreamingOS 提交问题或代码。项目仍处于早期阶段，请优先提交范围明确、可复现、便于验证的改动。

## 提交 Issue

提交 Bug 前请先搜索现有 Issue，并准备以下信息：

- DreamingOS 版本或 Git commit；
- 目标平台、CPU 架构、内存与存储；
- 可重复的操作步骤、预期结果和实际结果；
- 错误前后的精简日志；
- 与问题相关的配置，但必须移除密码、密钥、公网地址、设备标识和私人流量数据。

缺少私有 DPI、设备指纹或图库数据是 `26.07.1` 的预期状态。只有当系统未明确报告 `unavailable`/`degraded`、因此崩溃或无法构建时，才属于公开版本的缺陷。

安全漏洞不要提交公开 Issue，请按 [SECURITY.md](SECURITY.md) 私密报告。

## 提交 Pull Request

1. 从目标分支创建短生命周期分支。
2. 一个 PR 只解决一个清晰问题，避免夹带无关格式化或重构。
3. 保留 OpenWrt 与第三方文件原有的版权和 SPDX 声明。
4. 新引入的代码、数据和资产必须说明来源、版本、修改内容与许可证。
5. 不得提交私有 DPI/指纹库、生成输入、凭据、设备配置备份、抓包、构建产物或本地路径。
6. 为行为变更增加聚焦测试，并在 PR 中列出实际执行的命令和结果。

提交前至少运行：

```bash
python3 package/lester/jmxd/tests/test_public_data_boundary_contract.py
python3 package/lester/jmxd/tests/test_static_authority_consolidation.py
python3 package/lester/jmxd/tests/test_core_startup_schema_contract.py
python3 package/lester/jmxd/tests/test_unified_status_contract.py
```

涉及 `jmxd`、JMX 内核接口、PPPd、odhcpd 或 Web 工作流时，还应运行对应目录中的专项测试，并在可用的 glibc x86_64 环境中完成组件编译或链接验证。

## 分支与版本

- `dev` 跟进 Linux 7.2 和后续新版内核，允许较快演进；
- `stable` 计划使用 Linux 6.18 LTS，在首个稳定版本准备完成前不会提供空分支；
- 公开版本使用 `YY.MM.N`，例如 `26.07.1`；
- Git tag 使用 `vYY.MM.N`，例如 `v26.07.1`。

## 评审原则

维护者会优先考虑正确性、可验证性、公开数据边界、许可证来源以及对现有用户的兼容性。PR 可能因范围过大、无法复现、测试不足、来源不清或依赖未公开数据而暂缓合并。
