# Changelog

本项目使用 `YY.MM.N` 版本号。

## 26.07.1 - 2026-07-26

首个早期源码版本。

### 包含

- 基于官方 OpenWrt commit `25ee12629edcc38feffbd06255dd47840cd7af7e` 的公开源码树；
- x86_64、glibc 2.43、GCC 16 与 Linux 7.2-rc3 兼容改动；
- JMX conntrack 状态与 flow-offload 隔离补丁；
- PPPoE 多拨认证同步补丁；
- 静态 DHCPv6 IA-PD 早期补丁；
- 完整、独立的 `dreamingwrt-web`；
- `jmxd`、`jmx` 与 `libjmx_common` 公开源码；
- 无私有数据时的显式 `unavailable`/`degraded` 状态和发布边界测试。

### 不包含

- 私有 DPI/应用特征库；
- 设备指纹数据库、完整设备图库和私有 logo 库；
- 内部规则生成材料；
- `dreamingproxy`；
- 旧版 `luci-app-*`、`luci-theme-*` 和历史 LuCI 后台；
- 固件镜像、IPK/APK 或其他构建产物。

### 已知限制

- Linux 7.2 仍处于 release-candidate 阶段；
- 静态 DHCPv6 IA-PD 补丁仍需要更广泛的真实网络验证；
- 没有私有数据时，DPI、设备指纹和相关图片能力会明确降级；
- 标准 OpenWrt `luci-app-*` 不能直接运行在 DreamingOS Web 中；
- 首版主要面向开发者和测试用户，不承诺稳定升级 ABI。
