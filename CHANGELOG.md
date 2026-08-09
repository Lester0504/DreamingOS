# Changelog

本项目使用 `YY.MM.N` 版本号。

## 26.08.1 - 2026-08-09

第二个早期源码版本。相对 26.07.1 共 11 次增量提交，658 个文件变更。

### 新增

- 云端接入组件 `cloud`：设备注册、身份与中继 router id、配置下发、隧道与重放保护；
- AP 管理增强：主动发现、beacon、配对码与二维码配对、`apdctl` 命令行、
  厂商信道表、配置执行与失败恢复；
- OTA 信任链：ed25519 发布签名校验、热更新暂存与落盘、磁盘空间门禁、
  状态探测缓存（公钥与 `policy.json` 公开，私钥不入库）；
- `jmx` 内核统计模块 `jmx_stats`：连接、客户端、规则的实时计数与内存池统计；
- AegisX 侧 PCDN 识别与证书处理；
- 新增 Web 页面：应用过滤、终端联网控制、终端限速、流量引擎、网关影子、
  IP 地址管理、QWRT 模块、Web 访问控制；
- 终端分组校验、存储文件字节流下载、UCI 取值净化。

### 变更

- Web 前端统一到 dwrt ui-kit（抽屉、sheet、纵向 tab、表格），并补齐
  对应 gzip 资源；
- 多 WAN 会话记账、路由表重同步与运营商自动识别；
- Wi-Fi 频段真值合并，AP 无线接口探测区分 MLD 伪 PHY 与真实失败。

### 不包含

同 26.07.1：私有 DPI/特征库、设备指纹库与图库、私有 logo、内部规则生成材料、
`dreamingproxy`、旧版 LuCI 后台、固件镜像与构建产物。

此外本版暂缓：Flow QoE 运行时（依赖尚未在公开 `jmxd/Makefile` 声明的
`nftables`/`libnetfilter-conntrack`）、内核 APPCAT 分类计数的内核侧实现。

### 已知限制

- Dev 分支仅供开发者尝鲜，建议在 PVE/ESXi 等虚拟机中安装；
- Linux 7.2 仍处于 release-candidate 阶段；
- 无私有数据时，DPI、设备指纹及相关图片能力仍会明确降级；
- 部分功能仍在逐步上线，公开树中可能存在尚未接线的页面或接口。

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
