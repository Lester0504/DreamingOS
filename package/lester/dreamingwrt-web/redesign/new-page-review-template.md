# Dreaming OS 新页面准入审查

> 本模板必须在新增路由或新增独立页面任务前填写。未回答完整时不得合入。

## 页面合同

- 路由：
- 用户任务名称：
- Owner：
- PageShell：`status-overview | data-workbench | settings-workbench | master-detail | guided-configuration | canvas-workbench | focused-task`
- 主任务：
- 主状态：
- 唯一主操作：

## 组件与依赖

- 复用的 UI Kit 原语：
- 必须新增的原语及不能复用现有原语的理由：
- 主从关系与渐进披露方式：
- Capability key 与 `available/unavailable/hidden` 表达：

## 数据合同

- Registry key：
- Owner / schema / 单位 / `observed_at`：
- TTL / stale-while-revalidate / last-known-good：
- WebSocket patch 方式：
- 配置、运行态、聚合和历史的边界：

## 状态与生命周期

- `loading`：
- `refreshing`：
- `ready`：
- `stale`：
- `empty`：
- `error`：
- `unavailable`：
- `forbidden`：
- `mount/update/unmount` 资源与 Abort 清理：

## 响应式与可访问性

- 390x844 核心任务步骤：
- 键盘路径和焦点返回：
- Accessible name / Field label：
- 44x44px 命中区：
- 长中文、MAC、IPv6、路径处理：

## 性能预算

- 100ms 内导航反馈与骨架：
- 单任务 <50ms：
- 空态 DOM：
- 延迟图表/地图/历史：
- 稳定节点和局部 patch：

## 验收证据

- 自动化命令与结果：
- 1440x1000：
- 1024x768：
- 390x844：
- 30.1 真实运行态：
- 明暗壁纸、reduced motion/transparency、high contrast：

