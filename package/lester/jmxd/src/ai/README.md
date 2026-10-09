# 本机 RKLLM 推理

本实现使用独立 C 管理服务与 RKLLM C ABI worker（厂商头文件需要 C++ 编译）。API 供应商不经过本机服务；本机错误不会转发到 API。实现已接入 webd 的会话归属、条件版本、SSE 与响应取消，不提供本机 shell 或工具执行。

## 产品与安装映射

- `dreamingwrt-ai-locald` → `/usr/sbin/`；依赖 json-c、SQLite、curl/TLS、libcrypto、pthread。
- `dreamingwrt-ai-rkllm` → `/usr/libexec/`；编译需 Rockchip **release-v1.3.1** 的 `rkllm.h`，运行时动态加载对应 `librkllmrt.so`。SDK/二进制遵守厂商许可，由 Build 独立取得和打包，不从竞品复制。
- `jmxd/files/ai-local/catalog.json` → `/usr/share/dreamingwrt/ai-local/catalog.json`。
- init 脚本 → `/etc/init.d/dreamingwrt-ai-local`。它仅启动轻量管理服务；不下载或加载模型。
- SQLite 状态：`/etc/dreamingwrt/ai-local/state.sqlite`；控制 socket：`/var/run/dreamingwrt-ai-local.sock`（0600，本机同 UID）。

## 硬件与目录

当前只实现 RK3588/RKLLM 1.3.1 的候选适配。尚无真机，随包 profile 的 `validated=false`，驱动/库指纹未知，模型目录为空。不能把这些字段改成虚假的已验证值来绕过门禁。取得真机、匹配驱动及转换模型后，完成本单规定的资源/ABI/生成/取消验证，再发布 profile。

已验证 profile 必须包含实际 `driver_version`（`/sys/module/rknpu/version`）、`library_sha256`（实际 `/usr/lib/librkllmrt.so`）及 `runtime=rkllm-1.3.1`。模型目录项字段：

```json
{"id":"operator-selected-id","name":"实际模型名称","format":"rkllm","runtime":"rkllm-1.3.1","profile_id":"rk3588-rkllm-1.3.1","template":"chatml","url":"https://operator-selected-model-url","sha256":"实际转换文件的64位小写SHA256","size_bytes":0,"required_memory_bytes":0,"context_tokens":4096,"max_tokens":512}
```

该示例不是可下载模型。大小、内存为零和非真实 hash 会被拒绝。当前模板适配范围是 ChatML 文字模型（例如经过相同 SDK 转换的 Qwen 系列）；不宣称通用模板、视觉、语音或结构化工具支持。本机请求正文上限 128 KiB，实际 token 上限由模型目录决定。不复用引擎 KV 历史：每回合从当前用户经过归属校验的上下文重建，避免用户间上下文串用。取消只向当前 response_id/actor 对应的 worker 发出 abort。

## 生命周期

模型目录取已挂载、可写的 ext3/ext4/btrfs/xfs/f2fs 数据卷；排除 rootfs、overlay、tmpfs。文件位于所选卷 `.dreamingwrt-ai/` 下。下载由管理服务线程持有，UI 关闭不取消。先检查空间，限制接收字节数，下载到任务 ID 所属的 `.part`，核对实际大小/SHA256，原子更名后登记已安装。取消删除本任务临时文件；不提供断点续传，重试重新下载。管理服务重启把未终结任务标 `interrupted`，卷在线时清理该任务临时文件。

配置保存只保存选择，不自动启停。启动/切换重新核实文件、内存与卷。旧模型在新文件校验和资源检查完成后才停止；新模型加载失败时保留原选择，服务显示失败，不假报回滚。生成期间拒绝停止/切换。只收到 worker 的加载成功事件才显示 ready；只看到 PID 不足以就绪。worker 随管理进程退出，由内核 PDEATHSIG 杀掉，避免遗留重型进程。

## HTTP

全部外层 `{ok,data}`，错误 `{ok:false,error:{code,message},status}`。默认读取 LOW，控制写沿用现有 MEDIUM 风险校验；不改变用户角色或系统工具权限。

- `GET /ai/local/status`、`GET /ai/local/models`（包括 models/volumes/config/task）
- `GET/PUT /ai/local/config`：model_id、volume_id、revision；冲突 409。
- `POST /ai/local/models/{id}/download`：volume_id；202 + task_id。
- `GET /ai/local/tasks/{id}`、`POST /ai/local/tasks/{id}/cancel`：只允许创建者。
- `POST /ai/local/service`：action=start/stop/switch、model_id、volume_id；202 + task_id。
- 现有 chat/stream：`execution_backend=local`、`local_model_id`；响应仍带实际来源/模型/response_id、unknown usage=null。取消继续用现有 responses 接口。

未部署、未执行真机推理。代码与编译结果不能代替 RK 驱动/ABI/模型与资源验证。
