# IDA 多版本发现与选择

## 目标

重构 IDA 路径发现，支持同机多个 IDA Pro 版本，并允许 Agent 自主选择。

## 发现顺序

1. `--ida-dir`
2. `IDADIR`
3. `ida-config.json`
   - Windows: `%APPDATA%\Hex-Rays\IDA Pro\ida-config.json`
   - Linux/macOS: `~/.idapro/ida-config.json`
4. OS 原生发现
   - Windows: Uninstall Registry / App registration
   - macOS: LaunchServices、`/Applications`、`~/Applications`
   - Linux: `.desktop`、PATH、`/opt`
5. 常见默认路径
6. `ida.reg` 仅作为低优先级 hint

每个候选必须真实验证：
- IDA 版本
- 架构
- `ida` / `idalib`
- Hex-Rays / decompiler
- reverse-mcp backend 兼容性

建议：

```rust
struct IdaInstallation {
    root: PathBuf,
    version: Version,
    arch: Arch,
    idalib: PathBuf,
    ida: PathBuf,
    decompilers: Vec<Decompiler>,
    source: DiscoverySource,
}
```

实现：

```rust
discover_all() -> Vec<IdaInstallation>
resolve(requirement: IdaRequirement) -> Result<IdaInstallation>
validate(path: &Path) -> Result<IdaInstallation>
```

## Agent 选择

增加 MCP：

- `ida_installations`
- `ida_capabilities`

`ida_db.open` 支持：

```json
{"path":"...","ida_version":"9.2"}
{"path":"...","ida_version":"latest"}
{"path":"...","ida_version":">=9.2,<9.4"}
```

省略版本时自动选择。

规则：
1. Agent 明确指定时严格匹配
2. 已有 IDB 优先兼容版本
3. 按 processor/decompiler/capability 筛选
4. 默认最高“已安装 + backend 已验证”的版本
5. 不兼容时返回候选，不偷偷 fallback

一个 DB session 创建后固定 backend。

## Backend 版本化

不要假设 9.2 FFI 可安全驱动其他版本。

```text
reverse-ida
├── backend-9_2
├── backend-9_3
└── ...
```

v0.1 只实现并验证 `backend-9_2`，其他版本仍需发现并标记：

```text
IDA 9.2  installed + backend ready
IDA 9.3  installed + backend unavailable
```

## CLI

增加：

```text
reverse-mcp doctor
reverse-mcp ida list
```

显示安装来源、版本、runtime、decompiler、backend 状态。

## 构建

继续使用 DotSlash 固定 LLVM/Clang 等公开构建依赖。

禁止通过 DotSlash、Git 或 Release 分发 IDA runtime、Hex-Rays decompiler、license 等专有文件。
