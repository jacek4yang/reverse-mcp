# reverse-mcp：IDA 9.2 Native FFI 任务

## 目标

继续 **方案 2**：

`Rust -> Native FFI -> IDA Pro 9.2 SDK / idalib`

禁止退回 `idat`、IDAPython、Python bridge 或 mock 作为正式后端。
目标是无 GUI、真实 IDA 9.2、可供 MCP 多 Agent 使用。

## 当前优先级

先暂停 MCP 功能扩展，优先彻底打通 Native FFI：

1. 固定 IDA SDK 9.2 与 `idalib 0.7.2` 对应源码。
2. 定位 `insn_t` / `range_t` / Hex-Rays 类型变 opaque 的根因。
3. 不修改生成后的 bindings；修生成链、wrapper、bindgen/autocxx 配置或 FFI bridge。
4. 测试 LLVM/Clang 18/19/20/21，建立兼容矩阵并固定可用版本。
5. 对复杂 C++ 类型允许 `opaque handle + 极薄 extern "C" C++ accessor`，不要猜 ABI/layout。
6. 为跨 FFI 按值类型增加 `sizeof / alignof / offsetof` ABI 校验。
7. 最终真实验证 IDA 9.2：open -> analyze -> functions -> instruction -> xrefs -> strings -> Hex-Rays decompile -> rename/comment -> save -> reopen。

## DotSlash

引入 [DotSlash](https://dotslash-cli.com/) 管理可公开再分发的大型构建依赖，重点是固定 LLVM/Clang。

要求：

- Git 只保存 DotSlash 描述文件，不保存大型工具本体。
- 固定版本、URL、size、SHA256/BLAKE3。
- 使用 DotSlash cache，并自动设置 `LIBCLANG_PATH` / `PATH`。
- Windows 不依赖用户全局安装 LLVM。
- Rust 用 `rust-toolchain.toml` 固定，不交给 DotSlash。
- **不得**通过 DotSlash 分发 IDA runtime、Hex-Rays、license 或其他专有文件。

建议提供：

```text
cargo xtask setup
cargo xtask doctor
cargo xtask build
```

## 代码结构

逐步收敛为：

```text
reverse-ida-sys   # 唯一集中 unsafe/FFI/C++ bridge
reverse-ida       # 安全 Rust API
reverse-core
reverse-mcp
```

业务逻辑必须留在 Rust；C++ bridge 仅处理 IDA C++ ABI 隔离。

## 验收原则

- 不以 `cargo check` 为完成。
- 不用 mock 掩盖真实 FFI 未完成。
- 不因 bindgen/autocxx 困难再次询问是否切 Python。
- 每次失败：定位 -> 修复 -> 测试 -> 继续。
- 不提交任何 IDA 专有文件。

最终目标：

**REAL IDA PRO 9.2 HEADLESS NATIVE RUST FFI WORKING CORRECTLY.**
