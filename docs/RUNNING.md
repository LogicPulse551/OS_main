# 运行速查

在仓库根目录用 Bash 和 Python 3.11 或更新版本运行。先准备在仓库外保存结果的父目录。每次 `--output` 都要指向一个尚不存在的子目录。

```bash
mkdir -p "$HOME/kconc-runs"
RUNS=$(mktemp -d "$HOME/kconc-runs/session.XXXXXX")
python3 -B kconc.py commands
```

## 离线演示

完整解压单独提供的演示包。直接打开 `demo/index.html` 可浏览已有页面。要校验归档、重新计算性能区间并生成报告，将 `KIT` 设为解压后包含 `bundle.json` 的目录。

```bash
KIT=/实际路径/kit
python3 -B kconc.py demo "$KIT/bundle.json" --output "$RUNS/demo"
```

打开 `$RUNS/demo/index.html`，从事件进入源码，或查看修复回归、优化源码和计时结果。分享时复制整个输出目录。

| 要复核的结果 | 记录位置 |
| --- | --- |
| 原构建 159/160 | 完整实验档案中原构建稳定性验收表的 `counts.full_matches`、`counts.actual_replay_attempts` 和 `counts.path_diverged`。演示包附其中一个用例的原始与重执行记录。 |
| 修复构建 40/40 | `kit/repair/acceptance.json` 的 `summary.current` 记录正式批次，`summary.historical` 保存早期批次。 |
| 优化与计时 | `kit/opt/certificate.json` 绑定两版源码。`kit/perf/protocol.json` 和 `kit/perf/ledger.json` 给出协议和各次启动，重新计算的结果在输出的 `summary.json` 中。 |

## 从原始执行生成源码报告

`BUNDLE` 指向完整见证目录，`BUILD_RECORD` 指向匹配的源码构建清单 JSON，`SOURCE_ROOT` 指向该次内核源码树或快照的根目录。请先把三个变量设为本机的实际路径。

```bash
python3 -B kconc.py report --bundle "$BUNDLE" --build-record "$BUILD_RECORD" \
  --source-root "$SOURCE_ROOT" --output "$RUNS/original"
```

打开输出的 `index.html`。查看一次已发生的重执行时，在命令中加 `--attempt "$ATTEMPT"` 并换用新的输出目录。`ATTEMPT` 指向原批次中的尝试目录，需保留其父目录的批次记录。

## 运行来宾任务或重新生成优化源码

在 WSL Debian 准备匹配的来宾环境或证明工具链。以查询来宾状态为例，复制模板后，填写 `runtime.lab_dir` 和 `runtime.ssh_port`。[环境与构建](BUILDING.md)

```bash
cp configs/tasks/env-status.example.json "$RUNS/status.json"
# 在 status.json 中填好本机实验目录和端口
python3 -B kconc.py validate "$RUNS/status.json"
python3 -B kconc.py run "$RUNS/status.json" --output "$RUNS/vm-status"
python3 -B kconc.py result "$RUNS/vm-status"
```

生成 BMA400 专用源码时，使用以下模板，将清单中的五个路径改为固定 Linux 源码树、正常优化配置、Clang、CompCert 构建树和 Coq 的 `bin` 目录。相对路径按清单所在目录解析。

```bash
cp configs/tasks/optimize-bma400.example.json "$RUNS/bma400.json"
# 在 bma400.json 的 inputs 中填好五个路径
python3 -B kconc.py run "$RUNS/bma400.json" --output "$RUNS/bma400"
```

成功时两版源码与证书位于 `source/package/`。输入指纹失配且原源码可读时，命令返回 3，原因在 `source/result.json`。其余任务模板分别提供来宾初始化、候选导出、实际命中核对、原构建重放、修复回归、预算搜索和见证缩减。[任务模板](../configs/tasks/)
