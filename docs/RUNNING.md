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

## 识别并重放两次传感器读取

在 WSL Debian 中操作。按[环境与构建](BUILDING.md)准备一款软件 SPI 板的普通采样包，将它的目录记为 `NORMAL_PACKAGE`。以下命令训练一次，再用另一次冷启动分别核对 X→Y 和 Y→X。

```bash
python3 -B scripts/iio-path/capture.py boot "$NORMAL_PACKAGE" train "$RUNS/train"
python3 -B kconc.py iio discover --capture "$RUNS/train" --out "$RUNS/axes.json"
python3 -B scripts/iio-path/capture.py boot "$NORMAL_PACKAGE" xy-first "$RUNS/ordered"
python3 -B kconc.py iio verify --capture "$RUNS/ordered" --reference "$RUNS/axes.json" \
  --order XY --keys xy1 xy2 --out "$RUNS/xy.json"
python3 -B kconc.py iio verify --capture "$RUNS/ordered" --reference "$RUNS/axes.json" \
  --order YX --keys yx1 yx2 --out "$RUNS/yx.json"
```

要重放读取内部的重叠，请使用同一组已登记的输入。`REPLAY_PACKAGE` 是带一次准备窗口的软件板运行包，`AXES` 是对应驱动的轴特征登记，`NATURAL` 是从普通板采样中核实了目标交错的参考 JSON。三者的生成方式见[构建说明](BUILDING.md)。

```bash
python3 -B scripts/replay-iio-overlap.py --package "$REPLAY_PACKAGE" \
  --reference "$AXES" --natural "$NATURAL" --out "$RUNS/replayed"
```

每次执行都会冷启动一套来宾。`verdict.json` 给出进入驱动、提交、开始和完成传输的实际事件，以及两次读取的结果。`negative.json` 记录三个改错中间证据的对照。已有原始记录时，在同一命令中加 `--check-only "$SAVED_SLOT"` 并更换输出目录，即可离线复核。

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

## 扫描驱动并生成读取补丁

在完成[驱动源码与编译记录的准备](BUILDING.md#准备驱动源码与实际编译记录)后使用此命令。`KERNEL` 是原始内核源码，`BUILD` 是对应 Kbuild 对象目录，`LLVM_BIN`、`COMPCERT` 和 `COQ_BIN` 指向匹配的工具链。

```bash
python3 -B kconc.py optimize --policy init-n \
  --kernel "$KERNEL" --build-dir "$BUILD" --config "$BUILD/.config" \
  --scope drivers/iio/accel --clang "$LLVM_BIN/clang" \
  --coq-bin "$COQ_BIN" --compcert "$COMPCERT" --output "$RUNS/driver-reads"
```

`scan.json` 逐处列出调用和准入原因。`result.json` 的 `decision` 为 `emit_guarded_sites` 时，`admitted` 给出改写位置，`proof` 绑定局部证书，`linux.patch` 是相对于原始源码的补丁。`keep_original` 表示本次输出沿用原调用，失配原因可在 `reasons` 中查看。

`init-n` 在格式就绪时为每个新对象选定资格。启动参数 `kconc.observe_callbacks=1` 保留逐次回调，供功能核对使用。对照每次读取判断的实现可选 `valid-n`，每次运行使用新的输出目录。其余已实现的策略可用 `python3 -B kconc.py optimize --help` 查看。
