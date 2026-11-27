# 运行速查

## 教师入口

克隆仓库后进入项目目录，运行：

```sh
./start.sh
```

| 菜单 | 老师会看到什么 |
| --- | --- |
| 查看已有离线演示 | 在浏览器查看已归档的线程读写、源码和修复回执。离线可用。 |
| 在本机快速复现 | 默认在真实内核中核对一次更新丢失与修复。也可选 Ubuntu 的操作交接或 BMA400 六字节读取。每次运行生成单独的报告。 |
| 按冻结条件复现代表成果 | 选择寄存器性质、两款原生 SPI 驱动的读取、Ubuntu 操作重放、BMA400 计时或局部证书。报告分别列出本次和历史结果。 |
| 安装工具测试自己的驱动 | 选择仅并发检错、仅可信优化或整套。工具写入用户目录，按自己的设备、采样记录或驱动源码使用。 |

推荐主机为 Ubuntu 24.04 或 Debian 13 的 x86_64 Linux。执行虚拟机案例时，当前账户需要能读写 `/dev/kvm`。首次会从镜像站下载约 1.04 GB 的 openEuler 映像，脚本验证压缩文件和解压后的磁盘，并只在独立的临时环境里运行。随后可用 `--offline` 复现同一案例。纯工具安装和看报告可以从空缓存离线开始。BMA400 的性能实验需要四个空闲 CPU 与可读写的 `/dev/vhost-vsock`。证明入口按需展开仓库内登记的 Coq 与 CompCert。

安装纯工具后，运行 `bin/kconc scan` 可直接扫描自己的驱动代码。运行 `bin/kconc optimize` 时提供自己的内核源码、Kbuild 构建目录和配置。工具核对实际编译命令并按需准备证明器。若移动了仓库，可通过 `KCONC_PROJECT` 指向新位置。

交互菜单会列出所选功能缺少的主机软件并征求安装许可；已有依赖时直接运行。首次应为下载、解压及运行记录在用户目录预留空间。可用 `XDG_CACHE_HOME` 和 `XDG_STATE_HOME` 分别指定缓存和结果目录。

用于脚本调用的等效命令：

```sh
./start.sh demo --offline
./start.sh quick update
./start.sh quick ubuntu
./start.sh quick opt
./start.sh reproduce opt-proof
./start.sh tools all
```

每次内核运行后，打开入口打印的 `index.html` 查看本机结果与原始记录。早期双线程 159/160 次重放与 40/40 次修复回归保存在历史演示里。

在仓库根目录用 Bash 和 Python 3.11 或更新版本运行。先准备在仓库外保存结果的父目录。每次 `--output` 都要指向一个尚不存在的子目录。

```bash
mkdir -p "$HOME/kconc-runs"
RUNS=$(mktemp -d "$HOME/kconc-runs/session.XXXXXX")
python3 -B kconc.py commands
```

## 离线演示

本版《离线演示.zip》解压后直接打开根目录 `index.html`。以下命令适用于另行取得的早期证据包。要校验那份归档、重新计算性能区间并生成报告，将 `KIT` 设为其中包含 `bundle.json` 的目录。

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

### 三轴读取重放

沿用上述普通软件板和工具链。先单独采集 X、Y、Z，再从一次新启动验证完整读取的顺序。使用构建说明中准备好的 `W` 和 `LINUX`。

```bash
cap=(python3 -B scripts/iio-path/capture.py)
"${cap[@]}" boot "$W/plain" train3 "$W/train3"
python3 -B kconc.py iio discover --capture "$W/train3" --out "$W/axes3.json"
"${cap[@]}" boot "$W/plain" ordered3 "$W/ordered3"
python3 -B kconc.py iio verify --reference "$W/axes3.json" --capture "$W/ordered3" \
  --order XYZ --keys xyz1 xyz2 xyz3 --out "$W/xyz.json"
python3 -B kconc.py iio verify --reference "$W/axes3.json" --capture "$W/ordered3" \
  --order ZYX --keys zyx1 zyx2 zyx3 --out "$W/zyx.json"
python3 -B scripts/iio-path/markers.py "$W/plain" "$W/axes3.json" "$LINUX" "$W/markers3"
"${cap[@]}" boot "$W/markers3" natural3 "$W/natural3"
python3 -B scripts/iio-path-overlap/checks/three.py passive --capture "$W/natural3" \
  --package "$W/markers3/package.json" --reference "$W/axes3.json" --out "$W/observed3.json"
```

`first_match` 指向普通板上第一个满足条件的组：Y、Z 均在 X 的 SPI 提交与开始传输之间进入驱动。若为空，这一批只记作自然观察。取得参考后，用同一内核构建的 `board-build` 收据封装主动包。若尚未生成该收据，直接从普通包运行下面的第一条命令。已有该收据时，从第二条开始。

```bash
python3 -B scripts/iio-path-overlap/build_board.py "$W/plain/package.json" \
  "$W/overlap-board" "$W/board-build" "$LLVM_BIN"
python3 -B scripts/iio-path-overlap/checks/prepare_three.py "$W/markers3" "$W/board-build" "$W/active3"
python3 -B scripts/replay-iio-overlap.py --package "$W/active3" --reference "$W/axes3.json" \
  --natural "$W/observed3.json" --out "$W/replayed3"
```

## 三线程寄存器更新

使用[构建说明](BUILDING.md#三线程寄存器更新的运行包)中的原内核构建身份、模块收据和只读盘。以下搜索运行三个线程各置位、清位一次的全部 90 种顺序，记录第一次超过两位同时占用的位置。下一条命令在新来宾中重放整批，与每一步的读写核对。

```bash
actors=(python3 -B kconc.py ram-regmap actors --build "$W/actor-module/receipt.json" --disk "$DISK")
"${actors[@]}" --threads 3 --max-switches 5 --budget 90 --max-active 2 --out "$RUNS/search"
"${actors[@]}" --replay "$RUNS/search" --out "$RUNS/search-replay"
```

更新丢失和互斥违例使用各自的原始与修复构建。以下命令运行两组性质对照，再把指定来宾串口中的一段执行整理成 HTML 见证。

```bash
python3 -B kconc.py ram-regmap exercise "$W/profiles.json" "$W/packages" "$RUNS/three-workers"
python3 -B kconc.py ram-regmap inspect "$RUNS/three-workers/mutex-base/reference/serial.log" \
  --property mutex --variant fault --order ACB --html-dir "$RUNS/witness"
```

## 在 Ubuntu 内核上重放操作交接

使用[Ubuntu 运行包](BUILDING.md#ubuntu-测试内核)。一次短测启动五个独立来宾，为 ABA、ABCA 各取参考并各重放一次，最后故意放错第三步。正式批共 43 次独立启动，两条正常路径各 1 次参考、20 次确认，另做 1 次错序对照。每条路径的门槛均为 20 次中至少 19 次完整匹配。

```bash
python3 -B kconc.py ram-regmap replay --package "$W/ubuntu-package" --output "$RUNS/ubuntu-smoke" --smoke
python3 -B kconc.py ram-regmap replay --package "$W/ubuntu-package" --output "$RUNS/ubuntu-formal"
```

从 `summary.json` 查看逐批结果，从各目录的 `serial.log` 查看协调者、工作线程及实际 regmap 读写。A→B→C→A 中的两个 A 属于同一工作线程的两次调用。

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
