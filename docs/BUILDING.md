# 环境与构建

以下命令从仓库根目录在 WSL Debian 的 Bash 中运行，需要 Python 3.11 或更新版本。请将源码、镜像、工具链和构建结果放在仓库外。只需查看已有演示时，直接使用离线包和浏览器即可。[运行速查](RUNNING.md)

## 基础来宾与检错内核

宿主需要能访问 `/dev/kvm` 和 `/dev/vhost-vsock`。来宾用户空间采用 openEuler 24.03 LTS SP3 x86_64。`prepare.sh` 从官方源取得镜像并核验校验和，创建只读基础盘和独立可写层。

```bash
set -euo pipefail
sudo apt-get update
sudo apt-get install -y --no-install-recommends git qemu-system-x86 qemu-utils \
  curl cloud-image-utils python3 python3-pexpect openssh-client xz-utils
export LAB_DIR="$HOME/kconc-lab" LAB_SSH_PORT=2222
VM_CONTROL="$PWD/实验环境/openeuler-x86_64/lab.py"
bash 实验环境/openeuler-x86_64/prepare.sh
env -u LAB_KERNEL -u LAB_INITRD -u LAB_APPEND python3 "$VM_CONTROL" start
# 等发行版首次启动并开放 SSH 后执行，按提示输入初始密码
python3 实验环境/openeuler-x86_64/provision_guest.py
python3 实验环境/openeuler-x86_64/verify.py
python3 "$VM_CONTROL" stop
```

沿用 `LAB_DIR`。以下命令取得并核验 MAccConc `c17ba2d68167`、Linux `2fc2e45b0cd7` 和 LLVM `dc5c6d008f48`，按锁文件安装宿主依赖，构建用于检查并发路径的工具链及内核。[版本、补丁与依赖](../configs/maccconc.lock.json)

```bash
python3 scripts/maccconc-sources.py fetch --component all
python3 scripts/maccconc-sources.py verify --component all
mapfile -t packages < <(python3 -c 'import json; print(*json.load(open("configs/maccconc.lock.json"))["dependencies"]["debian_host_packages"], sep="\n")')
sudo apt-get install -y -- "${packages[@]}"
python3 scripts/build-maccconc.py llvm --jobs 4
python3 scripts/build-maccconc.py verify-llvm
python3 scripts/build-maccconc.py kernel --jobs 4
python3 scripts/prepare-maccconc-vm.py --source-lab "$LAB_DIR" --target-lab "$HOME/kconc-regmap-guest"
```

基础来宾关机后方可派生。场景来宾还需要 openEuler 内原生编译的执行器和探针。保留匹配的来宾磁盘依赖链、`bzImage`、未剥离的 `vmlinux`、`.config`、`System.map`、源码映射器和构建记录，启动时选择对应内核。原构建重放和跨构建修复回归各自读取登记的环境与见证。[来宾适配](../adapters/maccconc/) · [构建及运行探针](../scripts/) · [任务模板](../configs/tasks/)

## 为 IIO 读取者准备实验环境

在 Debian 宿主安装 `gcc`、`libc6-dev`、`binutils`、`cpio` 和 `e2fsprogs`。准备与上节同一版本的带 KCOV 访存记录的 Linux 源码和工具链，以及一份关机后的 openEuler qcow2。来宾的第二分区应为 ext4 根分区，并装有 Bash、kmod、mount 和 sha256sum。每次启动都将它只读挂载，原始观测写入另建的证据盘。

将 `DISK` 设为来宾磁盘的绝对路径。下面先选 KX022A；验证 BMA400 时将 `BOARD` 改为 `bma400_board`，在新目录独立登记。已有符合这些条件的构建时，使用其源码和 LLVM，将 `OBJ` 指向带有 `source` 链接、符号和 `Module.symvers` 的对象目录，从编译外设模块开始。

```bash
BOARD=kx022a_lab
BASE_CONFIG="$LAB_DIR/build/linux-2fc2e45b0cd7/.config"
LINUX=$(realpath "$(dirname "$BASE_CONFIG")/source")
LLVM_BIN="$LAB_DIR/toolchains/llvm-dc5c6d008f48/bin"
W=$(mktemp -d "$HOME/iio-read.XXXXXX")
OBJ="$W/obj"
mkdir "$OBJ" "$W/board"
cp "$BASE_CONFIG" "$OBJ/.config"
options=(IIO_KX022A_SPI IIO_KX022A)
if [[ $BOARD == bma400_board ]]; then options=(BMA400 BMA400_SPI); fi
"$LINUX/scripts/config" --file "$OBJ/.config" -e SPI -e IIO -e "${options[0]}" \
  -e REGULATOR -e GPIOLIB -e GPIO_SIM -e DEVTMPFS -e SYSFS -e KPROBE_EVENTS -d RANDOMIZE_BASE
export KCFLAGS='-fno-optimize-sibling-calls -mllvm -sanitizer-coverage-prune-blocks=false'
build=(make -C "$LINUX" O="$OBJ" ARCH=x86_64 LLVM="$LLVM_BIN/")
"${build[@]}" olddefconfig
for option in KCOV KCOV_EXT_RECORDS KCOV_MEMORY KCOV_INSTRUMENT_ALL REGMAP_SPI \
  KPROBE_EVENTS DEBUG_INFO DEVTMPFS VIRTIO_BLK EXT4_FS "${options[@]}"; do
  grep -qx "CONFIG_${option}=y" "$OBJ/.config"
done
"${build[@]}" -j4 bzImage modules_prepare
if [[ ! -s "$OBJ/Module.symvers" ]]; then cp "$OBJ/vmlinux.symvers" "$OBJ/Module.symvers"; fi
cp "kernel/iio-spi-board/stock/$BOARD.c" "$W/board/"
printf 'obj-m += %s.o\nKCOV_INSTRUMENT := n\n' "$BOARD" > "$W/board/Makefile"
"${build[@]}" M="$W/board" modules
gcc -static -Wall -Wextra -Werror -O2 scripts/iio-path/init.c -o "$W/init"
cap=(python3 -B scripts/iio-path/capture.py)
"${cap[@]}" register "$OBJ" "$W/board/$BOARD.ko" "$W/init" "$DISK" "$W/profile.json"
"${cap[@]}" prepare "$W/profile.json" "$W/plain"
```

普通包支持两个或三个轴的 sysfs 读取。下面先登记 X、Y 两条路径，再根据实际源码中的 `read_raw` 注册驱动入口和返回观察点。三轴实验复用这份内核、只读盘与软件板，按[三轴读取重放](RUNNING.md#三轴读取重放)单独采样和登记。[接口实现](../scripts/iio-path/) · [软件外设](../kernel/iio-spi-board/)

```bash
"${cap[@]}" boot "$W/plain" train "$W/train"
python3 -B kconc.py iio discover --capture "$W/train" --out "$W/discovery.json"
python3 -B scripts/iio-path/markers.py "$W/plain" "$W/discovery.json" "$LINUX" "$W/markers"
"${cap[@]}" boot "$W/markers" natural "$W/passive"
ORDER=XY
if [[ $BOARD == bma400_board ]]; then ORDER=YX; fi
python3 -B scripts/iio-path-overlap/checks/inspect_overlap.py \
  --capture "$W/passive" --package "$W/markers/package.json" \
  --reference "$W/discovery.json" --order "$ORDER" --out "$W/natural.json"
```

查看 `natural.json` 的 `pairs` 和 `strict_matches`。此版本要求在同一批八对自然读取中，该方向恰有一对显示“第一笔已提交、第二个读者已进入、第一笔才开始传输”。符合这一条件后保留整批记录和参考，使用软件 SPI 控制器的准备回调生成主动包。自然采样可能得到零对或多对，这样的批次保留为观察记录。每次新采样、组包及启动均使用独立目录。

```bash
python3 -B scripts/iio-path-overlap/build_board.py "$W/plain/package.json" \
  "$W/overlap-board" "$W/board-build" "$LLVM_BIN"
python3 -B scripts/iio-path-overlap/checks/prepare.py "$W/markers" "$W/board-build" "$ORDER" "$W/active"
python3 -B scripts/replay-iio-overlap.py --package "$W/active" --reference "$W/discovery.json" \
  --natural "$W/natural.json" --out "$W/replay"
```

已保存的历史包使用各自登记的板、内核和启动程序；用公开源码重建时按新产物的身份重新采样。完整读取的顺序核对、冷启动和离线复核命令见[运行速查](RUNNING.md)。

## 三线程寄存器更新的运行包

完整操作搜索使用已登记的原实验内核。将 `KERNEL_RECEIPT` 设为上文 `build-maccconc.py kernel` 生成的 `build-result.json`，其构建系列为 `linux-original`。`DISK` 指向关机后的只读 openEuler qcow2。工作目录建在仓库外。

```bash
W=$(mktemp -d "$HOME/ram-regmap.XXXXXX")
python3 -B scripts/register-artifact.py --receipt "$KERNEL_RECEIPT" --output "$W/detection.json"
python3 -B scripts/build-regmap-actors.py --identity "$W/detection.json" --out "$W/actor-module"
```

性质对照使用更新丢失、互斥两组各自的原始和修复内核。`UPDATE_REPAIR_RECEIPT` 与 `MUTEX_REPAIR_RECEIPT` 是[修复内核构建工具](../scripts/build-k11-kernel.py)在 `rmw` 与 `mutex` 两个场景生成的 `build-result.json`。登记程序会从这两份收据查找并核对各自的原始构建。`LLVM_BIN` 与 `CLANG_SHA256` 取自登记的原实验工具链。

```bash
gcc -static -O2 scripts/iio-path/init.c -o "$W/init"
python3 -B scripts/register-regmap-three.py --update-repair "$UPDATE_REPAIR_RECEIPT" \
  --mutex-repair "$MUTEX_REPAIR_RECEIPT" --disk "$DISK" --init "$W/init" --out "$W/profiles.json"
python3 -B scripts/build-regmap-three-check.py "$W/profiles.json" "$W/packages" \
  --clang "$LLVM_BIN/clang" --clang-sha256 "$CLANG_SHA256"
```

## Ubuntu 测试内核

Ubuntu 路径使用发行版源码包 `linux 6.8.0-31.31` 和仓内的[实验配置](../scripts/regmap-central/ubuntu.config)。在 x86_64 Linux 宿主准备 GCC、make、flex、bison、bc、libssl-dev、libelf-dev、dpkg-dev、binutils、kmod 和静态 libc。运行需要 QEMU/KVM 及上述只读来宾盘。取得 Ubuntu 官方源码包的 `.dsc` 和其中列出的源档，放在同一目录，把 `UBUNTU_DSC` 指向该文件。

```bash
W=$(mktemp -d "$HOME/ubuntu-regmap.XXXXXX")
bash scripts/regmap-central/build-ubuntu.sh "$UBUNTU_DSC" "$W/ubuntu"
python3 -B scripts/regmap-central/prepare.py --kernel-build "$W/ubuntu/obj" \
  --disk "$DISK" --output "$W/ubuntu-package"
```

构建脚本先核对 `.dsc` 的固定哈希和配套源码档的哈希，再解包编译。已有用这份源码及配置完成的 Kbuild 时，可以把 `--kernel-build` 指向其输出，直接准备运行包。每份包单独登记内核、重编模块、initrd 和磁盘身份，运行时与来宾实际身份核对。这份配置关闭了 `CONFIG_PROC_SYSCTL`，各次独立 QEMU 启动使用来宾生成的随机标识区分，来源记录在串口中。[运行速查](RUNNING.md#在-ubuntu-内核上重放操作交接)

## BMA400 的源码证书和目标文件

先按下表将变量设为本机的实际绝对路径。对象构建驱动重新检查证书、配置和工具指纹，并用正常优化配置分别编译原版与优化版。[规则与输入指纹](../configs/optimization/bma400-six-byte.json) · [证明环境指纹](../proofs/bma400-noop/compcert-runtime.json)

| 变量 | 外部输入 |
| --- | --- |
| `LINUX_ARCHIVE` | 原始 Linux 源码 tar，SHA-256 为 `cdcf5373ee4a0c43c11ea3a1053d54534a8048f16057614f954f542f58990709`。 |
| `KERNEL_CONFIG`、`LLVM_BIN` | 与规则指纹一致的正常优化内核配置文件和含指定 Clang 的 LLVM `bin` 目录。 |
| `COMPCERT`、`COQ_BIN` | CompCert v3.13 的 x86_64-linux 构建树，以及 Coq 8.15.0 的 `bin`。保留 `clightgen`、编译好的证明库和 Coq 工具。证明环境使用 OCaml 4.14.2 与 Menhir 20220210。 |

```bash
mkdir -p "$HOME/kconc-builds"
BUILD_RUN=$(mktemp -d "$HOME/kconc-builds/build.XXXXXX")
python3 -B scripts/optimization/build_bma400_objects.py \
  --archive "$LINUX_ARCHIVE" --config "$KERNEL_CONFIG" --llvm-bin "$LLVM_BIN" \
  --compcert "$COMPCERT" --coq-bin "$COQ_BIN" --output "$BUILD_RUN/objects"
```

成功时 `objects/result.json` 的 `decision` 为 `objects_verified`，其中列出两版 `drivers/base/regmap/regmap.o` 的来源及指纹。已有单独保存的可信回执摘要时，可用 `--verify "$BUILD_RUN/objects/result.json" --expected-binding-sha256 "$SAVED_RECEIPT_SHA256"` 代替上述构建参数，只读复核产物。

## 计时内核

用上一步的证书包分别生成原版、仅缓存指针和跳过空回调的编译单元。下面的命令定位 BMA400 计时源码生成器，将每种实现装入独立源码副本，按同一份正常配置构建三份内核。

```bash
prepare_timing=(kernel/*-bma400/prepare.py)
test "${#prepare_timing[@]}" -eq 1 && test -f "${prepare_timing[0]}"
package="$BUILD_RUN/objects/verified-source/package"
for variant in reference cached optimized; do
  unit=drivers/base/regmap/regmap.c
  tree="$BUILD_RUN/linux-$variant"
  dest="$BUILD_RUN/build-$variant"
  python3 -B "${prepare_timing[0]}" --package "$package" \
    --variant "$variant" --output "$BUILD_RUN/timing-$variant"
  mkdir "$tree" "$dest"
  tar -xf "$LINUX_ARCHIVE" -C "$tree"
  cp "$BUILD_RUN/timing-$variant/$unit" "$tree/$unit"
  cp "$KERNEL_CONFIG" "$dest/.config"
  build=(make -C "$tree" O="$dest" ARCH=x86_64 LLVM="$LLVM_BIN/" HOSTCC=gcc HOSTCXX=g++ KCFLAGS= KCPPFLAGS=)
  "${build[@]}" olddefconfig
  cmp "$KERNEL_CONFIG" "$dest/.config"
  "${build[@]}" -j4 bzImage
done
```

功能核对使用独立观察构建。正式计时关闭观察器，使用四 vCPU 来宾的 CPU 2。完整配对实验还需对应的来宾镜像与采集脚本，并按演示包中的 `kit/perf/protocol.json` 固定宿主亲和性、启动顺序和批次。

## 准备驱动源码与实际编译记录

按前表准备原始源码归档、LLVM、CompCert 和 Coq。推广后的读取规则使用仓库中的[加速度计驱动配置](../configs/optimization/sixbyte-x86_64.config)。在 WSL 的 Linux 文件系统上解包干净的源码，使用独立的 Kbuild 输出目录，使分析器可以核对驱动实际使用的头文件和编译参数。

```bash
mkdir -p "$HOME/kconc-builds"
SCAN_RUN=$(mktemp -d "$HOME/kconc-builds/scan.XXXXXX")
KERNEL="$SCAN_RUN/linux"
BUILD="$SCAN_RUN/obj"
mkdir "$KERNEL" "$BUILD"
tar -xf "$LINUX_ARCHIVE" -C "$KERNEL"
cp configs/optimization/sixbyte-x86_64.config "$BUILD/.config"
export KBUILD_BUILD_VERSION=1 KBUILD_BUILD_TIMESTAMP="2026-11-19 00:00:00 UTC"
export KBUILD_BUILD_USER=lab KBUILD_BUILD_HOST=api-frame
build=(make -C "$KERNEL" O="$BUILD" ARCH=x86_64 LLVM="$LLVM_BIN/" HOSTCC=gcc HOSTCXX=g++ KCFLAGS= KCPPFLAGS=)
"${build[@]}" olddefconfig
cmp configs/optimization/sixbyte-x86_64.config "$BUILD/.config"
"${build[@]}" -j4 bzImage modules_prepare
```

保留源码、原始配置和对象目录，在同一 Bash 会话中执行[扫描和生成补丁](RUNNING.md#扫描驱动并生成读取补丁)。[软件 SPI 外设模块](../kernel/sixbyte-boards/)提供内核功能验证所用的模拟设备。

## 证明依赖与许可

PromisingComp 与 SEQ 使用各自独立的 opam 环境。前者锁定 Coq 8.13.1、OCaml 4.12.1 和 Paco 4.0.4，后者锁定 Coq 8.15.0、OCaml 4.14.2、Paco 4.1.2 和 ITree 4.0.0。驱动提供源码核验、完整构建、`coqchk` 与原算法的输入输出示例。[依赖锁](../configs/optimization/) · [驱动](../scripts/optimization/) · [证明工件](../proofs/)

MAccConc 使用 Apache-2.0，ImGui 使用 MIT，LLVM 使用带 LLVM 例外的 Apache-2.0，Linux 按源码文件许可分发。SEQ 派生证明保留 MIT 许可。PromisingComp 原工件及部分证明依赖的再分发条件尚未完整确认。CompCert、原论文工件、镜像和工具链须从各自来源取得并遵守对应许可。[上游来源](../configs/maccconc.lock.json) · [SEQ 原许可](../proofs/seq/UPSTREAM-LICENSE) · [CompCert 来源与版本](../proofs/bma400-noop/compcert-runtime.json)
