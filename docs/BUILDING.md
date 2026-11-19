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

## 证明依赖与许可

PromisingComp 与 SEQ 使用各自独立的 opam 环境。前者锁定 Coq 8.13.1、OCaml 4.12.1 和 Paco 4.0.4，后者锁定 Coq 8.15.0、OCaml 4.14.2、Paco 4.1.2 和 ITree 4.0.0。驱动提供源码核验、完整构建、`coqchk` 与原算法的输入输出示例。[依赖锁](../configs/optimization/) · [驱动](../scripts/optimization/) · [证明工件](../proofs/)

MAccConc 使用 Apache-2.0，ImGui 使用 MIT，LLVM 使用带 LLVM 例外的 Apache-2.0，Linux 按源码文件许可分发。SEQ 派生证明保留 MIT 许可。PromisingComp 原工件及部分证明依赖的再分发条件尚未完整确认。CompCert、原论文工件、镜像和工具链须从各自来源取得并遵守对应许可。[上游来源](../configs/maccconc.lock.json) · [SEQ 原许可](../proofs/seq/UPSTREAM-LICENSE) · [CompCert 来源与版本](../proofs/bma400-noop/compcert-runtime.json)
