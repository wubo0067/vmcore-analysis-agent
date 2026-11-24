#!/usr/bin/env bash
#
# check_kernel_env.sh
# 检查 RHEL 9 系 (RHEL / Rocky / Alma) 的内核开发与调试环境:
#   1. 能否编译当前内核的外部模块 (.ko)
#   2. 能否用 crash 分析 vmcore
#
# 用法:
#   ./check_kernel_env.sh [选项]
#     -k <release>  检查指定内核版本 (默认: uname -r)
#     -c <vmcore>   校验 vmcore 的内核版本是否与目标版本一致
#     -b            实际编译一个 hello.ko 做验证
#     -i            用 dnf 自动安装缺失的包 (需 root),装完自动复查
#     -h            显示帮助
#
# 退出码: 0 = 编译与 crash 环境均就绪, 1 = 有缺失项

set -u

RUNNING="$(uname -r)"
KREL="$RUNNING"
ARCH="$(uname -m)"
VMCORE=""
DO_BUILD=0
DO_INSTALL=0

# ---------- 内核变体归一化 ----------
# RHEL 的调试/实时变体内核 uname -r 带后缀, 例如:
#   5.14.0-362.24.1.el9_3.x86_64+debug     (kernel-debug)
#   5.14.0-362.24.1.el9_3.x86_64+rt        (kernel-rt)
#
# 拼 RPM 包名时必须去掉后缀:
#   kernel-debuginfo-<base>         普通内核
#   kernel-debug-debuginfo-<base>   调试内核 (包名多一层 debug-, 路径不带 +debug)
#   kernel-rt-debuginfo-<base>      实时内核
#
# 但查找 debuginfo 安装路径时反而必须保留后缀:
#   /usr/lib/debug/lib/modules/<KREL>/vmlinux
#
# 这两者方向相反, 混用会全部误判, 所以下面分别保存。
VARIANT=""                      # "" | debug | rt | rtdebug
KREL_BASE=""                    # 用于拼包名

# -k 会改 KREL, 所以归一化必须放在参数解析之后做, 封装成函数便于随时重算。
normalize_release() {
    VARIANT=""
    KREL_BASE="$KREL"
    case "$KREL" in
        # 必须放在 *+debug 之前: +rt+debug 同时匹配 *+rt* 和 *+debug,
        # 若先匹配 *+debug 会得到 base=...+rt 与 VARIANT=debug, 两者都错。
        *+rt+debug)
            VARIANT="rtdebug"
            KREL_BASE="${KREL%+debug}"
            KREL_BASE="${KREL_BASE%+rt}"
            ;;
        *+debug)
            VARIANT="debug"
            KREL_BASE="${KREL%+debug}"
            ;;
        # kernel-rt 的 release 形如 5.14.0-362.el9_3.x86_64+rt
        *+rt)
            VARIANT="rt"
            KREL_BASE="${KREL%+rt}"
            ;;
    esac
}

usage() {
    sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

while getopts "k:c:bih" opt; do
    case "$opt" in
        k) KREL="$OPTARG" ;;
        c) VMCORE="$OPTARG" ;;
        b) DO_BUILD=1 ;;
        i) DO_INSTALL=1 ;;
        *)
            usage
            ;;
    esac
done

# -k 可能覆盖了 KREL, 这里统一归一化一次
normalize_release

# ---------- 输出辅助 ----------
if [ -t 1 ]; then
    G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; N=$'\e[0m'
else
    G=""; R=""; Y=""; N=""
fi

PASS=0; FAIL=0; WARN=0
BUILD_OK=1      # 能否编译 ko
CRASH_OK=1      # 能否用 crash 分析
MISSING=()      # 缺失且可用 dnf 安装的包

ok()   { echo "  ${G}[ OK ]${N} $*"; PASS=$((PASS + 1)); }
bad()  { echo "  ${R}[FAIL]${N} $*"; FAIL=$((FAIL + 1)); }
warn() { echo "  ${Y}[WARN]${N} $*"; WARN=$((WARN + 1)); }
info() { echo "  [INFO] $*"; }
sec()  { echo; echo "== $* =="; }

# 标记某项失败影响哪项能力: build | crash | opt
fail_cap() {
    case "$1" in
        build) BUILD_OK=0 ;;
        crash) CRASH_OK=0 ;;
    esac
}

# check_pkg <rpm名> <build|crash|opt>
check_pkg() {
    local pkg="$1" cap="$2"
    if rpm -q "$pkg" >/dev/null 2>&1; then
        ok "$(rpm -q "$pkg")"
    elif [ "$cap" = "opt" ]; then
        warn "$pkg 未安装 (可选)"
    else
        bad "$pkg 未安装"
        fail_cap "$cap"
        MISSING+=("$pkg")
    fi
}

# check_path <-d|-f|-e> <路径> <build|crash|opt>
check_path() {
    local flag="$1" path="$2" cap="$3"
    if test "$flag" "$path"; then
        ok "$path"
    elif [ "$cap" = "opt" ]; then
        warn "$path 不存在 (可选)"
    else
        bad "$path 不存在"
        fail_cap "$cap"
    fi
}

# ---------- 1. 基本信息 ----------
sec "基本信息"
if [ -r /etc/os-release ]; then
    # 用子 shell 读取: /etc/os-release 里也有 VARIANT= 变量 (如 VARIANT="Server"),
    # 直接 source 会覆盖上面算好的内核变体, 导致后面的包名判断全部错乱。
    OS_PRETTY=$( (. /etc/os-release && echo "${PRETTY_NAME:-unknown}") 2>/dev/null )
    info "发行版:   ${OS_PRETTY:-unknown}"
fi
info "运行内核: $RUNNING"
info "检查目标: $KREL"
if [ -n "$VARIANT" ]; then
    info "内核变体: $VARIANT (包名以 $KREL_BASE 为准, debuginfo 路径仍用 $KREL)"
fi
if [ "$KREL" != "$RUNNING" ]; then
    warn "检查目标与运行内核不同, 将跳过 kdump 运行态检查"
fi

# ---------- 2. RPM 包 ----------
sec "RPM 包"

# 按变体决定该装哪个 debuginfo。
# 普通内核     -> kernel-debuginfo-$KREL_BASE
# 调试内核     -> kernel-debug-debuginfo-$KREL_BASE
#                (注意: 不是 kernel-debuginfo-<...+debug>, 那个名字不存在)
# 实时内核     -> kernel-rt-debuginfo-$KREL_BASE
# rt+debug     -> kernel-rt-debug-debuginfo-$KREL_BASE
case "$VARIANT" in
    debug)   DBG_PKG="kernel-debug-debuginfo-$KREL_BASE" ;;
    rt)      DBG_PKG="kernel-rt-debuginfo-$KREL_BASE" ;;
    rtdebug) DBG_PKG="kernel-rt-debug-debuginfo-$KREL_BASE" ;;
    *)       DBG_PKG="kernel-debuginfo-$KREL_BASE" ;;
esac

check_pkg "kernel-devel-$KREL_BASE"               build
check_pkg gcc                                     build
check_pkg make                                    build
check_pkg elfutils-libelf-devel                   build
check_pkg "$DBG_PKG"                              crash
check_pkg "kernel-debuginfo-common-$ARCH-$KREL_BASE" crash
check_pkg crash                                   crash
check_pkg "kernel-core-$KREL_BASE"                opt
check_pkg "kernel-modules-$KREL_BASE"             opt
check_pkg kexec-tools                             opt
# 只有 crash 自身崩溃、需要用 gdb 跟进去时才需要; 它是 noarch/x86_64 的
# 普通包, 装在 AppStream 的 debug 仓库里, 不属于 kernel 系。
check_pkg crash-debuginfo                         opt
# 排查 kdump/kexec 自身问题(如 makedumpfile 失败)时用
check_pkg kexec-tools-debugsource                 opt

if [ -n "$VARIANT" ] && [ "$VARIANT" != "rt" ] && [ "$VARIANT" != "rtdebug" ]; then
    info "已安装 debug 内核变体: $(rpm -q "kernel-debug-$KREL_BASE" 2>/dev/null | grep -v 'is not installed' || echo '未安装')"
    info "  vmcore 来自 debug 变体, 必须装 $DBG_PKG 才能用 crash 打开"
else
    if rpm -q "kernel-debug-$KREL_BASE" >/dev/null 2>&1; then
        info "已安装 debug 内核变体: $(rpm -q "kernel-debug-$KREL_BASE") (仅当 vmcore 来自 debug 内核时才需要其 debuginfo)"
    else
        info "kernel-debug-$KREL_BASE 未安装 (这是调试内核变体, 一般不需要)"
    fi
fi

# ---------- 3. 关键文件 ----------
sec "关键文件"
# kernel-devel 安装路径不含变体后缀, 即便是 debug 内核也是 /usr/src/kernels/<base>
KSRC="/usr/src/kernels/$KREL_BASE"
KBUILD="/lib/modules/$KREL_BASE/build"
# debuginfo 安装路径反而含完整 release (含 +debug)
DBGDIR="/usr/lib/debug/lib/modules/$KREL"
VMLINUX="$DBGDIR/vmlinux"

check_path -d "$KSRC"                  build
check_path -f "$KSRC/Module.symvers"   build
check_path -f "$KSRC/.config"          build
check_path -e "$KBUILD"                build
check_path -f "$VMLINUX"               crash

# 变体不一致时最容易踩的坑: debuginfo 装了但路径找错了
if [ -n "$VARIANT" ] && [ ! -f "$VMLINUX" ]; then
    ALT=$(find /usr/lib/debug/lib/modules -maxdepth 2 -name vmlinux 2>/dev/null | grep -F "$KREL_BASE" | head -1)
    if [ -n "$ALT" ]; then
        warn "vmlinux 不在预期路径, 但找到了: $ALT"
        info "  这可能说明安装的内核 release 与 $KREL 的变体后缀不同"
    fi
fi

if [ -f "$VMLINUX" ]; then
    if command -v readelf >/dev/null 2>&1; then
        if readelf -S -W "$VMLINUX" 2>/dev/null | grep -q '\.debug_info'; then
            ok "vmlinux 含 DWARF 调试信息 ($(du -h "$VMLINUX" | cut -f1))"
        else
            bad "vmlinux 不含 .debug_info, 不能用于 crash"
            fail_cap crash
        fi
    else
        warn "未找到 readelf, 跳过 vmlinux 调试信息检查"
    fi

    # 关键: vmcore 与 vmlinux 必须是同一次构建。
    # 只要 kernel 包被升级过, 旧 debuginfo 就不匹配, crash 会报
    # "vmlinux and vmcore do not match"。
    BKREL=$(strings -a "$VMLINUX" 2>/dev/null | grep -m1 -E '^5\.14\.[0-9]+-[0-9.]+\.el[0-9]+' || true)
    if [ -n "$BKREL" ]; then
        if [ "$BKREL" = "$KREL" ]; then
            ok "vmlinux 内嵌 release 与目标一致: $BKREL"
        else
            bad "vmlinux 内嵌 release ($BKREL) 与目标 ($KREL) 不一致"
            fail_cap crash
        fi
    fi
fi

if [ -d "$DBGDIR" ]; then
    nko=$(find "$DBGDIR" -name '*.ko.debug' 2>/dev/null | wc -l)
    if [ "$nko" -gt 0 ]; then
        ok "模块 debuginfo: $nko 个 .ko.debug"
    else
        warn "未找到 .ko.debug, crash 中 mod -S 无法加载模块符号"
    fi
fi

# ---------- 4. 编译器版本 ----------
sec "编译器"
if command -v gcc >/dev/null 2>&1; then
    info "本机 gcc:   $(gcc --version | head -1)"
    KCOMP=$(grep -h LINUX_COMPILER "$KSRC/include/generated/compile.h" 2>/dev/null | cut -d'"' -f2)
    if [ -n "$KCOMP" ]; then
        info "内核编译器: $KCOMP"
        kmaj=$(echo "$KCOMP" | grep -oE ' [0-9]+\.[0-9]+\.[0-9]+' | head -1 | tr -d ' ' | cut -d. -f1)
        lmaj=$(gcc -dumpversion | cut -d. -f1)
        if [ -n "$kmaj" ] && [ "$kmaj" != "$lmaj" ]; then
            warn "gcc 主版本不同 (内核 $kmaj / 本机 $lmaj), 编译 ko 可能告警或失败"
        else
            ok "gcc 主版本与内核编译器一致 ($lmaj)"
        fi
    else
        info "无法读取内核编译器信息 (kernel-devel 未装?)"
    fi
else
    bad "gcc 未安装"
    fail_cap build
fi

# ---------- 5. crash / kdump ----------
sec "crash 与 kdump"
if command -v crash >/dev/null 2>&1; then
    info "$(crash --version 2>/dev/null | head -1)"
fi
if [ "$KREL" = "$RUNNING" ]; then
    if grep -q 'crashkernel=' /proc/cmdline; then
        ok "cmdline 含 $(grep -o 'crashkernel=[^ ]*' /proc/cmdline)"
    else
        warn "cmdline 未配置 crashkernel, 无法产生 vmcore"
    fi
    if systemctl is-active --quiet kdump 2>/dev/null; then
        ok "kdump 服务运行中"
    else
        warn "kdump 服务未运行 (systemctl enable --now kdump)"
    fi
    if [ "$(cat /sys/kernel/kexec_crash_loaded 2>/dev/null)" = "1" ]; then
        ok "crash kernel 已加载"
    else
        warn "crash kernel 未加载"
    fi
else
    info "检查目标不是运行内核, 跳过"
fi

# ---------- 6. vmcore 校验 ----------
if [ -n "$VMCORE" ]; then
    sec "vmcore 校验"
    if [ ! -r "$VMCORE" ]; then
        bad "无法读取 $VMCORE"
        fail_cap crash
    elif ! command -v crash >/dev/null 2>&1; then
        bad "crash 未安装, 无法校验"
        fail_cap crash
    else
        VOSR=$(crash --osrelease "$VMCORE" 2>/dev/null | tail -1)
        if [ -z "$VOSR" ]; then
            warn "crash --osrelease 未返回结果, 请手动确认 vmcore 版本"
        elif [ "$VOSR" = "$KREL" ]; then
            ok "vmcore 内核版本与目标一致: $VOSR"
        else
            bad "vmcore 内核 ($VOSR) 与目标 ($KREL) 不一致, 请改用 -k $VOSR 并安装对应 debuginfo"
            # 给出可直接照抄的包名, 避免用户在变体上再踩一次
            case "$VOSR" in
                *+debug) VCAND="kernel-debug-debuginfo-${VOSR%+debug}" ;;
                *+rt+debug) VCAND="kernel-rt-debug-debuginfo-${VOSR%+debug}" ;;
                *+rt) VCAND="kernel-rt-debuginfo-$VOSR" ;;
                *) VCAND="kernel-debuginfo-$VOSR" ;;
            esac
            info "  该 vmcore 对应的 debuginfo 包是: $VCAND"
            fail_cap crash
        fi
    fi
fi

# ---------- 7. 实际编译测试 ----------
if [ "$DO_BUILD" = "1" ]; then
    sec "编译测试 (hello.ko)"
    if [ "$BUILD_OK" != "1" ]; then
        warn "前置条件不满足, 跳过编译测试"
    else
        TMP=$(mktemp -d /tmp/kmod_test.XXXXXX)
        trap 'rm -rf "$TMP"' EXIT
        cat > "$TMP/hello.c" <<'EOF'
#include <linux/module.h>
#include <linux/init.h>
static int __init h_init(void) { pr_info("hello\n"); return 0; }
static void __exit h_exit(void) { pr_info("bye\n"); }
module_init(h_init);
module_exit(h_exit);
MODULE_LICENSE("GPL");
EOF
        echo 'obj-m += hello.o' > "$TMP/Makefile"

        KDIR="$KBUILD"
        [ -e "$KDIR" ] || KDIR="$KSRC"

        if make -C "$KDIR" M="$TMP" modules >"$TMP/build.log" 2>&1 && [ -f "$TMP/hello.ko" ]; then
            vm=$(modinfo -F vermagic "$TMP/hello.ko" 2>/dev/null | awk '{print $1}')
            if [ "$vm" = "$KREL" ]; then
                ok "hello.ko 编译成功, vermagic = $vm"
            else
                bad "hello.ko 已生成但 vermagic ($vm) 与目标 ($KREL) 不一致"
                fail_cap build
            fi
        else
            bad "编译失败, 日志末尾 20 行:"
            tail -n 20 "$TMP/build.log" | sed 's/^/        /'
            fail_cap build
        fi
    fi
fi

# ---------- 8. 结论 ----------
sec "结论"
if [ "$BUILD_OK" = "1" ]; then
    echo "  ${G}✔${N} 可以编译 $KREL 的 .ko"
else
    echo "  ${R}✘${N} 暂不能编译 $KREL 的 .ko"
fi
if [ "$CRASH_OK" = "1" ]; then
    echo "  ${G}✔${N} 可以用 crash 分析 vmcore:"
    echo "      crash $VMLINUX <vmcore>"
else
    echo "  ${R}✘${N} 暂不能用 crash 分析 vmcore"
fi
echo "  统计: OK=$PASS  WARN=$WARN  FAIL=$FAIL"

if [ ${#MISSING[@]} -gt 0 ]; then
    echo
    echo "  缺失的包, 可尝试:"
    echo "      dnf install -y ${MISSING[*]}"
    case " ${MISSING[*]} " in
        *debuginfo*)
            echo
            echo "  提示: $KREL_BASE 若是旧小版本, 当前仓库可能已没有它的 debuginfo, 可到 vault 获取:"
            if [ -n "$VARIANT" ]; then
                echo "  注意: 你的内核是 $VARIANT 变体, 必须装 ${DBG_PKG},"
                echo "        而不是 kernel-debuginfo-$KREL_BASE (两者不通用)。"
            fi
            echo "      RHEL : 启用 rhel-9-for-$ARCH-baseos-debug-rpms 或 EUS 仓库, 或从 Customer Portal 下载"
            echo "      Rocky: https://dl.rockylinux.org/vault/rocky/9.3/BaseOS/$ARCH/debug/tree/Packages/k/"
            echo "      Alma : https://vault.almalinux.org/9.3/ 下对应的 debug 目录"
            echo "      需要下载的典型文件 (以 Rocky 9.3 / x86_64 为例, 注意 KREL 本身已含 $ARCH):"
            echo "        kernel-debuginfo-$KREL_BASE.rpm           ~611 MB"
            echo "        kernel-debug-debuginfo-$KREL_BASE.rpm     ~709 MB  (仅 debug 变体)"
            echo "        kernel-debuginfo-common-$ARCH-$KREL_BASE.rpm"
            echo "      下载 RPM 后用 rpm -ivh 安装"
            echo
            echo "  说明: kernel-debug-debuginfo 只对 kernel-debug 变体的 vmcore 有效,"
            echo "        它把 vmlinux 装到 /usr/lib/debug/lib/modules/$KREL_BASE+debug/vmlinux,"
            echo "        与普通内核的 kernel-debuginfo 互不替代。"
            ;;
    esac

    if [ "$DO_INSTALL" = "1" ]; then
        echo
        if [ "$(id -u)" -ne 0 ]; then
            echo "  ${R}-i 需要 root 权限${N}"
        else
            echo "  == 开始安装 =="
            dnf install -y "${MISSING[@]}" || echo "  ${Y}dnf 安装未完全成功, 请按上面的提示手动处理${N}"
            ARGS=(-k "$KREL")
            [ -n "$VMCORE" ] && ARGS+=(-c "$VMCORE")
            [ "$DO_BUILD" = "1" ] && ARGS+=(-b)
            echo "  == 重新检查 =="
            exec "$0" "${ARGS[@]}"
        fi
    fi
fi

[ "$BUILD_OK" = "1" ] && [ "$CRASH_OK" = "1" ] && exit 0
exit 1
