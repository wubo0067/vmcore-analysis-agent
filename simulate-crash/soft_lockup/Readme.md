# Soft Lockup 模拟模块

本模块在指定 CPU 上创建一个内核线程，让它在**禁止抢占**的状态下持续忙等，从而触发 Linux 内核的 soft lockup 检测器。配合 `kernel.softlockup_panic=1` 和 kdump，可以得到一份现场清晰、可复现的 vmcore，用来测试和演示 vmcore-analysis-agent 的 `soft_lockup` 分析流程。

除默认的忙等场景外，模块还通过 `mode` 参数提供自旋锁争抢、软中断忙等和关中断（hard lockup）三种场景，见第 2 节。

> 适用环境：RHEL 9.3，内核 `5.14.0-362.24.1.el9_3.x86_64`（其他 5.x 内核原理相同，但具体参数可能不同）。
> **只能在测试机或虚拟机上使用**。开启 `softlockup_panic` 后，系统会直接 panic 并重启。

---

## 1. 什么是 soft lockup

### 1.1 定义

**soft lockup（软锁死）** 是指某颗 CPU 长时间运行在内核态，一直不让出 CPU，导致这颗 CPU 上的其他任务（包括内核自己的周期性任务）得不到调度。默认阈值是 20 秒。

"软"的意思是：这颗 CPU **仍然能响应中断**，时钟中断、IPI 都还正常，只是调度器无法在这颗 CPU 上切换任务。如果连中断也响应不了，那就是更严重的 **hard lockup**（硬锁死）。

### 1.2 内核如何检测（5.14）

检测逻辑在 `kernel/watchdog.c`，每颗 CPU 上有两部分配合工作：

| 角色 | 运行上下文 | 作用 |
|---|---|---|
| `watchdog_timer_fn()` | 每颗 CPU 上的 hrtimer，**中断上下文** | 周期性采样，周期为 `watchdog_thresh × 2 / 5`，默认 4 秒。每次触发时，一方面安排一次"喂狗"，另一方面检查上一次喂狗距今多久 |
| `softlockup_fn()` | 由 `stop_one_cpu_nowait()` 交给该 CPU 的 **cpu stopper** 线程执行 | 真正的"喂狗"：更新该 CPU 的 `watchdog_touch_ts` 时间戳 |

cpu stopper 是优先级最高的内核线程，但它**仍然需要被调度**才能运行。如果这颗 CPU 一直不发生调度，比如处于禁抢占状态长时间运行，或者一直在内核里循环而不调用 `cond_resched()`，`softlockup_fn()` 就跑不起来，时间戳也就不会更新。当 hrtimer 发现

```
now - watchdog_touch_ts > 2 × watchdog_thresh   （默认 2 × 10 = 20 秒）
```

时，就判定为 soft lockup，打印：

```
watchdog: BUG: soft lockup - CPU#2 stuck for 22s! [softlockup_sim:12345]
```

随后输出被卡住 CPU 的寄存器和调用栈。如果设置了 `kernel.softlockup_panic=1`，内核会接着 `panic()`，由 kdump 保存 vmcore。

> 在 5.1 之前，每颗 CPU 上有一个 `watchdog/N` 内核线程负责喂狗。新内核已改为由 cpu stopper 负责，所以 `ps` 里看不到 `watchdog/N` 线程是正常的。

由于检测周期是 4 秒，实际报警时间通常在 **20~24 秒**之间。

### 1.3 和相近问题的区别

| 类型 | 现象 | 检测机制 | 默认阈值 | 关键日志 |
|---|---|---|---|---|
| **soft lockup** | CPU 在内核态长时间不调度，但还能响应中断 | hrtimer + cpu stopper | `2 × watchdog_thresh` = 20s | `BUG: soft lockup - CPU#N stuck for Ns!` |
| **hard lockup** | CPU 长时间关中断，连时钟中断都不响应 | NMI watchdog（基于 perf 硬件计数器）检查 hrtimer 中断计数是否还在增长 | `watchdog_thresh` = 10s | `Watchdog detected hard LOCKUP on cpu N` |
| **RCU CPU stall** | CPU 长时间无法经过 RCU 静止状态，导致宽限期无法结束 | RCU 自身的超时检查 | `rcu_cpu_stall_timeout`（上游默认 21s） | `rcu: INFO: rcu_preempt detected stalls on CPUs/tasks` |
| **hung task** | 任务长时间处于 D（`TASK_UNINTERRUPTIBLE`）状态 | `khungtaskd` 线程定期扫描 | `hung_task_timeout_secs` = 120s | `INFO: task xxx:pid blocked for more than 120 seconds.` |

几点要注意：

- soft lockup 卡住的是 **CPU**，hung task 卡住的是 **任务**。一个任务因为等锁或等 I/O 一直睡着，CPU 本身完全空闲，这属于 hung task，不是 soft lockup。
- 禁抢占忙等也会让这颗 CPU 过不了 RCU 静止状态，所以 **soft lockup 通常伴随 RCU stall**，两者的时间又很接近，具体见第 6 节。
- 一颗 CPU 关中断卡死，可能让其他 CPU 在等它响应 IPI（比如 TLB flush 需要所有 CPU 确认）时陷入忙等，结果 soft lockup **报在别的 CPU 上**。`issue_1.txt` 记录的就是这种情况。

### 1.4 生产环境中的常见原因

- 内核或驱动代码里的长循环没有调用 `cond_resched()`，比如遍历超大链表、处理大量内存页。
- 自旋锁竞争激烈，或者持锁的一方迟迟不释放，等锁的 CPU 一直自旋在 `native_queued_spin_lock_slowpath`。
- 中断或软中断过多（中断风暴、网络软中断负载过高），导致这颗 CPU 总也轮不到普通任务。
- 虚拟化环境中宿主机过载，vCPU 长时间得不到物理 CPU（steal time 很高），表现为假性 soft lockup。
- 硬件或固件问题，比如 SMI 占用时间过长。

---

## 2. 本模块如何模拟

模块用 `mode` 参数选择场景。所有场景都满足下面几点：

- **独立的 `noinline` 卡住函数**：`bt` 和 `dis -rl` 里能直接看到语义明确的栈帧。
- **现场记录结构 `sim_ctx`**：记录场景、卡住的 CPU、开始时的 jiffies、循环次数，以及 spinlock 场景下锁的地址和争抢状态，分析时可以作为直接证据（见第 7 节）。
- **运行时开关**：线程在加载时就创建好，`enable_soft_lockup` 可以随时通过 sysfs 打开或关闭。关闭时线程真正睡眠，不占 CPU。

### 2.1 四种模式是什么意思

#### 先理解四个概念

| 概念 | 通俗解释 | 和 soft lockup 的关系 |
|---|---|---|
| **抢占（preemption）** | 调度器把正在运行的任务"换下来"，让别的任务上 CPU | 关闭抢占后，当前任务不让出 CPU，负责喂狗的 cpu stopper 就跑不上来 |
| **中断（interrupt）** | 硬件打断 CPU，去执行一小段处理程序，比如时钟中断、网卡收包 | soft lockup 检测器本身靠时钟中断（hrtimer）定期检查。关中断后，检测器在这颗 CPU 上也失效了 |
| **软中断（softirq）** | 硬件中断处理完后，"延后"执行的工作，比如网络协议栈处理、定时器回调 | 软中断执行时不会被普通任务抢占，在里面卡住同样会导致 CPU 不调度 |
| **自旋锁（spinlock）** | 一种拿不到就原地转圈等待、不睡眠的锁；持有期间自动关闭抢占 | 持锁不放的 CPU 不调度；等锁的 CPU 一直转圈，也不调度 |

soft lockup 的本质是：**某颗 CPU 长时间不发生任务切换**。四种模式只是用四种不同的方式制造"不切换"，分别对应四类真实故障。

#### 四种模式逐个说明

**① busy：关抢占忙等（默认）**

```c
preempt_disable();          // 关闭抢占：调度器不能把我换下来
while (开关打开)
    cpu_relax();            // 原地空转
preempt_enable();
```

- 这颗 CPU 一直在跑这个循环，cpu stopper 上不来，喂狗停止。
- 中断还开着，这颗 CPU 的时钟中断照常触发，检测器发现超时后，**由这颗 CPU 自己报** soft lockup。
- 真实场景：内核代码在禁抢占区执行超长循环（比如遍历巨大链表），又没有调用 `cond_resched()` 主动让出 CPU。
- 这是最简单、最"干净"的 soft lockup 现场。

**② spinlock：自旋锁争抢（需要至少 2 颗 CPU）**

```
CPU A（持有者，cpu_number）            CPU B（争抢者，contender_cpu）
spin_lock(&sim_lock);  ← 拿到锁
while (开关打开)                       spin_lock(&sim_lock);  ← 拿不到，
    cpu_relax();       ← 一直不释放        在 native_queued_spin_lock_slowpath
                                           里原地转圈等待
```

- 持有者：`spin_lock()` 会自动关闭抢占，然后一直不释放锁，效果和 busy 一样。
- 争抢者：自旋锁拿不到时不睡眠，而是原地转圈，同样不发生调度。
- 结果：**A、B 两颗 CPU 都会报** soft lockup。
- 分析重点：持有者 A 是"肇事者"，争抢者 B 是"受害者"。分析时如果只看 B 的栈，会以为是锁的问题；必须找到持有这把锁的 CPU A，才能定位真正的原因。
- 真实场景：某段代码持锁时间过长，或者某条错误处理路径忘了解锁。

**③ softirq：在软中断里忙等**

```
主线程（不绑核）：在目标 CPU 上布置一个定时器，然后每 100ms 检查一次开关
        ↓ 定时器到期
目标 CPU 的软中断：__do_softirq → run_timer_softirq → call_timer_fn
                    → softlockup_sim_timer_fn()：while (开关打开) cpu_relax();
```

- 主线程本身**不卡住**，它只负责"埋一颗定时器"。真正卡住的是目标 CPU 上的定时器回调函数。
- 软中断执行时不能被普通任务抢占，所以目标 CPU 同样无法调度，报 soft lockup。
- 和 busy 的区别：栈里能看到 `__do_softirq`、`call_timer_fn` 等软中断相关的帧，用来测试分析 agent 能否识别出"卡在软中断上下文"。
- 主线程不绑核，是为了在目标 CPU 被卡住时，主线程还能在其他 CPU 上响应开关和 `rmmod`。
- 真实场景：网络流量过大导致网络软中断长时间占用 CPU；某个定时器回调执行过慢。

**④ irqoff：关中断忙等（危险，需 `allow_irqoff=1`）**

```c
local_irq_save(flags);      // 关闭本 CPU 的中断
while (开关打开)
    cpu_relax();
local_irq_restore(flags);
```

- 中断关了，这颗 CPU 的时钟中断也不触发，**soft lockup 检测器在这颗 CPU 上失效**，不会报 soft lockup。
- 由 **NMI watchdog** 发现：NMI（不可屏蔽中断）不受关中断影响，它检查这颗 CPU 的时钟中断计数是否还在增长，不增长就报 **hard lockup**（默认约 10 秒）。
- 副作用：其他 CPU 发给这颗 CPU 的 IPI（比如 TLB 刷新请求）得不到响应，发送方会一直等待，结果可能在**别的 CPU** 上报 soft lockup。`issue_1.txt` 记录的就是这个现象。
- 真实场景：`spin_lock_irqsave()` 保护的关中断区域执行时间过长。

#### 一句话对比

| mode | 用什么方式让 CPU 不调度 | 谁报警 | 报什么 |
|---|---|---|---|
| `busy` | 关抢占 | 目标 CPU 自己 | soft lockup |
| `spinlock` | 持锁不放 + 等锁转圈 | 持有者和争抢者两颗 CPU | soft lockup |
| `softirq` | 在软中断里不返回 | 目标 CPU 自己 | soft lockup（栈里有 `__do_softirq`） |
| `irqoff` | 关中断 | NMI watchdog 报目标 CPU；其他 CPU 可能被连累 | hard lockup（+ 其他 CPU 的 soft lockup） |

### 2.2 场景一览

| mode | 做法 | 预期报警 | 被卡住的 CPU 上的关键栈帧 | 主要用来验证 |
|---|---|---|---|---|
| `busy`（默认） | 禁抢占忙等，**不关中断** | 目标 CPU 报 soft lockup | `softlockup_sim_spin` | 基础 soft_lockup 剧本 |
| `spinlock` | 持有者线程在 CPU A 上 `spin_lock(&sim_lock)` 后不释放；争抢者线程在 CPU B 上 `spin_lock` 同一把锁 | A、B **两颗 CPU** 都报 soft lockup | A：`softlockup_sim_hold_lock`<br>B：`native_queued_spin_lock_slowpath` ← `_raw_spin_lock` ← `softlockup_sim_contend` | `analyze_cpu_lockup_rcu` 的 `spinlock_contenders`；qspinlock 解码；找出持锁者 |
| `softirq` | 在目标 CPU 的定时器软中断回调里忙等 | 目标 CPU 报 soft lockup | `__do_softirq` → `run_timer_softirq` → `call_timer_fn` → `softlockup_sim_timer_fn` | 软中断上下文的识别（`irq_or_softirq_cpus`） |
| `irqoff`（危险） | 关中断忙等 | NMI watchdog 报 **hard lockup**；可能连累其他 CPU 报 soft lockup | `softlockup_sim_irqoff_spin`（在 NMI 栈中看到） | hard_lockup 剧本；`issue_1.txt` 那种 IPI 连锁现场 |

各场景的执行路径：

```
busy      softlockup_sim 线程 ─ softlockup_sim_spin():  preempt_disable(); while (on) cpu_relax();

spinlock  CPU A  softlockup_sim 线程 ─ softlockup_sim_hold_lock(): spin_lock(&sim_lock); while (on) cpu_relax();
          CPU B  softlockup_ctd 线程 ─ softlockup_sim_contend():   spin_lock(&sim_lock);   ← 自旋等待

softirq   softlockup_sim 线程（不绑核）每 100ms 检查一次，在目标 CPU 上布置定时器
          目标 CPU 定时器软中断 ─ softlockup_sim_timer_fn(): while (on) cpu_relax();

irqoff    softlockup_sim 线程 ─ softlockup_sim_irqoff_spin(): local_irq_save(); while (on) cpu_relax();
```

### 2.3 各场景要点

- **busy**：只禁抢占，目标 CPU 上的 hrtimer 和 IPI 照常处理，soft lockup 就报在目标 CPU 本身，不会连累其他 CPU。
- **spinlock**：
  - `spin_lock()` 本身会禁抢占，所以持有者 CPU 也会报 soft lockup。两颗 CPU 几乎同时达到阈值，panic 时由哪颗 CPU 报出取决于谁先检测到。
  - 争抢者会等持有者真正拿到锁之后才去争抢，保证"持有者 A、等待者 B"的角色固定。
  - 锁地址在 `sim_ctx.lock` 中，也可以直接 `p &sim_lock`。
  - 写 0 到 `enable_soft_lockup` 后，持有者释放锁，争抢者随即拿到锁并释放，系统恢复。
- **softirq**：软中断上下文本身不可抢占，忙等期间 cpu stopper 同样无法运行，所以报的是 soft lockup，栈里能看到软中断相关的帧。
- **irqoff**：
  - 必须同时设置 `allow_irqoff=1` 才能加载，否则 `insmod` 返回 `Operation not permitted`。
  - 关中断后这颗 CPU 上的 hrtimer 不再触发，**它自己不会报 soft lockup**，只能由 NMI watchdog 报 hard lockup（需要 `kernel.nmi_watchdog=1`，见 5.2）。
  - 其他 CPU 如果需要这颗 CPU 响应 IPI（比如 TLB flush），会在 `smp_call_function_many_cond` 里一直等，结果在**别的 CPU** 上报 soft lockup，这就是 `issue_1.txt` 记录的现象。
  - 一旦出现 IPI 连锁，写 sysfs 和 `rmmod` 都可能无法完成，**通常只能重启**。只建议在设置了 `hardlockup_panic=1` 的测试机上使用。
  - 虚拟机里通常没有可用的 perf NMI，hard lockup 检测不起作用，系统可能直接挂住而不产生 vmcore。

### 2.4 模块参数

| 参数 | 类型 / 权限 | 默认值 | 说明 |
|---|---|---|---|
| `mode` | string / 只读 | `busy` | 场景：`busy`、`spinlock`、`softirq`、`irqoff`。写错时 `insmod` 返回 `Invalid argument` |
| `cpu_number` | int / 只读 | `-1` | 要锁死的 CPU 编号（spinlock 场景下是持有者 CPU），必须是在线 CPU。`-1` 时：`busy` 不绑核；其他场景自动选最后一颗在线 CPU |
| `contender_cpu` | int / 只读 | `-1` | 仅 spinlock 场景：争抢者所在 CPU，必须在线且不同于 `cpu_number`。`-1` 时自动选另一颗在线 CPU |
| `enable_soft_lockup` | bool / 可写 | `0` | `1`：开始卡住；`0`：停止，线程睡眠。可在运行时修改 |
| `allow_irqoff` | bool / 只读 | `0` | `mode=irqoff` 时必须设为 `1`，表示确认接受可能整机挂住的风险 |

---

## 3. 环境要求

- RHEL 9.3 或兼容系统，内核 `5.14.0-362.24.1.el9_3.x86_64`
- 与运行内核**版本完全一致**的 `kernel-devel`
- `gcc`、`make`、`kexec-tools`
- root 权限
- 分析 vmcore 还需要：`crash`，以及 `kernel-debuginfo-$(uname -r)`（提供 `vmlinux`）

```bash
sudo dnf install kernel-devel-$(uname -r) gcc make kexec-tools crash
sudo dnf debuginfo-install kernel-$(uname -r)     # 需要启用 debuginfo 仓库
```

---

## 4. 构建

```bash
cd simulate-crash/soft_lockup
make                      # 生成 soft_lockup_module.ko（带 -g 调试信息）
make vermagic             # 确认输出中包含 5.14.0-362.24.1.el9_3.x86_64
```

如果在另一台机器上编译，用 `KERNEL_DIR` 指定目标内核的构建目录：

```bash
make KERNEL_DIR=/usr/src/kernels/5.14.0-362.24.1.el9_3.x86_64
```

> 不要用 `strip` 处理 `.ko`。分析时需要它带的调试信息来把地址对应到 `file:line`。

---

## 5. 配置 kdump 和 panic 参数

### 5.1 启用 kdump

RHEL 9 已经**不再支持** `crashkernel=auto`，改用 `kdumpctl` 设置默认的预留内存：

```bash
sudo kdumpctl reset-crashkernel --kernel=ALL
sudo systemctl enable --now kdump
sudo reboot
# 重启后确认
sudo kdumpctl status          # 应显示 Kdump is operational
cat /proc/cmdline | grep -o 'crashkernel=[^ ]*'
```

vmcore 默认保存到 `/var/crash/<IP>-<日期时间>/`，路径可以在 `/etc/kdump.conf` 的 `path` 项中修改。

### 5.2 内核参数

| sysctl | 推荐值 | 作用 |
|---|---|---|
| `kernel.softlockup_panic` | `1` | 检测到 soft lockup 时 panic，触发 kdump。为 `0` 时只打印警告 |
| `kernel.softlockup_all_cpu_backtrace` | `1` | 检测到时额外打印**所有 CPU** 的调用栈，便于分析 |
| `kernel.watchdog_thresh` | `10`（默认），或调小到 `5` | soft lockup 阈值为它的 2 倍。调小可以更快触发，并让 soft lockup 明显早于 RCU stall 出现 |
| `kernel.panic_on_rcu_stall` | `0` | 避免 RCU stall 抢先导致 panic，见第 6 节 |
| `kernel.nmi_watchdog` | `1` | 仅 irqoff 场景需要：启用 NMI watchdog（hard lockup 检测）。启动日志中搜索 `NMI watchdog` 应显示 Enabled |
| `kernel.hardlockup_panic` | `1` | 仅 irqoff 场景需要：检测到 hard lockup 时 panic |

```bash
sudo sysctl -w kernel.softlockup_panic=1
sudo sysctl -w kernel.softlockup_all_cpu_backtrace=1
sudo sysctl -w kernel.panic_on_rcu_stall=0
# 可选：sudo sysctl -w kernel.watchdog_thresh=5
# 仅 irqoff 场景：
# sudo sysctl -w kernel.nmi_watchdog=1 kernel.hardlockup_panic=1
```

要永久生效，可以写到 `/etc/sysctl.d/90-softlockup-test.conf`。

> 检测范围：soft lockup 只检测 `kernel.watchdog_cpumask` 包含的 CPU。用 `nohz_full=` 或 `isolcpus=` 隔离的 CPU 通常不在其中，绑定到这些 CPU 上不会触发报警。

---

## 6. 触发和观察

### 6.1 先演练（不 panic）

```bash
sudo sysctl -w kernel.softlockup_panic=0
make load_cpu CPU=2               # = insmod soft_lockup_module.ko enable_soft_lockup=1 cpu_number=2
dmesg -w | grep -E 'soft_lockup_module|soft lockup|rcu'
```

约 20~24 秒后应看到：

```
soft_lockup_module: busy-waiting with preemption disabled on CPU 2
watchdog: BUG: soft lockup - CPU#2 stuck for 22s! [softlockup_sim:12345]
```

停止并卸载：

```bash
make stop                         # 写 0 到 enable_soft_lockup，CPU 2 恢复空闲
make unload
```

### 6.2 先加载、后触发

```bash
make load_idle CPU=2              # 只加载，线程在 CPU 2 上睡眠
make start                        # 需要时再开始忙等
```

### 6.3 生成 vmcore

```bash
sudo sysctl -w kernel.softlockup_panic=1
make load_cpu CPU=2
# 约 20~24 秒后系统 panic，kdump 保存 vmcore 后自动重启
```

### 6.4 关于 RCU stall

禁抢占忙等也会阻止这颗 CPU 经过 RCU 静止状态，所以 dmesg 里可能同时出现：

```
rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
```

RCU stall 的超时时间可以这样查看：

```bash
cat /sys/module/rcupdate/parameters/rcu_cpu_stall_timeout
```

它和 soft lockup 的 20 秒阈值很接近。如果你想得到**单纯的 soft lockup 现场**，建议：

- 保持 `kernel.panic_on_rcu_stall=0`，确保 panic 原因是 soft lockup；
- 或者把 `kernel.watchdog_thresh` 调到 `5`，让 soft lockup 在约 10 秒时先报出。

如果你就是想测试"soft lockup 加 RCU stall"同时出现的复合现场，保留默认值即可。

### 6.5 其他场景

```bash
# spinlock：持有者在 CPU 2，争抢者在 CPU 1
make load_spinlock CPU=2 CPU2=1
# = insmod soft_lockup_module.ko mode=spinlock enable_soft_lockup=1 cpu_number=2 contender_cpu=1

# softirq：在 CPU 2 的定时器软中断里忙等
make load_softirq CPU=2

# irqoff（危险，可能整机挂住）：在 CPU 2 上关中断忙等
make load_irqoff CPU=2
# = insmod soft_lockup_module.ko mode=irqoff allow_irqoff=1 enable_soft_lockup=1 cpu_number=2
```

各场景在 dmesg 里的预期输出：

| mode | 预期日志 |
|---|---|
| `spinlock` | `[spinlock] holder on CPU 2 holds sim_lock at ...`，约 20~24 秒后 `BUG: soft lockup - CPU#1 stuck ...` 和 `CPU#2 stuck ...` 都会出现 |
| `softirq` | `[softirq] timer armed on CPU 2`，之后 `BUG: soft lockup - CPU#2 stuck ...`，栈里有 `__do_softirq` |
| `irqoff` | 约 10 秒后 `Watchdog detected hard LOCKUP on cpu 2`；可能还有其他 CPU 的 soft lockup，栈在 `smp_call_function_many_cond` |

`spinlock` 和 `softirq` 场景都可以用 `make stop` 恢复；`irqoff` 场景通常只能重启。

---

## 7. 分析 vmcore

### 7.1 用 crash 手工分析

```bash
sudo crash /usr/lib/debug/lib/modules/$(uname -r)/vmlinux /var/crash/<dir>/vmcore
```

```
crash> sys                                    # PANIC: "watchdog: BUG: soft lockup - CPU#2 stuck for 22s!"
crash> bt                                     # 在 IRQ 栈上：watchdog_timer_fn -> panic
crash> mod -s soft_lockup_module /path/to/soft_lockup_module.ko
crash> bt -c 2                                # 被中断的现场应在 softlockup_sim_spin
crash> dis -rl softlockup_sim_spin            # 对应到源码行
crash> p sim_ctx                              # 锁死的 CPU / 开始时间 / 循环次数
crash> p jiffies                              # 与 sim_ctx.start_jiffies 相减得到卡住时长（单位为 jiffies；RHEL x86_64 通常 CONFIG_HZ=1000）
crash> runq -c 2                              # 该 CPU 上积压的就绪任务
```

`sim_ctx.magic` 在内存中的字节是 `"SOFTLKP"`，也可以用 `search -k 0x504b4c54464f53` 直接定位。

各场景的分析重点：

| mode | 关键命令 | 应看到 |
|---|---|---|
| `busy` | `bt -c <cpu>`、`p sim_ctx` | 被中断的帧在 `softlockup_sim_spin`；`sim_ctx.mode_name` 为 `busy` |
| `spinlock` | `bt -c <A>`、`bt -c <B>`、`p sim_ctx`、`struct qspinlock <sim_ctx.lock>` | A 在 `softlockup_sim_hold_lock`，B 在 `native_queued_spin_lock_slowpath`；`sim_ctx.lock_held=1`、`contender_waiting=1`；qspinlock 的 `locked` 字节为 1。`sim_ctx.cpu` 就是持锁者 CPU |
| `softirq` | `bt -c <cpu>`、`p sim_ctx` | 栈里有 `__do_softirq` / `call_timer_fn` / `softlockup_sim_timer_fn`；`sim_ctx.in_softirq=1` |
| `irqoff` | `bt -a`（hard lockup 场景允许）、`p sim_ctx` | 目标 CPU 的 NMI 栈中被打断的帧在 `softlockup_sim_irqoff_spin`；其他 CPU 可能卡在 `smp_call_function_many_cond` |

### 7.2 用 vmcore-analysis-agent 分析

```bash
cd client
uv run main.py --url http://<server>:8000 --stream \
  --vmcore-path /var/crash/<dir>/vmcore \
  --vmlinux-path /usr/lib/debug/lib/modules/5.14.0-362.24.1.el9_3.x86_64/vmlinux \
  --vmcore-dmesg-path /var/crash/<dir>/vmcore-dmesg.txt \
  --debug-symbols /path/to/soft_lockup_module.ko
```

预期结果：

| mode | agent 应判定的 `signature_class` | 应定位到 |
|---|---|---|
| `busy` | `soft_lockup` | `softlockup_sim_spin` 中禁抢占的忙等循环 |
| `spinlock` | `soft_lockup` | 持锁者 `softlockup_sim_hold_lock` 长期持有 `sim_lock`；争抢者是受害方 |
| `softirq` | `soft_lockup` | 定时器软中断回调 `softlockup_sim_timer_fn` |
| `irqoff` | `hard_lockup` | `softlockup_sim_irqoff_spin` 关中断忙等；其他 CPU 的 soft lockup 是连带现象 |

---

## 8. 卸载

```bash
make stop        # 如果还在忙等，先停止
make unload
make status      # 应显示 Module not loaded
```

---

## 9. 常见问题

| 现象 | 原因与处理 |
|---|---|
| `insmod: ERROR: could not insert module ...: Invalid argument` | `mode` 写错，或 `cpu_number` / `contender_cpu` 不是在线 CPU。用 `lscpu -e` 查看在线 CPU 编号 |
| `insmod` 返回 `Operation not permitted` | `mode=irqoff` 时没有设置 `allow_irqoff=1` |
| spinlock 场景加载失败，提示需要至少 2 颗在线 CPU | 单核机器无法运行 spinlock 场景；或 `contender_cpu` 与 `cpu_number` 相同 |
| `insmod` 报 `Invalid module format` | `.ko` 和运行内核的版本不一致，用 `make vermagic` 和 `uname -r` 对比，重新编译 |
| 加载后一直没有报警 | ① 没有设置 `enable_soft_lockup=1`；② 目标 CPU 不在 `kernel.watchdog_cpumask` 中（`nohz_full` / `isolcpus`）；③ `kernel.watchdog` 或 `kernel.soft_watchdog` 被设成了 0 |
| 报警出现在别的 CPU 上 | 通常是目标 CPU **关了中断**，其他 CPU 在等它响应 IPI 时被连累，见 `issue_1.txt`。只有 `irqoff` 场景会这样；spinlock 场景下争抢者 CPU 报警是正常现象 |
| irqoff 场景系统挂住但没有 vmcore | NMI watchdog 不可用（虚拟机常见）或没有设置 `kernel.hardlockup_panic=1`，只能手动重启 |
| panic 原因是 RCU stall 而不是 soft lockup | `kernel.panic_on_rcu_stall=1` 且 RCU stall 先报出，见第 6.4 节 |
| 报警后没有生成 vmcore | `kernel.softlockup_panic` 为 0，或者 kdump 没有正常工作（`kdumpctl status`） |
