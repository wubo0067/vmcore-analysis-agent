# RCU Stall Simulator（`rcu_stall_mod.ko`）

## 1. 这个 ko 是干什么用的

`rcu_stall_mod.ko` 是一个**故意制造 RCU stall 的内核模块**，只用于专用测试虚拟机。
它的目标是给 vmcore-analysis-agent 提供一份可控、可复现的 vmcore，用来验证
`lock_hang` MCP 工具在 RCU stall 场景下的取证能力：

- `analyze_cpu_lockup_rcu` 能否把 stall CPU、看门狗/RCU 检测栈、可疑 CPU 归类出来；
- 能否在大量任务栈中把"阻塞的 RCU 读者"与"等待宽限期的任务"关联起来；
- 能否避免在 `bt -a` 原文上浪费上下文，而是直接给出结构化结论。

它**不模拟** mutex/rwsem 死锁、自旋锁风暴、hard lockup，也不产生 Wait-For Graph。
锁死锁场景请使用独立的测试模块，两者不要混在一次 panic 里。

## 2. 故障模型

模块创建两个内核线程，形成一条清晰的因果链：

| 线程名 | 行为 | 在 vmcore 中的证据 |
| --- | --- | --- |
| `rcu_blocked_rea` | 在 `rcu_read_lock()` 临界区内分片睡眠（默认 70 s） | 任务栈停在 `schedule_timeout`，状态为 `S`，仍处于 RCU 读侧临界区 |
| `rcu_gp_waiter` | 确认读者进入临界区后调用 `synchronize_rcu()` | 任务栈停在 `synchronize_rcu` / RCU GP 等待路径 |

> 表里 `rcu_blocked_rea` 是**截断后的真实 comm**：源码写的名字是
> `rcu_blocked_reader`，但 `vsnprintf` 会把它截到 15 个字符。
> 在 `ps` / `pgrep` / vmcore 的 `COMMAND` 字段里看到的都是 `rcu_blocked_rea`。

因果关系：

```text
rcu_blocked_reader 持有 RCU 读锁且长期不出临界区
        │  该任务被登记到 rcu_node->blkd_tasks，GP 必须等它退出临界区
        │  （注意：CPU 本身照常上报 quiescent state，被卡住的是"任务"）
        ▼
grace period 无法完成
        │
        ▼
rcu_gp_waiter 阻塞在 synchronize_rcu()
        │  超过 rcu_cpu_stall_timeout
        ▼
rcu: INFO: rcu_preempt detected stalls on tasks → panic → kdump 生成 vmcore
```

关键设计取舍：

- 读者使用 `schedule_timeout_interruptible` 睡眠，**CPU 仍可调度**，
  因此只会触发 RCU stall，不会顺带触发 soft lockup；
- 睡眠按 50 ms 分片，目的是让 `kthread_stop()` 的唤醒与 `signal_pending()`
  检查能在有限时间内生效，`rmmod` 不会被挂死。
  **不是为了规避 hung_task**——读者处于 `TASK_INTERRUPTIBLE`（`S` 态），
  而 hung_task 只检查 `TASK_UNINTERRUPTIBLE`（`D` 态），本来就查不到它；
- 读者先让出 CPU 再通知等待者，保证等待者进入 `synchronize_rcu()` 时
  因果链已经成立（这一步真正保证的是"任务已被挂入 `blkd_tasks`"，
  而不只是"已让出 CPU"）。

> 需要内核开启 `CONFIG_PREEMPT_RCU`：源码里有编译期校验
> `#if !IS_ENABLED(CONFIG_PREEMPT_RCU) #error ... #endif`，
> 配置不对时 `make` 直接失败，不会装出一个不工作的模块。
> 非抢占 RCU 内核上，读者睡眠引发的上下文切换会被当成静止状态，
> GP 会提前结束，读者醒来后可能访问已释放的内存，不要这样用。
> 即使在 PREEMPT_RCU 上，这也是**刻意的违规用法**：实现能承接，但内核会打一条 WARNING。
> 详见 [7. 名词解释 · PREEMPT_RCU](#preempt_rcu可抢占-rcu)。

## 3. 原理：内核为什么会因此崩溃

要理解这个模块为什么能"合法地"搞崩内核，需要先理解 RCU 回收内存的机制。
关键点在于：**RCU 从不主动锁住读者，它靠"等所有 CPU 都至少让出一次"来保证安全**。

### 3.1 RCU 的基本约定

RCU 回收者（updater）修改链表时，不直接释放旧元素，而是：

1. 把旧元素从链表摘除（新读者看不到它）；
2. 等待一个 **grace period（宽限期）** 结束；
3. 确认所有在修改前就存在的读者都离开了临界区，才真正 `kfree()` 旧元素。

判断"所有读者都走了"的方法是对每个 CPU 收集 **quiescent state（静止状态）**：
一个 CPU 只要发生了一次上下文切换，或者从内核态返回用户态、进入 idle，
就说明它此刻不可能滞留在 RCU 读侧临界区里，可以记为"已静止"。
**所有 CPU 都静止过一次 = 一个 grace period 结束。**

#### 摘除旧元素后，正在遍历的读者怎么办

这是 RCU 最容易卡住人的地方。先明确一个前提：**`list_del_rcu()` 只改动邻居的指针，不改动被删元素自身的指针。**

```c
/* 删除前：A -> B -> C */
A->next = C;  C->prev = A;      /* list_del_rcu(&B->list)：只改 A、C */
/* B->next 仍然指向 C，B->prev 仍然指向 A */
```

因此分三种情况看：

**情况一：读者还没取到 B（例如停在 A 上）**

读者读 `A->next` 时，A 的指针已经被改成 C，所以读者直接看到 `A -> C`，
跳过 B，走的是"新链表"。**完全安全**，也符合"新读者看不到已删除元素"的约定。

**情况二：读者已经取到 B 并正在使用它（停在 B 上）**

读者手里的 B 地址仍然有效（内存没被释放），B 的 `next` 也**没有被改动**，
所以读者继续走下去仍然能到达 `B -> C`。

> 这里就是问题所在：读者看到的是**"B 还在链上"的旧视图**。
> 这在 RCU 的语义里是**允许**的——RCU 不承诺读者看到最新数据，
> 只承诺"读者看到的任何数据都还在内存里，不会野指针"。
> 这叫**读者可能看到过期数据（stale data）**，属于可接受的权衡。

**情况三：读者还没取到 B，但已在遍历中途**

关键在于**取 next 指针的那一刻**。RCU 要求读者用
`rcu_dereference()` / `list_for_each_entry_rcu()` 读取，标准遍历形态是：

```c
rcu_read_lock();
list_for_each_entry_rcu(pos, head, list) {
    use(pos);
}
rcu_read_unlock();
```

展开后等价于"先取当前元素，再取它的 next"，两个步骤都在临界区内。
只要读者还在临界区里，它走到的每个元素都保证没被 `kfree()`——
**但它走到的元素集合可能是"新 + 旧的混合体"**，具体混成什么样取决于它
在 `list_del_rcu()` 前后各读了哪几个指针。

结论：**读者不会"断链"到走不下去**，因为断链风险来自"内存被释放"，
而 RCU 保证内存要等所有既有读者退出后才释放。代价是读者可能
看到删了一半的链表视图（所谓 "RCU 遍历看到的链表是 snapshot-ish，
但不是严格快照"）。

#### 那什么情况下才会真的断链

断链只发生在**违反了 RCU 使用规则**时：

| 错误用法 | 后果 |
| --- | --- |
| 用 `list_del()` 而不是 `list_del_rcu()` | 它会把 `entry->next` 置成 `LIST_POISON`，正在遍历的读者直接踩到毒值 |
| 用 `list_add()` 而不是 `list_add_rcu()` | 新元素插入时指针写入顺序不对，读者可能看到"半插入"状态 |
| 读指针不用 `rcu_dereference()` | 编译器和 CPU 可能重排读到野值（尤其在弱内存序架构） |
| 摘链后立刻 `kfree()`，不等 GP | 读者手里的指针变成悬空指针 → use-after-free |
| 读者不进入 `rcu_read_lock()` | 上文所有保证全部失效 |

所以"摘除会不会让读者走不下去"这个问题，答案是：
**只要按 RCU 的写入/读取规则来写，就不会；违反任一规则就会。**

#### 本模块与这个问题的关系

本模块的读者**根本不是在遍历链表**，它只是在 `rcu_read_lock()` 里睡觉。
所以它和"链表摘除"没有直接交互——但它和上面第 3 条规则等价：
**这个读者永远不会调用 `rcu_read_unlock()`，所以 GP 永远认为"还有一个读者在里面"**，
于是一个本来 10 ms 就结束的 GP 被无限拉长，updater 的 `kfree()` 也就永远等不到。

换句话说，本模块就是"把上面情况二的'读者还没走'无限放大"——
真实内核里读者总会在微秒级离开，本模块让它永远不离开。

```text
grace period 开始
  ├─ CPU0 报告 quiescent state ✔
  ├─ CPU1 报告 quiescent state ✔
  └─ CPU2 …… 仍在 rcu_read_lock() 内 ✘
                         ▲
                         └── 这里被本模块卡住，GP 永远无法完成
```

### 3.2 本模块做的事

`rcu_blocked_reader` 调用 `rcu_read_lock()` 后**长时间不调用 `rcu_read_unlock()`**：

```c
rcu_read_lock();
/* 用截止时刻计时，而不是拿 schedule_timeout 的返回值当总剩余量 */
while (time_before(jiffies, deadline)) {
        schedule_timeout_interruptible(50ms);   /* 反复睡眠，共 70s */
}
rcu_read_unlock();
```

> **计时必须用截止时刻**：`schedule_timeout()` 的返回值是**本次调用那个 timeout**
> 的剩余值（v5.14 `kernel/time/timer.c`）：
>
> ```c
> expire = timeout + jiffies;
> schedule();
> timeout = expire - jiffies;
> return timeout < 0 ? 0 : timeout;
> ```
>
> 睡满 50 ms 就返回 0。如果把返回值回写成"总剩余量"，循环第一次结束就归零，
> 读者只持有约 50 ms，stall 永远不会发生。模块用
> `start = jiffies; deadline = start + msecs_to_jiffies(stall_duration_ms);`
> 配合 `time_before(jiffies, deadline)` 判定。

这个线程处于 `TASK_INTERRUPTIBLE` 睡眠，但它在 RCU 眼里仍然"在临界区内"：
任务身上的嵌套计数器 `rcu_read_lock_nesting` 仍然是 1。

睡眠时它让出了 CPU，所以**这个 CPU 本身会照常上报静止状态**；
但内核（`rcu_note_context_switch()`）同时把这个任务挂到了所在 `rcu_node` 的
`blkd_tasks` 链表上，GP 必须等链表里的读者全部退出才能结束。
也就是说，卡住 GP 的不是某个 CPU，而是**一个被挂起的读者任务**。
详见 [7. 名词解释 · PREEMPT_RCU](#preempt_rcu可抢占-rcu)。

于是 grace period 停在这一步，无法结束。

### 3.3 谁在等 grace period

`rcu_gp_waiter` 调用 `synchronize_rcu()`，它会一直阻塞到"下一个 grace period 结束"。
在正常情况下这是毫秒级操作；现在它被永久挂住：

```text
rcu_gp_waiter  ── synchronize_rcu() ──▶ 等待 GP
                                          │
               GP 需要所有读者都退出临界区  │
                                          ▼
   rcu_blocked_reader ── rcu_read_lock() 内睡眠，一直不 rcu_read_unlock()
```

注意这里等的是**读者任务**，不是 CPU：读者睡眠后 CPU 照常上报静止状态，
但该任务已被登记进 `blkd_tasks`，只要它不执行 `rcu_read_unlock()`，
`rnp->gp_tasks` 就不会变成 NULL，GP 就无法收尾。

内核不会因为"GP 慢"就判死，但它有一个**看门狗**。

### 3.4 从 stall 到 panic

RCU 的 `rcu_gp_kthread` 与 CPU stall 检测器周期性检查 GP 的推进情况。
如果 GP 在 `rcu_cpu_stall_timeout`（默认 21 s）内没有结束——某个 CPU 没有报告静止状态，
或者有读者任务一直阻塞着 GP——内核会打印 `INFO: rcu_preempt detected stalls`，其中包含：

- 出问题的 CPU 编号与当前任务（若阻塞 GP 的是睡眠/被抢占的读者任务，则是这些任务的 PID，可能没有 CPU）；
- 没报 QS 的 CPU 上所有任务的调用栈（`rcu_dump_cpu_stacks`），以及被阻塞读者任务的栈（`sched_show_task`）；
- 阻塞的 GP 序号、等待中的 `synchronize_rcu()` 调用者列表。

此时内核**并没有坏掉**，只是"变慢"。真正让它 `panic` 的是一行 sysctl：

```bash
kernel.panic_on_rcu_stall = 1
```

这个开关的语义是"RCU stall 视为致命错误"。置 1 后，检测器在打印 stall
报告的同时执行：

```text
panic("RCU Stall")
```

panic 路径会停止其他 CPU、保存现场，然后调用 kdump 的
`crash_kexec()` 进入 kexec 内核，由第二个内核把第一个内核的内存
写成 `/var/crash/.../vmcore`。这就是本模块的最终产物。

> 所以严格来说：**不是"RCU 坏了"导致崩溃，而是 RCU 检测到活性违规后
> 按配置主动 panic**。这也正是它能作为可复现 vmcore 样本的原因——
> 崩溃点确定、堆栈确定、因果链清晰。

### 3.5 与 soft lockup / hard lockup 的区别

三种"停顿"的成因和判定方式完全不同，不要把它们的 vmcore 混为一谈：

| | 触发条件 | 判定者 | 本模块是否触发 |
| --- | --- | --- | --- |
| RCU stall | GP 长时间不结束：某 CPU 不报静止状态，或读者任务一直阻塞 GP | `rcu_gp_kthread` + stall 检测器 | **是**（后一种） |
| soft lockup | 某 CPU 长时间不让出调度（如 `mdelay` 忙等） | `watchdog/N` 内核线程 | 否 |
| hard lockup | 某 CPU 长时间关中断（NMI 都进不来） | NMI 看门狗（hrtimer/PMU） | 否 |

本模块的读者是**睡眠**而不是忙等，CPU 调度器工作正常，
所以内核只会报 RCU stall，不会顺带报 soft lockup。这让 vmcore
里的证据更干净——`rcu_blocked_reader` 的栈停在 `schedule_timeout`，
而不是 `mdelay`。

如果想制造"CPU 卡死"那种更粗暴的形态，需要把睡眠换成
`mdelay()` 忙等，但那样同时会触发 soft lockup，且 `kthread_stop()`
无法生效（`rmmod` 会连同整个 CPU 一起挂死）。本模块刻意选择了
可恢复的版本。

### 3.6 RCU 检测器会打印什么

`analyze_cpu_lockup_rcu` 依赖的正是这几段输出，它们会进入 vmcore 的
内核日志缓冲区：

```text
rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
rcu: 	Tasks blocked on level-0 rcu_node (CPUs 0-3): P12345/1:b..l
rcu: 	(detected by 1, t=21002 jiffies, g=..., q=..., ncpus=4)
task:rcu_blocked_rea state:S ...       <- sched_show_task() 打出的被阻塞读者的栈（comm 截断为 15 字符）
rcu: rcu_preempt kthread starved for ... jiffies! ...   <- 仅当 GP kthread 长时间得不到运行时才有
```

> 格式取自 v5.14 `kernel/rcu/tree_stall.h` 的格式串，数值为示意，以实机输出为准。

- `Tasks blocked on level-0 rcu_node (CPUs 0-3): P12345/...` 直接点名阻塞 GP 的读者任务（PID），
  是本模块在 vmcore 中最有价值的"自证"输出；`level-0` 与 `CPUs 0-3` 是 `rcu_node` 树的层级
  及其覆盖的 CPU 范围，**不是** stall CPU，字段含义见 7 · PREEMPT_RCU；
- 因为读者睡眠时已让出 CPU，本模块的报告里**通常不会出现** `3-...!` 这种 stall CPU 行
  （那是 CPU 自己不报静止状态时的形态）；
- `detected by 1` 的 `1` 是负责检测的 CPU；
- 被阻塞读者的完整调用栈由 `sched_show_task()` 打进日志
  （`rcu_dump_cpu_stacks()` 只负责没报 QS 的 CPU，本场景下没有），
  即使 `ap` 指令无法回溯也能拿到。

因此验收标准很明确：vmcore 里应当能同时看到
`rcu_blocked_reader` 与 `rcu_gp_waiter`，且前者栈里有
`schedule_timeout` + `rcu_stall_thread`，后者栈里有 `synchronize_rcu`。

## 4. 编译

```bash
make
```

需要安装与当前运行内核严格匹配的 `kernel-devel` / `linux-headers`，并确保
`/lib/modules/$(uname -r)/build` 存在。

## 5. 触发测试

**前提：只在测试虚拟机执行，会 panic 并可能丢失未保存数据。**

```bash
# 5.1 确认 kdump 可用
systemctl status kdump

# 5.2 让 RCU stall 直接 panic，以便生成 vmcore
sudo sysctl -w kernel.panic_on_rcu_stall=1

# 5.3 确认检测阈值，stall_duration_ms 必须明显大于它
cat /sys/module/rcupdate/parameters/rcu_cpu_stall_timeout

# 5.4 加载模块，默认 70000 ms
sudo insmod rcu_stall_mod.ko
# 或指定时长（1..300000 ms）
sudo insmod rcu_stall_mod.ko stall_duration_ms=80000
```

预期现象：

1. `dmesg` 出现 `rcu_blocked_reader` 与 `rcu_gp_waiter` 的启动日志；
2. 超过阈值后出现 `INFO: rcu_preempt detected stalls on CPUs/tasks`；
3. `kernel.panic_on_rcu_stall=1` 时打印 `Kernel panic - not syncing: RCU Stall`；
4. kdump 在 `/var/crash/<host>-<time>/vmcore` 生成转储。

`stall_duration_ms` 同时暴露在 `/sys/module/rcu_stall_mod/parameters/` 下，
可在加载后读取核对。

## 6. 不 panic 时的卸载与提前终止

```bash
sudo rmmod rcu_stall_mod
```

退出流程先停止读者使其释放 RCU 读锁，宽限期得以推进，再回收 GP 等待者。
读者每 50 ms 检查一次 `kthread_should_stop()`，因此 `rmmod` 不会等待完整时长。

若只想提前结束模拟而不卸载模块，可以给读者发 `SIGINT`：

```bash
# 注意：内核线程名被截断到 15 个字符，pgrep 必须用截断后的名字
pgrep rcu_blocked_rea
sudo kill -SIGINT $(pgrep rcu_blocked_rea)
```

读者会清除信号并提前释放 RCU 读锁，dmesg 出现
`RCU reader interrupted by signal, exiting early` 与
`RCU reader released its read-side critical section after N ms`，其中 `N` 是实际持有时间。

#### 关于线程名截断

`TASK_COMM_LEN` 是 16，`kthread_create()` 内部用 `vsnprintf(name, sizeof(name), ...)`
把名字截到 **15 个字符**再加 `\0`：

```c
char name[TASK_COMM_LEN];                       /* 16 */
vsnprintf(name, sizeof(name), namefmt, args);   /* 最多写 15 字符 + '\0' */
set_task_comm(task, name);
```

所以 `rcu_blocked_reader`（18 字符）在 `ps` 里显示为 **`rcu_blocked_rea`**（15 字符）。
写成 `pgrep rcu_blocked_reader` 会零匹配——`pgrep` 匹配的是 comm 字段，不是完整名字
（`/proc/<pid>/cmdline` 里也没有原始名字）。`ps -eLo pid,comm,stat` 可验证这一点。

#### 为什么必须 `allow_signal(SIGINT)`

`kthreadd()` 的主循环里调用了 `ignore_signals(tsk)`，所有 kthread 子线程都**继承 `SIG_IGN`**。
`allow_signal()` 的源码注释就说得很直接：

```c
static inline void allow_signal(int sig)
{
	/*
	 * Kernel threads handle their own signals. Let the signal code
	 * know it'll be handled, so that they don't get converted to
	 * SIGKILL or just silently dropped.
	 */
	kernel_sigaction(sig, SIG_KTHREAD);
}
```

没有这一行，"信号会被静默丢弃"（*silently dropped*）：`signal_pending()` 永远为假，
上面那条 `kill -SIGINT` 完全不生效，源码里的提前退出分支就是死代码。
模块现在在读者线程开头调用了 `allow_signal(SIGINT);`。

> **不要使用 `kill -9`**：`SIGKILL` 没有 `allow_signal`，对内核线程会被直接丢弃，
> 即使能送达也会绕过 `rcu_read_unlock()`，使该 CPU 的 RCU 状态失衡，
> 后续测试结果不再可信。请用 `SIGINT` 或 `rmmod`。

## 7. 名词解释

阅读 vmcore 报告和 `dmesg` 时最容易被绕晕的几个词，按"是什么 → 为什么 → 在本模块里是谁"顺序说明。

### stall CPU（停滞 CPU）

`dmesg` 里 `detected stalls on CPUs/tasks: 3-...!` 中的 **`3`** 就是 stall CPU：
它是"在超过 `rcu_cpu_stall_timeout` 的时间内，一直没向上报告 quiescent state 的那个 CPU"。

- **不是**"这台 CPU 死机了"。stall CPU 往往仍在正常跑中断、正常调度别的任务，
  只是它一直没走到任何静止状态（典型如在读侧临界区里长时间忙等）。
- 在 `PREEMPT_RCU` 上，阻塞 GP 的还可能是**被挂起的读者任务**（睡眠或被抢占）。
  这时报告里没有 CPU 编号，而是写
  `Tasks blocked on level-0 rcu_node (CPUs 0-3): P12345/1:b..l`，点名的是 PID。
- **本模块属于后一种**：读者睡眠时已让出 CPU，该 CPU 的静止状态照常上报，
  所以这里**没有 stall CPU**，只有一个被点名的读者任务。

在 vmcore 里如何确认：用报告里的 PID 在 `crash` 中 `set <pid>` / `bt <pid>`，
再用 `task -R rcu_read_lock_nesting,rcu_read_unlock_special <pid>` 查看嵌套计数为 1、
任务已被标记为 blocked；只有真正的 stall CPU 形态，才用 `runq` / `bt -c <cpu>` 交叉验证。

### PREEMPT_RCU（可抢占 RCU）

这是理解本模块**为什么会这样表现**的关键概念，放在前面先讲。

**一句话版本**：`PREEMPT_RCU` 让 GP 等待的对象从"CPU"扩展到了"任务"——
读者可以被抢占、甚至睡眠，GP 会把这些被挂起的读者任务一并等完。

> 先澄清一个常见混淆：Tree RCU 是 RCU 的**扩展性实现**（用 `rcu_node` 树汇总各 CPU 的状态），
> `PREEMPT_RCU` 是它的**一个模式**（`CONFIG_PREEMPT_RCU` 会 `select TREE_RCU`）。
> 两种模式都是 Tree RCU，区别只在于"读者能不能被打断"。

#### 第一步：先看不可抢占的 RCU（`CONFIG_PREEMPT_RCU=n`）

- `rcu_read_lock()` 就是 `preempt_disable()`（v5.14 `include/linux/rcupdate.h`）；
- 读者在临界区内不会被切走，所以内核可以用一条很简单的推理：
  **"某个 CPU 发生了上下文切换 ⇒ 它上面的读者一定已经退出临界区"**；
- 于是 **上下文切换 = 静止状态（QS）**，GP 只需要等每个 CPU 都切换（或进 idle、回用户态）一次；
- 代价：读者不可被抢占（实时延迟差）；而且读者**不能睡眠**——睡眠就是一次上下文切换，
  会被当成 QS，GP 提前结束，读者醒来后可能访问已被释放的内存。

#### 第二步：PREEMPT_RCU 改了什么

实时/低延迟内核要求读者可以被抢占，这就打破了上面那条推理：
**切换走了，不代表读者退出了**。所以 `PREEMPT_RCU` 做了三件事：

1. `rcu_read_lock()` 不再关抢占，只做 `current->rcu_read_lock_nesting++`；
2. 任务在临界区内被切走（被抢占或睡眠）时，`rcu_note_context_switch()` 把它挂到
   所在 `rcu_node` 的 `blkd_tasks` 链表，并标记 `blocked`；
   而 CPU 自己**照常记一次 QS**（这个 CPU 此刻确实不在临界区里了）；
3. GP 的结束条件变成"两条同时满足"：
   - 所有 CPU 都报告过 QS；
   - 没有任务还挂在 `blkd_tasks` 上阻塞着这个 GP。

   任务最终执行 `rcu_read_unlock()`、嵌套计数回到 0 时，走 `rcu_read_unlock_special()`
   把自己从链表摘掉并向上汇报，GP 才能继续。

| | 非抢占 RCU（`=n`） | PREEMPT_RCU（`=y`） |
| --- | --- | --- |
| `rcu_read_lock()` | `preempt_disable()` | `current->rcu_read_lock_nesting++`，不关抢占 |
| 读者能否被抢占 | 不能 | 能 |
| 临界区内发生上下文切换 | 等同于读者已退出，记 QS | 读者可能还在：任务挂入 `blkd_tasks`，CPU 另记 QS |
| GP 等待的对象 | CPU | CPU **和**被挂起的读者任务 |
| `rcu_read_lock_nesting` | 没有这个字段 | `task_struct` 的成员，每任务一份 |
| 日志前缀 | `rcu_sched` | `rcu_preempt` |
| 何时开启 | `CONFIG_PREEMPTION` 未开（`PREEMPT_NONE` / `PREEMPT_VOLUNTARY`） | `CONFIG_PREEMPTION=y` 时自动开启（`default y if PREEMPTION`） |

#### 第三步：放到本模块里，时间线是这样的

```text
rcu_blocked_reader                       内核 / RCU
------------------                       ----------------------------------------
rcu_read_lock()                          nesting: 0 -> 1
schedule_timeout_interruptible()
  +- schedule() ----------------------->  rcu_note_context_switch(preempt=false)
                                           - WARN_ON_ONCE：自愿切换（见下文）
                                           - 任务挂入 rnp->blkd_tasks，标记 blocked
                                           - rcu_qs()：本 CPU 记一次 QS  [OK]
（每 50 ms 醒来再睡，共 70 s）             任务一直留在 blkd_tasks 上

rcu_gp_waiter
synchronize_rcu() -------------------->  启动新 GP；各 CPU 陆续报 QS  [OK]
                                           但 blkd_tasks 里仍有读者  [BLOCKED]
                                             -> GP 无法结束
                                           超过 rcu_cpu_stall_timeout（21 s）
                                             -> stall 报告 -> panic_on_rcu_stall -> panic
```

**所以本模块里没有"stall CPU"**：读者睡眠时已让出 CPU，该 CPU 的 QS 早已上报；
卡住 GP 的是链表上那个任务。stall 报告点名的是任务（PID），不是 CPU。

#### 睡在读侧临界区里，到底算不算"合法"

- **非抢占内核：不行。** 见第一步——睡眠被当成 QS，GP 会提前结束；
  开了 `CONFIG_PREEMPT_COUNT` 时还会报 `BUG: scheduling while atomic`。
- **PREEMPT_RCU：实现扛得住，但不是被鼓励的用法。** 睡眠和被抢占走的是同一条
  "挂入 `blkd_tasks`"的路径，所以 GP 会正确地等它——这正是本模块能稳定复现 stall 的原因。
  但内核对"自愿"切换有一道检查：v5.14 的 `rcu_note_context_switch()` 里是
  `WARN_ON_ONCE(!preempt && rcu_preempt_depth() > 0)`，
  读者**主动**睡眠会在 dmesg 打出一条一次性的 WARNING。

对本模块的实际影响：

- vmcore 的 dmesg 里会**先**出现一条指向 `rcu_note_context_switch` 的 WARNING，
  这是预期现象，不是另一个故障。它会出现在读者进入临界区后的**第一次**
  `schedule_timeout()`，也就是加载模块后的第一个睡眠步进，远早于 stall 检测；
- 如果测试机设置了 `panic_on_warn=1`，会在 stall 出现**之前**就 panic，
  拿到的 vmcore 就不是预期的 RCU stall 样本。加载模块前请确认
  `cat /proc/sys/kernel/panic_on_warn` 为 `0`。

> 以上按 v5.14 源码核对；其他内核版本请对照 `kernel/rcu/tree_plugin.h` 确认。

#### 怎么读 stall 日志里的 PREEMPT_RCU 痕迹

```text
rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
rcu: 	Tasks blocked on level-0 rcu_node (CPUs 0-3): P12345/1:b..l
rcu: 	(detected by 1, t=21002 jiffies, g=..., q=..., ncpus=4)
task:rcu_blocked_rea state:S ...       <- 紧跟着 sched_show_task() 打出的任务栈（comm 截断为 15 字符）
```

- **`rcu_preempt`**（前缀）：GP 所属的实现名。`PREEMPT_RCU=y` 时是 `rcu_preempt`，
  `=n` 时是 `rcu_sched`。v4.20 起各 flavor 已合并，`rcu_bh` 不再单独出现。
  **看前缀就能反推内核是否开了 PREEMPT_RCU**；
- **`level-0`** 是 `rcu_node` 树的**层级**，不是"读者的嵌套层级"。
  默认叶子扇出为 16，CPU 数不超过它时整棵树只有一个 `rcu_node`，所以是 level-0；
  CPU 更多的机器会出现 level-1、level-2……；
- **`(CPUs 0-3)`** 是这个 `rcu_node` **覆盖**的 CPU 范围，不是 stall CPU；
- **`P12345/1:b..l`**：PID 12345，读侧嵌套深度 1；后面四个字符是标志位，`.` 表示未置位：
  `b` = 已被挂起（blocked），`q` = need_qs，`e` = exp_hint，`l` = 在 `blkd_tasks` 链表上。
  本模块的读者典型情况下是 `b` 与 `l` 置位。

#### 怎么确认测试机是否支持

```bash
# 1. 内核配置（各发行版默认值不同，以实际结果为准）
grep -E 'CONFIG_PREEMPT_RCU=|CONFIG_PREEMPT(_VOLUNTARY|_NONE|_DYNAMIC)?=' /boot/config-$(uname -r)
# 或
zgrep -E 'CONFIG_PREEMPT_RCU=' /proc/config.gz

# 2. 启动日志里的 RCU 横幅
dmesg | grep -i 'hierarchical RCU implementation'
#   Preemptible hierarchical RCU implementation.  -> PREEMPT_RCU=y
#   Hierarchical RCU implementation.              -> PREEMPT_RCU=n
# 运行很久后横幅可能已被冲出 ring buffer，可改用：
journalctl -k -b | grep -i 'hierarchical RCU implementation'

# 3. 在 vmcore 里（crash）
crash> log | grep -i "hierarchical RCU"
crash> task -R rcu_read_lock_nesting,rcu_read_unlock_special <pid>
#   rcu_read_lock_nesting 成员只在 PREEMPT_RCU 内核里存在；
#   非抢占 RCU 内核上这条命令会报成员不存在
```

输出 `CONFIG_PREEMPT_RCU=y` 才能用本模块当前形态。若为 `n`，请改用忙等
（`mdelay`）型 stall——代价是会连带触发 soft lockup，且 `rmmod` 可能挂死。

### Quiescent State（静止状态，QS）

一个 CPU 的"我这会儿肯定不在任何 RCU 读侧临界区里"的声明。
满足任一条件即可：

| 事件 | 说明 |
| --- | --- |
| 上下文切换 | 切走意味着原任务不会再继续执行临界区代码 |
| 返回用户态 | 内核态 RCU 临界区一定已经退出 |
| 进入 idle | 空闲 CPU 不持有任何临界区 |

**所有 CPU 都报告过一次 QS = 一个 grace period 结束**。本模块的手段就是让
某个 CPU 永远无法提供这个声明。

### Grace Period（宽限期，GP）与 GP 序号

从 updater 把旧元素摘链那一刻开始，到"所有在摘链前就存在的读者都已离开
临界区"为止的这段时间。vmcore 日志里的 `g=12345` 就是 GP 序号
（`gp_seq`），作用是让"哪个 GP 卡住了、卡了多久"可以精确定位。

`q=` 表示 RCU 队列累计处理次数，`ncpus=` 表示参与本次 GP 的 CPU 数量。
三者一起看：`g` 停滞而 `q` 不变，说明 GP 完全没有推进。

#### 一个 GP 默认多久

**没有"默认值"这个说法——正常 GP 的长度完全由"恰好有任务在临界区里"决定**，
是一个量级在**几毫秒到几十毫秒**的动态值，只有下界没有上界：

| 场景 | 典型耗时 | 说明 |
| --- | --- | --- |
| 空闲系统 | ~1–10 ms | 每个 CPU 都在 idle，静止信号很快收齐 |
| 有负载（正常 RCU 用法） | 10–50 ms | 要等正在跑的读者自己退出 |
| 用了 `synchronize_rcu_expedited()` | 亚毫秒级 | 走 IPI 强制静止，代价高 |
| `CONFIG_RCU_NOCB` / 大机器 | 数十 ms | 要等所有 nocb CPU 的静止信号 |

其中真正可调的常量是 **GP kthread 的轮询间隔**（`rcu_gp_kthread` 等 CPU 时的睡眠时长，

`kernel/rcu/tree.c` 里的 `jiffies_till_first_fqs` / `jiffies_till_next_fqs`），
默认通常是 3 个 jiffy（100 Hz 内核约 30 ms，1000 Hz 内核约 3 ms）——
但它只是"多久检查一次"，不是"GP 必须多久完成"。

真正决定**什么时候报 stall** 的是另一个参数：

```bash
# 单位：秒，默认 21
cat /sys/module/rcupdate/parameters/rcu_cpu_stall_timeout
```

它有三条规则需要注意：

1. `rcu_cpu_stall_timeout` 的单位是**秒**，而 GP kthread 内部用的是 jiffies，
   两者不要混；
2. 该值会被**自动向上调整**为不小于 `jiffies_till_first_fqs + jiffies_till_next_fqs`
   的整数倍，避免天然抖动误报；
3. 它有一个**硬性下限 3 秒**，即使写入更小的值也会被修正回去。

所以完整判据是：**某个 CPU 连续 `rcu_cpu_stall_timeout`（默认 21 s）
没有报告静止状态 → 打印 stall 报告**。本模块的默认 `stall_duration_ms=70000`
（70 s）刻意取了三倍以上余量，避免因系统负载导致检测时间飘移而偶发不触发。

#### 内核开发有没有规范限制临界区时长

**有规范，但没有硬性上限数字，也没有编译期检查**——它属于
"文档约束 + 代码评审 + 运行时兜底"三层：

**第一层：文档约定（`Documentation/RCU/checklist.rst`）**

RCU 的官方 checklist 明确要求：

- RCU 读侧临界区应当**短小、无阻塞、无睡眠**（PREEMPT_RCU 的实现能容纳被抢占的读者，
  但不意味着可以主动睡眠：v5.14 会对此打 `WARN_ON_ONCE`，普通内核代码不要这么做）；
- 临界区内**不要做耗时运算**、不要遍历超长链表、不要调用可能睡眠的函数
  （`kmalloc(GFP_KERNEL)`、`mutex_lock()`、`copy_to_user()` 等）；
- 临界区内**不要嵌套获取非 RCU 锁**（会放大争用，也容易引入锁序问题）；
- 优先用 `rcu_dereference()` / `rcu_assign_pointer()` 保持指针安全，
  而不是靠"临界区足够长"来碰运气。

**第二层：代码评审的隐性经验值**

社区评审中，"临界区里跑了多久"会按下面的经验看待：

| 时长 | 评审态度 |
| --- | --- |
| < 10 µs | 理想，绝大多数内核代码都在这个量级 |
| 10 µs – 1 ms | 可接受，但若在热路径会追问 |
| 1 ms – 10 ms | 需要理由，通常要求改成 `call_rcu()` 异步化 |
| > 10 ms | 基本会被要求返工；若是长遍历，应改用 SRCU 或 `rcu_read_lock_sched` 拆分 |
| > 100 ms | 视为缺陷，会显著拖慢所有 `synchronize_rcu()` 调用者 |

**第三层：运行时兜底（本模块利用的就是这一层）**

内核不会在临界区超时时"报错"，而是通过下面几个机制间接暴露问题：

| 机制 | 触发条件 | 后果 |
| --- | --- | --- |
| RCU stall 检测（`rcu_cpu_stall_timeout`，默认 21 s） | 某 CPU 长期不静止 | 打印报告；`panic_on_rcu_stall=1` 时 panic |
| Expedited stall 检测（`rcu_exp_cpu_stall_timeout`，默认 3 s） | `synchronize_rcu_expedited()` 等太久 | 打印 `expedited stalls` |
| `rcu_preempt kthread starved` 告警 | GP kthread 长时间无法运行 | 提示回调积压 |
| `scheduling while atomic` | 非抢占 RCU 临界区内睡眠 | `BUG()` / 栈回溯 |

也就是说：**"临界区不能长"是软约束，"超过 21 秒会被检测到"是硬兜底**。
两者之间有巨大的空档——1 秒的临界区不会被任何机制报错，
但已经足以让所有 `synchronize_rcu()` 调用者延迟 1 秒。

**实践建议**

- 需要"延迟执行"就注册 `call_rcu()`，不要用长临界区代替；
- 需要"保护长遍历"就用 **SRCU**（`srcu_read_lock()`），它允许睡眠且不阻塞
  普通 GP；
- 需要"跨临界区保留引用"就用**引用计数**（`kref` / `refcount_t`）；
- 确实无法缩短时，在注释里写明原因和实测时长，评审时主动说明。

> 补充：`CONFIG_RCU_CPU_STALL_CPUTIME` 可让 stall 报告额外打印每个 CPU
> 在本次 GP 期间消耗的 CPU 时间（`(1234 ticks this GP)` 那一段），
> 对判断"是哪个临界区拖慢了 GP"很有帮助。

### Callback / callback 积压

updater 通过 `call_rcu()` 注册一段"GP 结束后再执行"的回调（典型是 `kfree_rcu`）。
回调在软中断里批量执行，按 GP 序号分批次（`rcu_do_batch`）。

日志形态 `rcu: rcu_preempt kthread starved for 21000 jiffies! g=... f=... RCU_GP_WAIT_FQS(5)`，
然后跟随 `rcu: INFO: rcu_preempt detected stalls` 时，往往已经积压了成千上万个回调——
GC 无法前进，所有延迟释放都被拖住。这也解释了为什么 RCU stall 会连锁造成
OOM 或内存水位告警。

### GP kthread（`rcu_preempt` 内核线程）

每个 RCU flavor 有一个专门推进 GP 的 `kthread`（日志里的 `rcu_preempt`、
`rcu_sched`、`rcu_bh` 等）。它不在 vmcore 报告里"卡住"，因为它是等固定超时
（`RCU_GP_WAIT_FQS`，几 jiffies）就醒来检查一次，循环等待 CPU 就绪。
**看到它时不要误判为"GP 线程挂死"**，要看的是它等待的对象是谁。

### FQS（Force Quiescent State）

GP 线程等不及时的兜底手段：给指定 CPU 发 IPI 或 request 一个
"强制静止"请求。它在 logs 里表现为 `FQS` 状态与 `!`（感叹号）。
stall CPU 上的 `!` 表示该 CPU 的强制请求也失败了——这是"最坏情况"标记，
通常意味着该 CPU 连中断都无法正常处理（更接近 hard lockup 了）。

### Stall 报告里的一串符号

```text
rcu:   3-...!: (0 ticks this GP) idle=1a2/1/0x4000000000000000 softirq=123/456 fqs=7890
      ││ │ ││   │                    │                        │            └─ FQS 累计等待 jiffies
      ││ │ ││   │                    │                        └─ 软中断计数：累计/上次 GP 后
      ││ │ ││   │                    └─ idle 时间占比与嵌套信息（内核内部格式）
      ││ │ ││   └─ 本 GP 期间该 CPU 的 tick 数，0 表示几乎没有正常调度
      ││ │ │└─ 该 CPU 的 FQS 强制静止请求失败（!）
      ││ │ └─ 该 CPU 处于 idle 状态（. 表示 idle，`-` 表示需要 FQS）
      ││ └─ 该 CPU 在等待某个 GP
      │└─ 该 CPU 上有多个（嵌套）临界区
      └─ CPU 编号，即 stall CPU
```

> 各内核版本字段格式略有差异，以当前内核 `Documentation/RCU/stallwarn.rst` 为准。

### RCU Reader / Updater / RCU flavor

| 名词 | 含义 | 本模块中的角色 |
| --- | --- | --- |
| Reader | 在 `rcu_read_lock()` 与 `rcu_read_unlock()` 之间的代码 | `rcu_blocked_reader` |
| Updater | 修改数据并等待 GP 后才释放旧数据的一方 | `rcu_gp_waiter`（用 `synchronize_rcu()` 模拟） |
| RCU flavor | RCU 的变体名。v4.20 起各 flavor 已合并，现在日志里只会见到 `rcu_preempt`（`PREEMPT_RCU=y`）或 `rcu_sched`（`PREEMPT_RCU=n`），`rcu_bh` 已不再单独存在 | 本模块依赖 `rcu_preempt` |

> `synchronize_rcu()` 是"同步版 updater"：它不注册回调，而是原地等待一个 GP 结束。

下面把这三个函数展开讲。它们是 RCU 编程接口的"全部"，理解它们就理解了本模块为什么只需三行核心代码就能搞崩内核。

#### `rcu_read_lock()` — 声明"我进入读侧临界区了"

**原型**（`include/linux/rcupdate.h`）：

```c
static inline void rcu_read_lock(void);
```

**功能**：（PREEMPT_RCU 上）在当前任务的 `task_struct` 上把 `rcu_read_lock_nesting` 加 1
（非抢占 RCU 上则是 `preempt_disable()`），标记"从这个时刻到对应的 `rcu_read_unlock()` 为止，我不会访问到已摘链的数据"。

**它不做什么**（这点最容易误解）：

| 常见误解 | 实际情况 |
| --- | --- |
| 它会加锁、会阻塞写者 | **完全不会**。它是一个计数器自增，写者照常摘链，RCU 从不阻塞任何人 |
| 它会关抢占/关中断 | 非抢占 RCU 上等价于 `preempt_disable()`；**PREEMPT_RCU 上只是 `rcu_read_lock_nesting++`，不关抢占**，读者因此可以被抢占 |
| 它能防止数据被释放 | 只能防止**已存在的旧数据**被立刻释放；防止新数据被摘链需要 rcu_assign_pointer 等配合 |

**关键语义**：它不是"互斥"，而是**"延迟释放承诺"**。
写者摘链后不立即 `kfree()`，而是等所有已进入临界区的读者都离开——
这样读者哪怕正在用旧指针，也不会访问到已释放内存（use-after-free）。

**返回值**：无。**调用上下文**：任何上下文（进程、软中断、硬中断），
只要不主动睡眠（PREEMPT_RCU 能容纳被抢占的读者，睡眠也不会让 GP 误判，但 v5.14 会 WARN；本模块是刻意违规，见 7 · PREEMPT_RCU）。

```c
rcu_read_lock();
p = rcu_dereference(gp);   /* 安全读取指针 */
use(p);                    /* 临界区内使用，内存一定有效 */
rcu_read_unlock();
```

在本模块里，读者调用它之后**再也没有及时调用解锁**，这就是全部"故障"来源。

#### `rcu_read_unlock()` — 声明"我离开读侧临界区了"

**原型**：

```c
static inline void rcu_read_unlock(void);
```

**功能**：把 `rcu_read_lock_nesting` 减 1。减到 0 时：

1. 该任务不再被计为"活动读者"；
2. 如果此时有 GP 正在等待它，则触发
   `rcu_read_unlock_special()` → 通知 GP kthread"我这边空了"；
3. GP kthread 收齐所有 CPU 的静止信号后，推进 GP 并唤醒
   `synchronize_rcu()` 的等待者、执行 `call_rcu()` 注册的回调。

**必须成对出现**，且必须在**同一任务上下文**中调用（PREEMPT_RCU 检查的是
调用者任务的计数器）。以下写法都是错的：

```c
rcu_read_lock();
queue_work(...);       /* 错：在另一个上下文里 unlock */
/* 工作函数里 */
rcu_read_unlock();
```

**本模块里的作用**：它是"解药"。`rmmod` 时 `kthread_stop()` 唤醒读者，
读者跳出循环后执行 `rcu_read_unlock()`，GP 立即恢复推进，
被挂住的 `synchronize_rcu()` 也随之返回。若用 `kill -9` 绕过它，
该任务的计数永远不会归零，RCU 会一直认为存在活动读者。

**与 `preempt_enable()` 的关系**：非抢占 RCU 上两者合一；
PREEMPT_RCU 上它是独立路径（可能就地处理特殊事件，也可能转到软中断），
所以**不能**用 `preempt_enable()` 替代 `rcu_read_unlock()`。

#### `synchronize_rcu()` — "我原地等一个 grace period 结束"

**原型**（`kernel/rcu/tree.c`）：

```c
void synchronize_rcu(void);
```

**功能**：阻塞当前任务，直到"下一个 GP 完整结束"。
它保证：**函数返回时，所有在调用前就已进入 `rcu_read_lock()` 的读者都已经离开临界区**。
这是 RCU 删除路径上"何时可以安全 `kfree()`"的最终判据。

**语义图示**：

```text
时间 ──────────────────────────────────────────────────────▶
        rcu_read_lock()          rcu_read_unlock()
reader  ├────── 读侧临界区 ────────┤
        │                         │
updater            synchronize_rcu() 开始
        │                         │
        │                   等待……│  ← 必须等 reader 离开
        │                         ▼
        │                  synchronize_rcu() 返回 → 此时可安全 kfree 旧数据
```

**返回值**：无（`void`）。**不返回错误**——它要么等到，要么被信号打断
（此时可能返回，历史上 `synchronize_rcu()` 可被信号中断，
新内核提供 `synchronize_rcu()` / `synchronize_rcu_expedited()` 区分）。

**调用限制**：

| 限制 | 原因 |
| --- | --- |
| **只能进程上下文** | 它要睡眠等待；中断/软中断里调用会 `BUG()` |
| 不能持有自旋锁 | 睡眠 + 持锁 → 死锁 |
| 不能持有 `mutex` 且该 mutex 被 GP 路径需要 | 罕见但可能 |
| 不能在 RCU 读侧临界区内调用 | 自己等自己离开，必然死锁 |
| 可能很慢 | 用 `_expedited` 版本可快但代价高（发 IPI） |

**与 `call_rcu()` 的区别**：

| | `synchronize_rcu()` | `call_rcu(callback)` |
| --- | --- | --- |
| 阻塞吗 | 是，原地等 | 否，立即返回 |
| 回调在哪跑 | 无回调 | 软中断（`rcu_do_batch`） |
| 适用上下文 | 仅进程上下文 | 任何上下文 |
| 本模块用它是为了 | **制造可见的等待点** | — |

本模块**故意**选 `synchronize_rcu()` 而不是 `call_rcu()`：前者会在 vmcore 的
任务栈里留下 `synchronize_rcu → wait_rcu_gp → schedule` 这样的明确阻塞链，
而 `call_rcu()` 只是"注册完就走"，栈上什么也看不到。这正是"为了让分析器看得见"
而做的设计取舍。

**为什么它会被本模块挂住**：`synchronize_rcu()` 内部循环等待 GP kthread
推进 GP 序号（`gp_seq`），而 GP 推进的前提是所有 CPU 都静止；
`rcu_blocked_reader` 所在 CPU 永远不静止，所以这个 `while` 永远不满足。
它不会报错、不会超时（没有内置超时），只会安静地睡在那里，直到
`rcu_cpu_stall_timeout` 到期后被检测器发现。

> 补充：`synchronize_rcu()` 在较新内核中会走到
> `synchronize_rcu_normal()` / `synchronize_rcu_expedited_wait()`，
> 具体路径随版本变化；用 `crash` 看栈时以实际版本为准，
> 但"停在 `schedule` 上等 GP 序号变化"这一点是不变的。

### hung task（不可中断睡眠超时）

与 RCU stall 是**两套独立机制**，但常同时出现在崩溃报告里：

- hung task 监控的是 `TASK_UNINTERRUPTIBLE`（`D` 状态）任务超过
  `hung_task_timeout_secs`（默认 120 s）；
- 本模块的读者是 `TASK_INTERRUPTIBLE`（`S` 状态），**不会**触发 hung task；
- 但被阻塞的 `synchronize_rcu()` 调用者若也处于 `D` 状态且超时，
  就会先触发 hung task 告警。这也是为什么本模块把等待者放在独立线程里——
  避免把两种告警混在同一份 vmcore 中。

### kdump / vmcore / kexec

| 名词 | 含义 |
| --- | --- |
| kdump | 预留一小块内存，panic 时用 `kexec` 加载的第二个内核接管并转储 |
| kexec | 从运行中内核直接跳转到另一个内核，不走 BIOS |
| vmcore | 崩溃内核的内存镜像（ELF core 格式） |
| `makedumpfile -d 31` | 过滤级别位掩码，会丢弃大量页面（包括模块代码页） |
| `crash` / `mod -s` | 分析工具；`mod -s` 用于把 `*.ko` 的符号加载进会话 |

## 8. 注意事项

- `panic_on_rcu_stall=1` 是全局 sysctl，测试后记得改回 `0`；
- `panic_on_warn` 必须为 `0`（原因见
  [7. 名词解释 · PREEMPT_RCU](#preempt_rcu可抢占-rcu)）：读者第一次
  `schedule_timeout()` 就会命中 `rcu_note_context_switch()` 里的 `WARN_ON_ONCE`，
  若 `panic_on_warn=1` 会在第一个 jiffy 就 panic，抓不到 stall；
- `stall_duration_ms > 120000`（默认 `hung_task_timeout_secs`）时，vmcore 里会**多**
  一条 hung task 报告。真正被 hung_task 检查的是阻塞在 `synchronize_rcu()` 里的
  `rcu_gp_waiter`，不是处于 `S` 态的读者；
- 默认 `-d 31` 的 `makedumpfile` 会丢弃大量页面；若需要模块符号或完整栈，
  可调整为 `-d 17`（详见同目录 `issue.txt`），并保证 `rcu_stall_mod.ko` 可被
  crash 通过 `mod -s` 加载；
- 生成的报告应包含线程名 `rcu_blocked_rea`（`rcu_blocked_reader` 的 15 字符截断形式）
  与 `rcu_gp_waiter`，否则说明模块没有被正确加载或进程已被提前回收；
- `rmmod` 时若等待者仍在握手等待期（最长 10 s），`kthread_stop(waiter)`
  可能被阻塞到握手超时——kthread 收不到信号，那次唤醒只是虚假唤醒。
  这期间模块卸载会卡住，属预期行为；
- 源码用 `kthread_create()` + `get_task_struct()` + `wake_up_process()` 而非
  `kthread_run()`：两个线程函数都会正常返回（等价于 `do_exit`），
  `kthread_stop()` 的文档要求调用方保证 `task_struct` 不会消失，
  引用计数就是为此加的保险。