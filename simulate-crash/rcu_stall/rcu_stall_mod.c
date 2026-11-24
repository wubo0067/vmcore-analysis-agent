/*
 * rcu_stall_mod.c - RCU Stall 模拟内核模块
 *
 * 用途：在内核测试虚拟机上故意制造一次可复现的 RCU CPU stall，使 kdump 能抓取
 * 相关的 vmcore，用于验证 vmcore-analysis-agent 的 lock_hang MCP 工具对
 * "阻塞的 RCU 读者 + 等待宽限期的任务 + RCU stall 检测栈" 的识别与归因能力。
 *
 * 模块创建两个内核线程：
 *   rcu_blocked_reader - 在 rcu_read_lock() 临界区内长时间睡眠。在 PREEMPT_RCU 上
 *                        它睡眠时会作为 "阻塞任务" 被挂到 rcu_node->blkd_tasks 上，
 *                        grace period 必须等它退出临界区才能推进；
 *   rcu_gp_waiter      - 确认读者已进入临界区后调用 synchronize_rcu()，成为
 *                        宽限期等待者，在 vmcore 中留下明确的阻塞点。
 *
 * 使用前提与风险：
 *   - 仅在专用测试机上使用，会触发 panic 或长时间挂起；
 *   - 必须 CONFIG_PREEMPT_RCU=y（见下方编译期校验）；
 *   - 需要 kernel.panic_on_rcu_stall=1 才会 panic 并生成 vmcore；
 *   - 需要 kernel.panic_on_warn=0。读者第一次 schedule_timeout() 时，
 *     rcu_note_context_switch() 里的 WARN_ON_ONCE(!preempt && rcu_preempt_depth() > 0)
 *     会命中（这是预期行为，正是它把任务登记进 blkd_tasks），
 *     若 panic_on_warn=1 会在第一个 jiffy 就 panic，抓不到 stall；
 *   - 读者采用可中断睡眠，不会触发 soft lockup，与忙等型 stall 场景区分开；
 *   - stall_duration_ms 超过 hung_task_timeout_secs（默认 120s）时，
 *     vmcore 中会额外出现一条 hung task 报告，属预期现象。
 */

/*
 * pr_fmt 会让模块内所有 pr_* 输出自动带上 "模块名:函数名: " 前缀，
 * 便于在 dmesg / vmcore 日志中区分本模块的打点与内核自身输出。
 * 注意：pr_* 的格式串里不要再手写 "rcu_stall_mod: "，否则前缀会重复。
 */
#define pr_fmt(fmt) "%s:%s(): " fmt, KBUILD_MODNAME, __func__

/* 容器初始化 / 退出宏：module_init、module_exit、__init、__exit */
#include <linux/init.h>
/* 基础类型与 pr_* 日志宏 */
#include <linux/kernel.h>
/* Kconfig 选项判定的 IS_ENABLED / IS_BUILTIN 宏 */
#include <linux/kconfig.h>
/* 内核模块元数据与 module_param 参数注册 */
#include <linux/module.h>
/* RCU 原语：rcu_read_lock / rcu_read_unlock / synchronize_rcu */
#include <linux/rcupdate.h>
/* kthread_create / kthread_stop / kthread_should_stop */
#include <linux/kthread.h>
/* 安排超时睡眠：schedule_timeout_interruptible */
#include <linux/sched.h>
/* allow_signal / flush_signals / signal_pending */
#include <linux/sched/signal.h>
/* 时间单位换算：msecs_to_jiffies / jiffies_to_msecs / time_before */
#include <linux/jiffies.h>
/* 完成量：用于读者与等待者之间的启动握手 */
#include <linux/completion.h>
/* 互斥锁：保护全局线程指针，避免 init / exit 并发访问 */
#include <linux/mutex.h>
/* IS_ERR / PTR_ERR 错误指针判定；ETIMEDOUT 等错误码 */
#include <linux/err.h>

/*
 * 编译期校验：本模块的故障模型依赖 PREEMPT_RCU。
 *
 * 为什么必须是 PREEMPT_RCU：
 *   - 非抢占 RCU 下 rcu_read_lock() 只是 preempt_disable() + 编译屏障，
 *     在临界区内睡眠属于非法用法，会直接 "sleeping in atomic" 报错；
 *   - 只有 PREEMPT_RCU 允许读者在临界区内被抢占/睡眠，并由
 *     rcu_note_context_switch() 把该任务登记到 rcu_node->blkd_tasks，
 *     从而在磁盘上留下"某个 task 阻塞 GP"的证据。
 * kernel-devel 的 include/generated/autoconf.h 中可见该配置项。
 */
#if !IS_ENABLED(CONFIG_PREEMPT_RCU)
#error "rcu_stall_mod requires CONFIG_PREEMPT_RCU=y"
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Calm.Wu");
MODULE_DESCRIPTION("RCU Stall Simulator for Testing and Debugging");

/*
 * stall_duration_ms - 读者保持 RCU 读侧临界区的时长（毫秒）
 *
 * 默认 70s，需要大于 RCU stall 检测阈值：
 *   /sys/module/rcupdate/parameters/rcu_cpu_stall_timeout
 * 可通过 insmod 参数覆盖，例如 stall_duration_ms=80000。
 * module_param 在 /sys/module/rcu_stall_mod/parameters/ 下暴露该值，
 * 便于测试机在不重新编译的情况下调整。
 */
static uint32_t stall_duration_ms = 70000;
module_param(stall_duration_ms, uint, 0644);
MODULE_PARM_DESC(stall_duration_ms,
                 "Duration to hold RCU lock in milliseconds");

/*
 * 每次睡眠的步长：读者不会一次性睡满 stall_duration_ms。
 * 分片睡眠的唯一目的是让 kthread_stop() 的唤醒能在有限时间内生效
 * （最多等待一个步长），以及让 signal_pending() 检查有机会被及时执行。
 *
 * 注意：这不是为了规避 hung_task 检测——读者处于 TASK_INTERRUPTIBLE（S 态），
 * hung_task 只检查 TASK_UNINTERRUPTIBLE（D 态），本来就不会命中它。
 */
#define RCU_READER_STEP_MS 50

/* GP 等待者等待读者进入临界区的上限，防止读者启动失败时永久阻塞 */
#define RCU_READER_ENTER_TIMEOUT_MS 10000

/*
 * 两个线程的 task_struct 指针，仅在持有 thread_mutex 时读写。
 *
 * 这两个指针额外持有一个引用计数（get_task_struct），原因见
 * rcu_stall_spawn()：threadfn 自行返回（do_exit）后 task_struct 会被释放，
 * 若模块仍持有裸指针并在 rmmod 时传给 kthread_stop()，就是 use-after-free。
 */
static struct task_struct *reader_task;
static struct task_struct *gp_waiter_task;

/* 保护 reader_task / gp_waiter_task 的互斥锁 */
static DEFINE_MUTEX(thread_mutex);

/*
 * 启动握手：读者确认已进入 RCU 读侧临界区后 complete() 它，
 * 等待者在调用 synchronize_rcu() 前等待它，避免等待者先于读者阻塞住 GP。
 */
static DECLARE_COMPLETION(reader_entered);

/*
 * rcu_stall_spawn - 创建内核线程并持有其 task_struct 引用
 *
 * 为什么不直接用 kthread_run()：
 *   kthread_run() = kthread_create() + wake_up_process()，两步之间线程可能
 *   已经跑完 threadfn 并 do_exit，等调用者拿到指针时 task_struct 已释放。
 *   拆成 create + get_task_struct + wake_up 后，引用计数保证 task_struct
 *   至少要等到 rcu_stall_stop_threads() 里 put_task_struct() 才会消失，
 *   满足 kthread_stop() 文档的要求：
 *     "If threadfn() may call do_exit() itself, the caller must ensure
 *      task_struct can't go away."
 *   本模块两个线程函数都会正常 return（等价于 do_exit），所以必须这么做。
 *
 * 线程名字会被截断到 TASK_COMM_LEN-1 = 15 个字符：
 *   "rcu_blocked_reader" 实际显示为 "rcu_blocked_rea"，
 *   ps / top / pgrep 都必须用截断后的名字。
 */
static struct task_struct *rcu_stall_spawn(int (*fn)(void *), const char *name)
{
    struct task_struct *task;

    /*
     * kthread_create(): 只创建线程，不唤醒。
     * 返回的 task_struct 尚未被 wake_up_process()，因此不会先于
     * get_task_struct() 执行到 do_exit()。
     */
    task = kthread_create(fn, NULL, "%s", name);
    if (IS_ERR(task))
        return task;

    /*
     * get_task_struct(): 增加引用计数，把 task_struct 的生命周期
     * 延长到本模块显式 put_task_struct() 为止。
     */
    get_task_struct(task);

    /*
     * wake_up_process(): 让线程真正开始执行 threadfn。
     * 此后线程随时可能结束并 do_exit，但引用计数已保证指针有效。
     */
    wake_up_process(task);

    return task;
}

/*
 * rcu_stall_thread - RCU 读者线程
 *
 * 目的：让本任务长时间停留在 RCU 读侧临界区内。
 *
 * 在 PREEMPT_RCU 上，读者睡眠时 CPU 本身照常上报 quiescent state
 * （rcu_note_context_switch() 末尾就是 rcu_qs()），真正被卡住的是
 * "挂在 rcu_node->blkd_tasks 上的这个任务"：只要该任务还没执行
 * rcu_read_unlock()，rnp->gp_tasks 就不会变成 NULL，当前 grace period
 * 也就无法完成。最终触发
 *   "rcu: INFO: rcu_preempt detected stalls on tasks"
 * 检测日志。
 */
static int rcu_stall_thread(void *data)
{
    /*
     * 用"截止时刻"而不是"剩余计数"来计时。
     *
     * schedule_timeout() 的返回值是本次调用那个 timeout 的剩余值，
     * 不是总时长的剩余值：睡满 50ms 后它返回 0。若把返回值回写成总剩余量，
     * 第一次循环结束就会变成 0，循环立刻退出，读者只持有约 50ms，
     * stall 永远不会发生。这里改为记录起始 jiffies 并计算 deadline。
     */
    unsigned long start, deadline;

    /*
     * allow_signal(): 允许把 SIGINT 投递给本线程。
     *
     * kthreadd() 在主循环里调用了 ignore_signals()，所有 kthread 子线程
     * 都继承 SIG_IGN，信号会被"静默丢弃"（allow_signal 的注释原文就是
     * "so that they don't get converted to SIGKILL or just silently dropped"）。
     * 不调用它的话，signal_pending() 永远为假，下面的提前退出分支是死代码，
     * 测试人员的 kill -INT 也完全无效。
     */
    allow_signal(SIGINT);

    start = jiffies;
    /*
     * msecs_to_jiffies(): 把毫秒换算成内核 tick 计数。
     * 内核态计时 API 的单位都是 jiffies，不能直接传毫秒。
     */
    deadline = start + msecs_to_jiffies(stall_duration_ms);

    /*
     * task_pid_nr(current): 取当前线程的 PID。
     * 打印它是为了在 dmesg 与 vmcore 的 ps 输出之间建立对应关系。
     */
    pr_info("RCU reader %s PID %d entering rcu_read_lock for %u ms\n",
            current->comm, task_pid_nr(current), stall_duration_ms);

    /*
     * rcu_read_lock(): 标记进入 RCU 读侧临界区。
     * 在 PREEMPT_RCU 上它只做 current->rcu_read_lock_nesting++ 和
     * 编译期屏障，并**不**禁用抢占，因此临界区内可以睡眠——
     * 这正是本模块能在 rcu_read_lock() 与 rcu_read_unlock() 之间
     * 调用 schedule_timeout_interruptible() 的前提。
     * 不要把这里的行为与非抢占 RCU（rcu_read_lock() = preempt_disable()）混淆。
     */
    rcu_read_lock();

    /*
     * schedule_timeout_interruptible(1): 主动让出 CPU 一个 jiffy。
     *
     * 目的不是"等 1 jiffy"，而是强制走一次上下文切换，触发
     * rcu_note_context_switch()，让内核把当前任务登记到 blkd_tasks，
     * 从而使 GP 确实被这个任务挡住（而不只是"理论上挡住"）。
     * 这次调用会命中 rcu_note_context_switch() 里的
     *   WARN_ON_ONCE(!preempt && rcu_preempt_depth() > 0)
     * 属预期行为，测试机需 panic_on_warn=0。
     */
    schedule_timeout_interruptible(1);

    /*
     * complete(&reader_entered): 唤醒等待 reader_entered 的线程。
     * 此时读者已进入临界区且已走过一次上下文切换，
     * blkd_tasks 登记完成，等待者可以安全地进入 synchronize_rcu()。
     */
    complete(&reader_entered);

    /*
     * 主循环：分片睡眠，持续保持 RCU 读锁。
     *
     * 循环条件同时检查：
     *   time_before(jiffies, deadline) - 还没到截止时刻；
     *   kthread_should_stop()          - 未收到 kthread_stop() 的停止请求。
     */
    while (time_before(jiffies, deadline) && !kthread_should_stop()) {
        /*
         * signal_pending(current): 判断当前线程是否有待处理信号。
         * 配合开头的 allow_signal(SIGINT)，测试人员可以提前结束模拟，
         * 无需等待完整时长。
         */
        if (signal_pending(current)) {
            /*
             * flush_signals(current): 清空待处理信号，避免信号残留影响
             * 后续清理流程与下一次循环判断。
             */
            flush_signals(current);
            pr_info("RCU reader interrupted by signal, exiting early\n");
            break;
        }

        /*
         * schedule_timeout_interruptible(): 进入 TASK_INTERRUPTIBLE 睡眠。
         * 单次只睡 RCU_READER_STEP_MS，使 kthread_stop() 的唤醒能在
         * 一个步长内被感知，也让上面的 signal_pending() 检查足够及时。
         * 返回值这里不需要——时长由 deadline 统一判定。
         */
        schedule_timeout_interruptible(msecs_to_jiffies(RCU_READER_STEP_MS));
    }

    /*
     * rcu_read_unlock(): 退出 RCU 读侧临界区。
     * 内核会把当前任务从 blkd_tasks 摘除，rnp->gp_tasks 得以推进，
     * 被挂住的 synchronize_rcu() 调用者随即返回。
     */
    rcu_read_unlock();

    /*
     * jiffies_to_msecs(jiffies - start): 实际占用临界区的时长，
     * 与 stall_duration_ms 可对照核对（被信号或 kthread_stop 提前打断时更短）。
     */
    pr_info("RCU reader released its read-side critical section after %u ms\n",
            jiffies_to_msecs(jiffies - start));
    return 0;
}

/*
 * rcu_gp_waiter_thread - RCU 宽限期等待者线程
 *
 * 目的：在读者持有 RCU 读锁期间调用 synchronize_rcu()，成为一个可见的
 * "等待 grace period 完成" 任务。vmcore 中它的调用栈会停在
 * synchronize_rcu -> __wait_rcu_gp -> wait_for_completion 路径上，
 * 是 lock_hang 分析器关联 stall 根因的关键证据。
 */
static int rcu_gp_waiter_thread(void *data)
{
    long remaining;

    /*
     * wait_for_completion_interruptible_timeout(&reader_entered, timeout):
     * 等待读者完成启动握手，最多等待 RCU_READER_ENTER_TIMEOUT_MS。
     *
     * 返回值语义：
     *   > 0 - 完成量已触发，返回剩余 jiffies；
     *   = 0 - 超时，读者始终没有进入临界区；
     *   < 0 - 被信号中断，返回 -ERESTARTSYS。
     * 超时或中断时直接退出，避免在没有真实 stall 的场景下永久阻塞。
     */
    remaining = wait_for_completion_interruptible_timeout(
        &reader_entered, msecs_to_jiffies(RCU_READER_ENTER_TIMEOUT_MS));
    if (remaining <= 0) {
        pr_warn("RCU GP waiter did not observe the blocked reader: %ld\n",
                remaining);
        return remaining < 0 ? remaining : -ETIMEDOUT;
    }

    pr_info("RCU GP waiter %s PID %d entering synchronize_rcu\n",
            current->comm, task_pid_nr(current));

    /*
     * synchronize_rcu(): 阻塞直到当前 grace period 结束。
     *
     * 由于读者仍持有 RCU 读锁，此调用会长时间阻塞，形成：
     *   等待者 -> 等待 grace period -> 被读者的读侧临界区阻塞
     * 这条因果关系正是分析器需要还原的 stall 根因。
     * 它只能在允许睡眠的上下文调用（本线程满足条件）。
     */
    synchronize_rcu();
    pr_info("RCU grace period completed\n");
    return 0;
}

/*
 * rcu_stall_stop_threads - 停止并回收两个内核线程
 *
 * 顺序很重要：先停止读者释放 RCU 读锁，再回收等待者；
 * 否则 kthread_stop(waiter) 会卡在 synchronize_rcu() 里直到 stall 超时。
 *
 * 注意 kthread_stop() 可能阻塞较久：若等待者仍在
 * wait_for_completion_interruptible_timeout() 的握手等待期（最长 10s），
 * kthread_stop() 的唤醒对它只是虚假唤醒，它会继续睡到握手超时。
 */
static void rcu_stall_stop_threads(void)
{
    struct task_struct *reader, *waiter;

    /*
     * mutex_lock/unlock: 保护全局线程指针。
     * 先在锁内取出指针并置空，随后在锁外调用 kthread_stop，
     * 避免持有互斥锁期间阻塞等待线程退出而放大锁竞争。
     */
    mutex_lock(&thread_mutex);
    reader = reader_task;
    waiter = gp_waiter_task;
    reader_task = NULL;
    gp_waiter_task = NULL;
    mutex_unlock(&thread_mutex);

    /*
     * kthread_stop(): 置位 kthread_should_stop() 标志并唤醒目标线程，
     * 然后阻塞等待其线程函数返回。
     * 读者以 50ms 分片睡眠，因此这里最多等待一个步长即可返回。
     */
    if (reader) {
        kthread_stop(reader);
        /*
         * put_task_struct(): 释放 rcu_stall_spawn() 里取的引用。
         * 必须在 kthread_stop() 之后，且两者之间不能再访问 reader，
         * 因为引用归零后 task_struct 会立即被释放。
         */
        put_task_struct(reader);
    }
    if (waiter) {
        kthread_stop(waiter);
        put_task_struct(waiter);
    }
}

/*
 * rcu_stall_init - 模块加载入口（insmod）
 *
 * 只负责启动线程并返回，不在 init 路径里做阻塞等待，
 * 保证 insmod 命令本身不会被长时间挂住。
 */
static int __init rcu_stall_init(void)
{
    struct task_struct *task;
    int ret;

    /*
     * 参数范围校验：过小无法触发 stall 检测，过大则会让测试机长时间不可用。
     * 返回 -EINVAL 让 insmod 直接失败并提示参数错误。
     * 注意这里不要手写 "rcu_stall_mod: " 前缀，pr_fmt 已经加过了。
     */
    if (stall_duration_ms == 0 || stall_duration_ms > 300000) {
        pr_warn("invalid stall_duration_ms %u, expected 1..300000\n",
                stall_duration_ms);
        return -EINVAL;
    }

    /*
     * reinit_completion(): 把完成量重置为未完成状态。
     * 支持模块反复加载/卸载，避免上一次运行遗留的完成状态影响本次握手。
     */
    reinit_completion(&reader_entered);

    mutex_lock(&thread_mutex);
    if (reader_task || gp_waiter_task) {
        mutex_unlock(&thread_mutex);
        return -EBUSY;
    }

    /*
     * 启动读者线程。线程名前缀 rcu_ 会让它在 ps 中很容易被筛出来；
     * 名字会被截断到 15 字符，实际 COMMAND 为 "rcu_blocked_rea"。
     */
    task = rcu_stall_spawn(rcu_stall_thread, "rcu_blocked_reader");
    if (IS_ERR(task)) {
        ret = PTR_ERR(task);
        mutex_unlock(&thread_mutex);
        return ret;
    }
    /*
     * gp_waiter_task 的赋值同样在 thread_mutex 保护下完成，
     * 保持"仅在持锁时读写这两个指针"的约定。
     */
    reader_task = task;
    mutex_unlock(&thread_mutex);

    /*
     * 读者线程已启动后再创建等待者，且不在持有互斥锁时创建，
     * 避免等待者线程启动后与 init 路径争用同一把锁。
     */
    task = rcu_stall_spawn(rcu_gp_waiter_thread, "rcu_gp_waiter");
    if (IS_ERR(task)) {
        ret = PTR_ERR(task);
        /*
         * 回滚已创建的读者线程，避免留下孤儿线程持续占用 RCU 读锁。
         * rcu_stall_stop_threads() 内部会正确 put_task_struct()，
         * 不会因为线程已自行退出而访问已释放的 task_struct。
         */
        rcu_stall_stop_threads();
        return ret;
    }

    mutex_lock(&thread_mutex);
    gp_waiter_task = task;
    mutex_unlock(&thread_mutex);

    pr_info("RCU stall simulation started\n");
    return 0;
}

/*
 * rcu_stall_exit - 模块卸载入口（rmmod）
 *
 * 先释放读者的 RCU 读锁，使被挂住的 grace period 能推进，
 * 再回收等待者，最后模块才能安全卸载。
 */
static void __exit rcu_stall_exit(void)
{
    rcu_stall_stop_threads();
    pr_info("RCU stall simulation stopped\n");
}

/* 注册模块初始化和退出函数 */
module_init(rcu_stall_init);
module_exit(rcu_stall_exit);