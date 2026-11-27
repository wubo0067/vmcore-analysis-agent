// SPDX-License-Identifier: GPL-2.0
/*
 * soft_lockup_module - 模拟 CPU lockup 现场，用于生成 vmcore 测试分析 agent
 *
 * 通过 mode 参数选择场景（详见同目录 Readme.md）：
 *
 *   busy     (默认) 禁抢占忙等，不关中断。目标 CPU 报 soft lockup。
 *   spinlock 持有者线程在 CPU A 上持有 sim_lock 不放，争抢者线程在 CPU B 上
 *            spin_lock() 同一把锁，卡在 native_queued_spin_lock_slowpath。
 *            A、B 都会报 soft lockup，可验证自旋锁争抢检测与 qspinlock 解码。
 *   softirq  在目标 CPU 的定时器软中断回调里忙等，栈中出现 __do_softirq /
 *            run_timer_softirq / call_timer_fn。
 *   irqoff   关中断忙等，由 NMI watchdog 报 hard lockup；还可能连累向该 CPU
 *            发 IPI 的其他 CPU（见 issue_1.txt）。危险，必须同时设置 allow_irqoff=1。
 *
 * soft lockup 检测原理（5.14）：hrtimer 回调 watchdog_timer_fn() 每
 * watchdog_thresh*2/5 秒采样一次，由 cpu stopper 执行 softlockup_fn() 更新
 * watchdog_touch_ts。CPU 不发生调度时时间戳不再更新，超过 2*watchdog_thresh
 * （默认 20s）即报 "BUG: soft lockup"，softlockup_panic=1 时 panic。
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cpumask.h>
#include <linux/irqflags.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/timer.h>

/* ------------------------------------------------------------------------ */
/* 模块参数                                                                  */
/* ------------------------------------------------------------------------ */

static char *sim_mode_str = "busy";
module_param_named(mode, sim_mode_str, charp, 0444);
MODULE_PARM_DESC(mode, "Scenario: busy (default), spinlock, softirq, irqoff");

static int cpu_number = -1;
module_param(cpu_number, int, 0444);
MODULE_PARM_DESC(cpu_number,
		 "Online CPU to lock up (-1: busy=any CPU, other modes=last online CPU)");

static int contender_cpu = -1;
module_param(contender_cpu, int, 0444);
MODULE_PARM_DESC(contender_cpu,
		 "spinlock mode: CPU for the contending thread (-1: any other online CPU)");

static bool enable_soft_lockup;
module_param(enable_soft_lockup, bool, 0644);
MODULE_PARM_DESC(enable_soft_lockup,
		 "Start the lockup; switchable at runtime via sysfs (default 0)");

static bool allow_irqoff;
module_param(allow_irqoff, bool, 0444);
MODULE_PARM_DESC(allow_irqoff,
		 "Required for mode=irqoff, which may hang the whole system (default 0)");

/* ------------------------------------------------------------------------ */
/* 场景与现场记录                                                            */
/* ------------------------------------------------------------------------ */

enum sim_mode {
	SIM_MODE_BUSY,
	SIM_MODE_SPINLOCK,
	SIM_MODE_SOFTIRQ,
	SIM_MODE_IRQOFF,
};

static const char * const sim_mode_names[] = {
	[SIM_MODE_BUSY]     = "busy",
	[SIM_MODE_SPINLOCK] = "spinlock",
	[SIM_MODE_SOFTIRQ]  = "softirq",
	[SIM_MODE_IRQOFF]   = "irqoff",
};

/* 小端序下内存中的字节为 "SOFTLKP"，crash 里可用 search -k 定位 sim_ctx */
#define SOFTLOCKUP_SIM_MAGIC 0x504b4c54464f53UL

/*
 * 供 vmcore 分析使用的现场记录：
 *   crash> mod -s soft_lockup_module <path>/soft_lockup_module.ko
 *   crash> p sim_ctx
 *
 * cpu            正在执行卡住代码的 CPU（busy / spinlock 持有者 / softirq / irqoff）
 * contender_cpu  spinlock 模式下争抢者所在 CPU
 * start_jiffies  进入卡住代码时的 jiffies，与 dmesg "stuck for Ns" 互相核对
 * iterations     持续增长，说明 CPU 在空转而不是被彻底卡住
 * lock           spinlock 模式下被长期持有的锁，可 "struct qspinlock <addr>" 解码
 */
struct softlockup_sim_ctx {
	unsigned long magic;
	const char *mode_name;
	int cpu;
	int contender_cpu;
	unsigned long start_jiffies;
	unsigned long iterations;
	spinlock_t *lock;
	int lock_held;
	int contender_waiting;
	unsigned long contender_acquired;
	int in_softirq;
};

static DEFINE_SPINLOCK(sim_lock);

static struct softlockup_sim_ctx sim_ctx = {
	.magic = SOFTLOCKUP_SIM_MAGIC,
	.cpu = -1,
	.contender_cpu = -1,
	.lock = &sim_lock,
};

static enum sim_mode sim_mode;
static bool sim_stopping;
static struct task_struct *sim_task;
static struct task_struct *sim_contender;
static struct timer_list sim_timer;

/* 只在卡住代码所在 CPU 上写，WRITE_ONCE 即可，无需原子操作 */
static inline void sim_mark_start(void)
{
	WRITE_ONCE(sim_ctx.cpu, smp_processor_id());
	WRITE_ONCE(sim_ctx.start_jiffies, jiffies);
}

static inline bool sim_keep_spinning(void)
{
	return READ_ONCE(enable_soft_lockup) && !READ_ONCE(sim_stopping);
}

static inline void sim_spin_once(void)
{
	WRITE_ONCE(sim_ctx.iterations, sim_ctx.iterations + 1);
	cpu_relax();	/* x86: pause + 编译器屏障 */
}

/* ------------------------------------------------------------------------ */
/* 各场景的卡住函数：均为 noinline，使 bt / dis -rl 中有语义明确的栈帧          */
/* ------------------------------------------------------------------------ */

/* busy：禁抢占忙等，不关中断 */
static noinline void softlockup_sim_spin(void)
{
	preempt_disable();
	sim_mark_start();
	pr_info("[busy] spinning with preemption disabled on CPU %d\n", sim_ctx.cpu);

	while (sim_keep_spinning() && !kthread_should_stop())
		sim_spin_once();

	preempt_enable();
	pr_info("[busy] stopped on CPU %d\n", sim_ctx.cpu);
}

/* spinlock 持有者：spin_lock() 本身会禁抢占，持锁忙等不释放 */
static noinline void softlockup_sim_hold_lock(void)
{
	spin_lock(&sim_lock);
	sim_mark_start();
	WRITE_ONCE(sim_ctx.lock_held, 1);
	pr_info("[spinlock] holder on CPU %d holds sim_lock at %px\n",
		sim_ctx.cpu, &sim_lock);

	while (sim_keep_spinning() && !kthread_should_stop())
		sim_spin_once();

	WRITE_ONCE(sim_ctx.lock_held, 0);
	spin_unlock(&sim_lock);
	pr_info("[spinlock] holder on CPU %d released sim_lock\n", sim_ctx.cpu);
}

/* spinlock 争抢者：在 native_queued_spin_lock_slowpath 中自旋，直到持有者释放 */
static noinline void softlockup_sim_contend(void)
{
	WRITE_ONCE(sim_ctx.contender_waiting, 1);
	spin_lock(&sim_lock);
	WRITE_ONCE(sim_ctx.contender_waiting, 0);
	WRITE_ONCE(sim_ctx.contender_acquired, sim_ctx.contender_acquired + 1);
	spin_unlock(&sim_lock);
}

/* irqoff：关中断忙等，hrtimer / IPI 都无法在此 CPU 上处理 */
static noinline void softlockup_sim_irqoff_spin(void)
{
	unsigned long flags;

	pr_info("[irqoff] spinning with interrupts disabled on CPU %d\n",
		raw_smp_processor_id());
	local_irq_save(flags);
	sim_mark_start();

	while (sim_keep_spinning() && !kthread_should_stop())
		sim_spin_once();

	local_irq_restore(flags);
	pr_info("[irqoff] stopped on CPU %d\n", sim_ctx.cpu);
}

/* softirq：在定时器软中断回调中忙等（softirq 上下文本身不可抢占） */
static void softlockup_sim_timer_fn(struct timer_list *t)
{
	WRITE_ONCE(sim_ctx.in_softirq, 1);
	sim_mark_start();

	while (sim_keep_spinning())
		sim_spin_once();

	WRITE_ONCE(sim_ctx.in_softirq, 0);
}

/*
 * 只有主线程会 add_timer_on()，因此"未 pending 才添加"不会与其他添加者竞争，
 * 不会触发 add_timer_on() 中的 BUG_ON(timer_pending(timer))。
 */
static void softlockup_sim_arm_timer(void)
{
	if (READ_ONCE(sim_ctx.in_softirq) || timer_pending(&sim_timer))
		return;

	sim_timer.expires = jiffies + 1;
	add_timer_on(&sim_timer, cpu_number);
	pr_info("[softirq] timer armed on CPU %d\n", cpu_number);
}

/* ------------------------------------------------------------------------ */
/* 线程                                                                      */
/* ------------------------------------------------------------------------ */

/*
 * 主线程：开关关闭时真正睡眠（每 100ms 检查一次，kthread_stop() 可立即唤醒）；
 * 打开时按 mode 进入对应的卡住函数。只在 kthread_should_stop() 后返回，
 * 保证 exit 中 kthread_stop() 访问的 task_struct 始终有效。
 */
static int softlockup_sim_thread(void *data)
{
	while (!kthread_should_stop()) {
		if (!READ_ONCE(enable_soft_lockup)) {
			schedule_timeout_interruptible(HZ / 10);
			continue;
		}

		/*
		 * 四种模式的共同点：让某颗 CPU 长时间"不发生任务切换"。
		 * soft lockup 检测器依赖 cpu stopper 线程定期运行来"喂狗"，
		 * 只要这颗 CPU 一直不调度，喂狗就停了，超过 20s（默认）即报警。
		 * 四种模式的区别在于"用什么方式让 CPU 不调度"，对应不同的真实故障。
		 *
		 * busy / spinlock / irqoff 三种模式的卡住函数会一直阻塞在这里，
		 * 直到 enable_soft_lockup 被写 0 或模块卸载才返回；
		 * softirq 模式的卡住发生在定时器回调里，主线程本身不会卡住。
		 */
		switch (sim_mode) {
		case SIM_MODE_BUSY:
			/*
			 * 忙等模式（默认）：
			 * 本线程 preempt_disable() 关闭抢占后原地空转。
			 * - 关闭抢占 = 调度器不能把本线程从 CPU 上换下来，
			 *   cpu stopper 也就跑不上来，喂狗停止。
			 * - 中断仍然开着，本 CPU 的 hrtimer 照常触发，
			 *   所以由本 CPU 自己报出 soft lockup。
			 * 对应真实故障：内核代码在禁抢占区（或持有自旋锁时）
			 * 执行超长循环，且没有调用 cond_resched()。
			 */
			softlockup_sim_spin();
			break;
		case SIM_MODE_SPINLOCK:
			/*
			 * 自旋锁争抢模式（需要两颗 CPU）：
			 * - 本线程（持有者，CPU = cpu_number）spin_lock(&sim_lock) 后
			 *   一直不释放。spin_lock() 会自动关闭抢占，效果同 busy 模式。
			 * - 另一个线程 softlockup_ctd（争抢者，CPU = contender_cpu）
			 *   spin_lock() 同一把锁。自旋锁拿不到时不会睡眠，而是在
			 *   native_queued_spin_lock_slowpath 里原地转圈等待，
			 *   同样不发生调度。
			 * 结果：两颗 CPU 都报 soft lockup。持有者是"肇事者"，
			 * 争抢者是"受害者"，分析时要从争抢者顺藤摸瓜找到持有者。
			 * 对应真实故障：某段代码持锁时间过长或忘记解锁，
			 * 导致其他等锁的 CPU 全部卡住。
			 */
			softlockup_sim_hold_lock();
			break;
		case SIM_MODE_IRQOFF:
			/*
			 * 关中断模式（危险，需 allow_irqoff=1）：
			 * 本线程 local_irq_save() 关闭本 CPU 的中断后原地空转。
			 * - 中断都关了，本 CPU 的 hrtimer 也不会触发，
			 *   soft lockup 检测器在本 CPU 上完全失效，不会报 soft lockup。
			 * - 改由 NMI watchdog 发现：NMI（不可屏蔽中断）不受关中断影响，
			 *   它检查本 CPU 的时钟中断计数是否还在增长，
			 *   不增长就报 hard lockup（默认约 10s）。
			 * - 副作用：其他 CPU 发给本 CPU 的 IPI（如 TLB 刷新请求）得不到响应，
			 *   发送方会一直等，可能在"别的 CPU"上报 soft lockup（见 issue_1.txt）。
			 * 对应真实故障：spin_lock_irqsave() 等关中断区域执行时间过长。
			 */
			softlockup_sim_irqoff_spin();
			break;
		case SIM_MODE_SOFTIRQ:
			/*
			 * 软中断模式：
			 * 软中断是硬件中断处理完之后"延后执行"的工作（网络收包、
			 * 定时器回调等），它运行时同样不能被普通任务抢占。
			 * - 主线程本身不卡住，只负责在目标 CPU 上布置一个定时器
			 *   （已布置或回调正在运行时会跳过，不会重复布置）。
			 * - 定时器到期后，目标 CPU 在软中断上下文中执行
			 *   softlockup_sim_timer_fn()，在里面原地空转，
			 *   该 CPU 因此无法调度，报 soft lockup，
			 *   栈里能看到 __do_softirq → call_timer_fn。
			 * - 之后主线程睡 100ms 再回到循环顶部，检查开关和停止请求。
			 *   主线程不绑核，所以目标 CPU 被卡住时它仍能在其他 CPU 上运行。
			 * 对应真实故障：网络软中断负载过高、定时器回调执行过慢。
			 */
			softlockup_sim_arm_timer();
			schedule_timeout_interruptible(HZ / 10);
			break;
		}
	}
	return 0;
}

/* spinlock 争抢者线程：等持有者真正拿到锁后才去争抢，避免抢在持有者前面 */
static int softlockup_sim_contender_thread(void *data)
{
	while (!kthread_should_stop()) {
		if (!READ_ONCE(enable_soft_lockup) || !READ_ONCE(sim_ctx.lock_held)) {
			schedule_timeout_interruptible(HZ / 20);
			continue;
		}
		softlockup_sim_contend();
	}
	return 0;
}

/* ------------------------------------------------------------------------ */
/* 初始化与退出                                                              */
/* ------------------------------------------------------------------------ */

static bool sim_cpu_valid(int cpu)
{
	return cpu >= 0 && cpu < nr_cpu_ids && cpu_online(cpu);
}

static int sim_parse_mode(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(sim_mode_names); i++) {
		if (sysfs_streq(sim_mode_str, sim_mode_names[i])) {
			sim_mode = i;
			sim_ctx.mode_name = sim_mode_names[i];
			return 0;
		}
	}
	pr_err("unknown mode '%s' (expected busy, spinlock, softirq or irqoff)\n",
	       sim_mode_str);
	return -EINVAL;
}

/*
 * 校验并确定 CPU。num_online_cpus() 是在线 CPU 个数而非最大编号，编号可能
 * 不连续，必须用 cpu_online() 校验；无效时拒绝加载，避免静默跑到其他 CPU。
 * 测试模块不处理"校验后 CPU 被下线"的竞态。
 */
static int sim_setup_cpus(void)
{
	if (cpu_number >= 0 && !sim_cpu_valid(cpu_number)) {
		pr_err("cpu_number=%d is not an online CPU\n", cpu_number);
		return -EINVAL;
	}

	/* 除 busy 外的模式都必须落在确定的 CPU 上 */
	if (cpu_number < 0 && sim_mode != SIM_MODE_BUSY) {
		cpu_number = cpumask_last(cpu_online_mask);
		pr_info("cpu_number not set, using CPU %d\n", cpu_number);
	}

	if (sim_mode != SIM_MODE_SPINLOCK)
		return 0;

	if (contender_cpu < 0) {
		contender_cpu = cpumask_any_but(cpu_online_mask, cpu_number);
		if (contender_cpu >= nr_cpu_ids) {
			pr_err("spinlock mode needs at least 2 online CPUs\n");
			return -EINVAL;
		}
	} else if (!sim_cpu_valid(contender_cpu) || contender_cpu == cpu_number) {
		pr_err("contender_cpu=%d must be an online CPU other than %d\n",
		       contender_cpu, cpu_number);
		return -EINVAL;
	}
	sim_ctx.contender_cpu = contender_cpu;
	return 0;
}

static int __init softlockup_sim_init(void)
{
	int ret;

	ret = sim_parse_mode();
	if (ret)
		return ret;

	if (sim_mode == SIM_MODE_IRQOFF && !allow_irqoff) {
		pr_err("mode=irqoff can hang the whole system; set allow_irqoff=1 to confirm\n");
		return -EPERM;
	}

	ret = sim_setup_cpus();
	if (ret)
		return ret;

	timer_setup(&sim_timer, softlockup_sim_timer_fn, 0);

	/*
	 * kthread_create + kthread_bind + wake_up_process：线程首次运行即在目标 CPU 上。
	 * softirq 模式下忙等发生在定时器回调里，主线程只负责布置定时器，不绑核，
	 * 以免被锁死的 CPU 拖住而无法响应开关和 kthread_stop()。
	 */
	sim_task = kthread_create(softlockup_sim_thread, NULL, "softlockup_sim");
	if (IS_ERR(sim_task)) {
		pr_err("failed to create kthread: %ld\n", PTR_ERR(sim_task));
		return PTR_ERR(sim_task);
	}
	if (cpu_number >= 0 && sim_mode != SIM_MODE_SOFTIRQ)
		kthread_bind(sim_task, cpu_number);

	if (sim_mode == SIM_MODE_SPINLOCK) {
		sim_contender = kthread_create(softlockup_sim_contender_thread, NULL,
					       "softlockup_ctd");
		if (IS_ERR(sim_contender)) {
			ret = PTR_ERR(sim_contender);
			pr_err("failed to create contender kthread: %d\n", ret);
			sim_contender = NULL;
			kthread_stop(sim_task);	/* 尚未唤醒的线程可直接 stop */
			return ret;
		}
		kthread_bind(sim_contender, contender_cpu);
		wake_up_process(sim_contender);
	}
	wake_up_process(sim_task);

	pr_info("loaded (mode=%s, cpu_number=%d, contender_cpu=%d, enable_soft_lockup=%d)\n",
		sim_ctx.mode_name, cpu_number, sim_ctx.contender_cpu, enable_soft_lockup);
	if (!enable_soft_lockup)
		pr_info("idle; echo 1 > /sys/module/%s/parameters/enable_soft_lockup to trigger\n",
			KBUILD_MODNAME);
	return 0;
}

/*
 * 退出顺序：先置停止标志让所有忙等循环退出（持有者因此释放锁，争抢者随之拿到锁），
 * 再停争抢者和主线程，最后等待可能仍在运行的定时器回调结束。
 */
static void __exit softlockup_sim_exit(void)
{
	WRITE_ONCE(sim_stopping, true);
	WRITE_ONCE(enable_soft_lockup, false);

	if (sim_contender)
		kthread_stop(sim_contender);
	kthread_stop(sim_task);
	del_timer_sync(&sim_timer);

	pr_info("unloaded (iterations=%lu, contender_acquired=%lu)\n",
		sim_ctx.iterations, sim_ctx.contender_acquired);
}

module_init(softlockup_sim_init);
module_exit(softlockup_sim_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Calm.Wu");
MODULE_DESCRIPTION("Simulate soft/hard lockup scenarios for vmcore analysis");
MODULE_VERSION("1.2");
