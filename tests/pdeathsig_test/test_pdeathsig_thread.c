
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>

static atomic_int stop_thread_b = 0;
static pid_t child_pid = -1;

static volatile sig_atomic_t child_received_signal = 0;

/* Child: SIGTERM handler */
static void sigterm_handler(int sig)
{
    (void)sig;

    child_received_signal = 1;

    const char msg[] =
        "\n[CHILD] Received SIGTERM!\n"
        "[CHILD] PDEATHSIG triggered by parent thread exit!\n";

    write(STDOUT_FILENO, msg, sizeof(msg) - 1);
}

/*
 * Thread A:
 * 1. fork() creates child process
 * 2. Wait until child configures PDEATHSIG
 * 3. Exit this thread using pthread_exit()
 */
static void *thread_a(void *arg)
{
    (void)arg;

    printf("[THREAD A] PID=%d TID=%ld\n",
           getpid(), syscall(186));
    fflush(stdout);

    int pipefd[2];

    if (pipe(pipefd) == -1)
    {
        perror("pipe");
        return NULL;
    }
    // 创建子进程
    pid_t pid = fork();

    if (pid < 0)
    {
        // Error handling for fork failure
        perror("fork");
        return NULL;
    }

    /* ================= CHILD PROCESS ================= */
    if (pid == 0)
    {
        close(pipefd[0]);

        /* 先注册 SIGTERM 处理函数，再设置 PDEATHSIG：
         * 保证父线程退出触发信号时，子进程已有处理函数，
         * 不会被默认行为（直接终止）杀掉，从而能验证信号确实到达。 */
        struct sigaction sa;

        /* 清零结构体，避免未初始化字段（如 sa_flags）带来随机行为 */
        memset(&sa, 0, sizeof(sa));

        /* 指定信号处理函数 */
        sa.sa_handler = sigterm_handler;

        /* 处理函数执行期间不额外屏蔽其他信号 */
        sigemptyset(&sa.sa_mask);

        /* 注册 SIGTERM 的处理动作；失败则以退出码 1 终止子进程 */
        if (sigaction(SIGTERM, &sa, NULL) == -1)
            _exit(1);

        /* Configure parent death signal */
        if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1)
            _exit(2);

        /*
         * Notify Thread A:
         * PDEATHSIG has been configured.
         */
        char ready = 'R';
        // 给父线程发送一个字节，表示子进程已经配置好了 PDEATHSIG
        if (write(pipefd[1], &ready, 1) != 1)
            _exit(3);

        close(pipefd[1]);

        printf("[CHILD] PID=%d PPID=%d\n",
               getpid(), getppid());
        printf("[CHILD] PR_SET_PDEATHSIG = SIGTERM\n");
        printf("[CHILD] Waiting for parent thread exit...\n");
        fflush(stdout);

        /* Wait for SIGTERM */
        while (!child_received_signal)
            sleep(1);

        printf("[CHILD] Current PPID=%d\n", getppid());
        printf("[CHILD] Exiting now.\n");
        fflush(stdout);

        _exit(0);
    }

    /* ================= PARENT THREAD A ================= */

    close(pipefd[1]);

    child_pid = pid;

    printf("[THREAD A] Created child PID=%d\n", pid);
    printf("[THREAD A] Waiting for child configuration...\n");
    fflush(stdout);

    char ready;

    ssize_t n;

    do
    {
        n = read(pipefd[0], &ready, 1);
    } while (n == -1 && errno == EINTR);

    close(pipefd[0]);

    if (n != 1 || ready != 'R')
    {
        fprintf(stderr, "[THREAD A] Child configuration failed\n");
        pthread_exit(NULL);
    }

    printf("[THREAD A] Child PDEATHSIG configured successfully.\n");
    printf("[THREAD A] Exiting Thread A now!\n");
    fflush(stdout);

    /* Important: exit this thread, NOT the process */
    pthread_exit(NULL);

    return NULL;
}

/*
 * Thread B:
 * Remains alive after Thread A exits.
 */
static void *thread_b(void *arg)
{
    (void)arg;

    printf("[THREAD B] PID=%d TID=%ld\n",
           getpid(), syscall(186));
    fflush(stdout);

    int count = 0;

    while (!atomic_load(&stop_thread_b))
    {
        printf("[THREAD B] Still alive... heartbeat=%d\n",
               ++count);

        fflush(stdout);
        sleep(1);
    }

    printf("[THREAD B] Exiting.\n");
    return NULL;
}

int main(void)
{
    pthread_t tid_a;
    pthread_t tid_b;

    printf("[MAIN] Parent process PID=%d\n", getpid());
    printf("[MAIN] Creating Thread A and Thread B...\n");
    fflush(stdout);

    if (pthread_create(&tid_b, NULL, thread_b, NULL) != 0)
    {
        perror("pthread_create B");
        return 1;
    }

    if (pthread_create(&tid_a, NULL, thread_a, NULL) != 0)
    {
        perror("pthread_create A");
        atomic_store(&stop_thread_b, 1);
        pthread_join(tid_b, NULL);
        return 1;
    }

    /* Wait for Thread A to exit */
    pthread_join(tid_a, NULL);

    printf("\n[MAIN] Thread A has exited.\n");
    printf("[MAIN] Parent process PID=%d is STILL ALIVE!\n",
           getpid());
    printf("[MAIN] Thread B should still be running.\n\n");
    fflush(stdout);

    /* Wait for child process to exit */
    int status;

    if (waitpid(child_pid, &status, 0) == -1)
    {
        perror("waitpid");
    }
    else
    {
        printf("\n[MAIN] Child process exited.\n");

        if (WIFEXITED(status))
            printf("[MAIN] Child exit code=%d\n",
                   WEXITSTATUS(status));
        else if (WIFSIGNALED(status))
            printf("[MAIN] Child killed by signal=%d\n",
                   WTERMSIG(status));
    }

    /* Stop Thread B only after child has exited */
    atomic_store(&stop_thread_b, 1);

    pthread_join(tid_b, NULL);

    printf("[MAIN] All threads finished. Parent exiting.\n");

    return 0;
}
