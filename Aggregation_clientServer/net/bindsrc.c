// =============================================================================
// bindsrc.c ── 用 LD_PRELOAD 讓 client 的 outbound TCP 綁定指定的來源 IP
// =============================================================================
// 解決的問題：
//   三台 motor 跑在同一台機器上，來源 IP 全是 127.0.0.1，只有隨機 client port
//   不同。pcap 因此無法穩定分辨「這條連線是哪一台 motor」（port 每次重啟都變），
//   GNN 的三個 motor 節點會塌縮成無法對應的匿名節點。
//
// 為什麼用 LD_PRELOAD 而不是改程式：
//   本專案使用的 open62541 版本，其 POSIX TCP 連線管理器
//   (arch/posix/eventloop_posix_tcp.c) 的參數只有
//   address / port / listen / validate / reuse —— **沒有 source-address**。
//   client 端無法透過函式庫 API 指定本地位址，改 client 程式碼也做不到。
//   攔截 connect() 是不動函式庫、不動 C 程式邏輯的最小侵入解法。
//
// 為什麼不需要虛擬機：
//   Linux 預設整段 127.0.0.0/8（1600 萬個位址）都路由到 loopback，
//   bind 到 127.0.0.2 不需要 root、不需要 ip addr add、不需要任何系統設定。
//   實測 server 端看到的對端位址就是 127.0.0.2 —— 這正是 pcap 記錄的值。
//
// 用法：
//   BIND_SRC=127.0.0.2 LD_PRELOAD=./net/bindsrc.so ./motor_sub 1
//
// 編譯：
//   gcc -shared -fPIC -o net/bindsrc.so net/bindsrc.c -ldl
//
// 注意：
//   - 只影響 AF_INET（IPv4）的 connect，其餘一律原樣放行。
//   - bind 失敗時**不中斷連線**，退回預設行為（例如該位址不可用時仍能運作），
//     避免這個輔助工具反而讓採集整個失敗。
// =============================================================================
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

static int (*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;

int connect(int fd, const struct sockaddr *addr, socklen_t len) {
    if (!real_connect)
        real_connect = dlsym(RTLD_NEXT, "connect");

    const char *src = getenv("BIND_SRC");
    if (src && *src && addr && addr->sa_family == AF_INET) {
        struct in_addr ia;
        if (inet_pton(AF_INET, src, &ia) == 1) {
            struct sockaddr_in local;
            memset(&local, 0, sizeof(local));
            local.sin_family = AF_INET;
            local.sin_addr = ia;
            local.sin_port = 0;              // port 交給核心配
            // 刻意忽略回傳值：bind 不成功就照原本的預設來源連線。
            bind(fd, (struct sockaddr *)&local, sizeof(local));
        }
    }
    return real_connect(fd, addr, len);
}
