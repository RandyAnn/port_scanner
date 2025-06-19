#define _WIN32_WINNT 0x0600
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "port_analyzer.h"

#define BUFFER_SIZE 1024

// 安全字符串处理函数
int safe_strncpy(char* dest, const char* src, size_t dest_size) {
    if (!dest || !src || dest_size == 0) {
        return -1;
    }

    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
    return 0;
}

int safe_snprintf(char* buffer, size_t size, const char* format, ...) {
    if (!buffer || !format || size == 0) {
        return -1;
    }

    va_list args;
    va_start(args, format);
    int result = vsnprintf(buffer, size, format, args);
    va_end(args);

    // 确保字符串以null结尾
    buffer[size - 1] = '\0';
    return result;
}

// 错误日志记录函数
void logAnalyzerError(AnalyzerResult error, const char* function, const char* details) {
    const char* error_messages[] = {
        "成功",
        "网络错误",
        "超时错误",
        "内存错误",
        "无效参数",
        "Socket创建失败",
        "Socket配置失败",
        "连接失败",
        "发送失败",
        "接收失败"
    };

    if (error >= 0 && error < sizeof(error_messages)/sizeof(error_messages[0])) {
        printf("错误 [%s]: %s", function ? function : "未知函数", error_messages[error]);
        if (details) {
            printf(" - %s", details);
        }
        printf("\n");
    }
}

// 探测策略结构体已在头文件中定义

// 重试配置结构体已在头文件中定义

// 网络状况评估结构体
typedef struct {
    int successful_connections; // 成功连接数
    int failed_connections;     // 失败连接数
    int average_response_time;  // 平均响应时间(毫秒)
    float packet_loss_rate;     // 丢包率
} NetworkCondition;

// 全局网络状况
static NetworkCondition g_network_condition = {0, 0, 1000, 0.0f};

// 连接池配置
#define MAX_CONNECTIONS 50
#define CONNECTION_TIMEOUT_MS 30000  // 30秒连接超时

// 缓冲区池配置
#define MAX_BUFFERS 100
#define BUFFER_POOL_SIZE 1024

// 缓存配置
#define MAX_CACHE_ENTRIES 1000
#define CACHE_TIMEOUT_MS 300000  // 5分钟缓存超时

// 连接池条目
typedef struct {
    SOCKET socket;
    char target_ip[16];
    int port;
    DWORD last_used;
    BOOL in_use;
    BOOL is_valid;
} ConnectionPoolEntry;

// 缓冲区池条目
typedef struct {
    char* buffer;
    size_t size;
    BOOL in_use;
} BufferPoolEntry;

// 探测结果缓存条目
typedef struct {
    char ip[16];
    int port;
    char service[32];
    char version[64];
    DWORD timestamp;
    BOOL is_valid;
} CacheEntry;

// 资源池结构体
typedef struct {
    ConnectionPoolEntry connections[MAX_CONNECTIONS];
    BufferPoolEntry buffers[MAX_BUFFERS];
    CacheEntry cache[MAX_CACHE_ENTRIES];
    HANDLE connection_mutex;
    HANDLE buffer_mutex;
    HANDLE cache_mutex;
    BOOL initialized;
} ResourcePool;

// 全局资源池
static ResourcePool g_resource_pool = {0};

// 性能统计结构体已在头文件中定义

static PerformanceStats g_perf_stats = {0};

// 默认重试配置
static const RetryConfig default_retry_config = {
    .max_retries = 2,
    .base_timeout_ms = 1000,
    .timeout_multiplier = 2.0f,
    .max_timeout_ms = 8000,
    .retry_delay_ms = 100
};

// 不同服务类型的重试配置
static const RetryConfig service_retry_configs[] = {
    // HTTP服务 - 通常响应较快
    {2, 1500, 1.5f, 6000, 100},
    // SSH服务 - 需要较长时间建立连接
    {1, 2000, 2.0f, 4000, 200},
    // FTP服务 - 中等响应时间
    {2, 1000, 2.0f, 4000, 150},
    // SMTP服务 - 通常响应较快
    {2, 1500, 1.5f, 5000, 100},
    // 数据库服务 - 可能需要较长时间
    {1, 2000, 1.5f, 6000, 200},
    // DNS服务 - 快速响应
    {3, 500, 2.0f, 2000, 50},
    // 其他服务 - 使用默认配置
    {2, 1000, 2.0f, 8000, 100}
};

// 增强的服务指纹数据库
typedef struct {
    const char *pattern;        // 匹配模式
    const char *service;        // 服务名称
    const char *version_pattern; // 版本提取模式
    int confidence;             // 置信度 (1-100)
    int port_hint;              // 端口提示 (0表示任意端口)
} ServicePattern;

// 各种协议的探测包定义
static const char *http_probes[] = {
    "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: PortScanner/1.0\r\nConnection: close\r\n\r\n",
    "HEAD / HTTP/1.0\r\n\r\n",
    "OPTIONS / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    NULL
};

static const char *https_probes[] = {
    // SSL/TLS 握手包 (简化版)
    "\x16\x03\x01\x00\x2f\x01\x00\x00\x2b\x03\x03",  // TLS ClientHello
    NULL
};

static const char *ftp_probes[] = {
    "USER anonymous\r\n",
    "HELP\r\n",
    "QUIT\r\n",
    NULL
};

static const char *ssh_probes[] = {
    "SSH-2.0-Scanner\r\n",
    "\r\n",
    NULL
};

static const char *smtp_probes[] = {
    "HELO localhost\r\n",
    "EHLO localhost\r\n",
    "\r\n",
    NULL
};

static const char *pop3_probes[] = {
    "USER test\r\n",
    "QUIT\r\n",
    NULL
};

static const char *imap_probes[] = {
    "A001 CAPABILITY\r\n",
    "A002 LOGOUT\r\n",
    NULL
};

static const char *telnet_probes[] = {
    "\xff\xfb\x01\xff\xfb\x03\xff\xfc\x27",  // Telnet negotiation
    "\r\n",
    NULL
};

static const char *mysql_probes[] = {
    "\x00\x00\x00\x01",  // MySQL connection packet
    NULL
};

static const char *dns_udp_probes[] = {
    "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",  // DNS query
    NULL
};

static const char *snmp_udp_probes[] = {
    "\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",  // SNMP GetRequest
    NULL
};

static const char *ntp_udp_probes[] = {
    "\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",  // NTP request
    NULL
};

static const char *generic_probes[] = {
    "\r\n",
    "\n",
    "GET / HTTP/1.0\r\n\r\n",
    NULL
};

// 端口特定的探测策略
static const ProbeStrategy portStrategies[] = {
    // Web服务
    {80, http_probes, 3000, 2, "HTTP Web Server"},
    {8080, http_probes, 3000, 2, "HTTP Alternate"},
    {8000, http_probes, 3000, 2, "HTTP Development"},
    {443, https_probes, 5000, 2, "HTTPS Secure Web"},
    {8443, https_probes, 5000, 2, "HTTPS Alternate"},

    // 文件传输
    {21, ftp_probes, 3000, 1, "FTP File Transfer"},
    {990, ftp_probes, 3000, 1, "FTPS Secure FTP"},

    // 远程访问
    {22, ssh_probes, 2000, 1, "SSH Secure Shell"},
    {23, telnet_probes, 2000, 1, "Telnet Remote Access"},

    // 邮件服务
    {25, smtp_probes, 3000, 1, "SMTP Mail Transfer"},
    {465, smtp_probes, 3000, 1, "SMTPS Secure SMTP"},
    {587, smtp_probes, 3000, 1, "SMTP Submission"},
    {110, pop3_probes, 2000, 1, "POP3 Mail Retrieval"},
    {995, pop3_probes, 2000, 1, "POP3S Secure POP3"},
    {143, imap_probes, 2000, 1, "IMAP Mail Access"},
    {993, imap_probes, 2000, 1, "IMAPS Secure IMAP"},

    // 数据库
    {3306, mysql_probes, 2000, 1, "MySQL Database"},
    {5432, generic_probes, 2000, 1, "PostgreSQL Database"},
    {1433, generic_probes, 2000, 1, "MSSQL Database"},
    {1521, generic_probes, 2000, 1, "Oracle Database"},
    {27017, generic_probes, 2000, 1, "MongoDB Database"},
    {6379, generic_probes, 1000, 1, "Redis Database"},

    // 其他服务
    {53, generic_probes, 1000, 1, "DNS Domain Name Service"},
    {3389, generic_probes, 3000, 1, "RDP Remote Desktop"},
    {5900, generic_probes, 2000, 1, "VNC Remote Desktop"},
    {161, generic_probes, 1000, 1, "SNMP Network Management"},
    {123, generic_probes, 1000, 1, "NTP Network Time"},

    // 结束标记
    {0, NULL, 0, 0, NULL}
};

static const ServicePattern servicePatterns[] = {
    // Web服务器
    {"Apache/", "HTTP", "Apache/([0-9.]+)", 95, 80},
    {"nginx/", "HTTP", "nginx/([0-9.]+)", 95, 80},
    {"Microsoft-IIS/", "HTTP", "Microsoft-IIS/([0-9.]+)", 95, 80},
    {"lighttpd/", "HTTP", "lighttpd/([0-9.]+)", 90, 80},
    {"Cherokee/", "HTTP", "Cherokee/([0-9.]+)", 85, 80},
    {"HTTP/1.", "HTTP", NULL, 70, 80},
    {"Server: ", "HTTP", "Server: ([^\r\n]+)", 60, 80},

    // SSH服务
    {"SSH-2.0-OpenSSH_", "SSH", "SSH-2.0-OpenSSH_([0-9.]+)", 95, 22},
    {"SSH-2.0", "SSH", "SSH-2.0-([^\r\n]+)", 90, 22},
    {"SSH-1.", "SSH", "SSH-1.([0-9]+)", 85, 22},

    // FTP服务
    {"220 (vsFTPd", "FTP", "220 \\(vsFTPd ([0-9.]+)\\)", 95, 21},
    {"220 ProFTPD", "FTP", "220 ProFTPD ([0-9.]+)", 95, 21},
    {"220 FileZilla Server", "FTP", "220-FileZilla Server ([0-9.]+)", 90, 21},
    {"220 Microsoft FTP Service", "FTP", "220 Microsoft FTP Service", 85, 21},
    {"220 ", "FTP", "220 ([^\r\n]+)", 70, 21},

    // SMTP服务
    {"220 ", "SMTP", "220 ([^\r\n]+)", 80, 25},
    {"ESMTP", "SMTP", "ESMTP ([^\r\n]+)", 85, 25},
    {"Postfix", "SMTP", "Postfix", 90, 25},
    {"Sendmail", "SMTP", "Sendmail ([0-9.]+)", 90, 25},
    {"Microsoft ESMTP MAIL Service", "SMTP", "Microsoft ESMTP MAIL Service", 85, 25},

    // 数据库服务
    {"MySQL", "MySQL", "([0-9.]+)-", 90, 3306},
    {"PostgreSQL", "PostgreSQL", "PostgreSQL ([0-9.]+)", 90, 5432},
    {"Microsoft SQL Server", "MSSQL", "Microsoft SQL Server ([0-9]+)", 90, 1433},
    {"Oracle", "Oracle", "Oracle Database ([0-9.]+)", 85, 1521},
    {"MongoDB", "MongoDB", "MongoDB ([0-9.]+)", 85, 27017},
    {"Redis", "Redis", "Redis server v=([0-9.]+)", 85, 6379},

    // 邮件服务
    {"POP3", "POP3", "POP3 ([^\r\n]+)", 85, 110},
    {"IMAP", "IMAP", "IMAP4rev1 ([^\r\n]+)", 85, 143},
    {"Dovecot", "IMAP", "Dovecot ([0-9.]+)", 90, 143},

    // DNS服务
    {"BIND", "DNS", "BIND ([0-9.]+)", 90, 53},
    {"dnsmasq", "DNS", "dnsmasq-([0-9.]+)", 85, 53},

    // 其他常见服务
    {"Telnet", "Telnet", NULL, 80, 23},
    {"SNMP", "SNMP", NULL, 80, 161},
    {"NTP", "NTP", NULL, 75, 123},
    {"LDAP", "LDAP", NULL, 80, 389},
    {"HTTPS", "HTTPS", NULL, 85, 443},
    {"FTPS", "FTPS", NULL, 80, 990},
    {"SMTPS", "SMTPS", NULL, 80, 465},
    {"POP3S", "POP3S", NULL, 80, 995},
    {"IMAPS", "IMAPS", NULL, 80, 993},

    // 远程访问服务
    {"RDP", "RDP", NULL, 80, 3389},
    {"VNC", "VNC", "RFB ([0-9.]+)", 85, 5900},
    {"TeamViewer", "TeamViewer", NULL, 75, 5938},

    // 文件共享服务
    {"SMB", "SMB", NULL, 80, 445},
    {"NetBIOS", "NetBIOS", NULL, 75, 139},
    {"NFS", "NFS", NULL, 75, 2049},

    // 代理服务
    {"Squid", "Proxy", "squid/([0-9.]+)", 85, 3128},
    {"SOCKS", "SOCKS", NULL, 75, 1080},

    // 游戏服务
    {"Minecraft", "Minecraft", "([0-9.]+)", 80, 25565},
    {"Steam", "Steam", NULL, 75, 27015},

    // 监控和管理
    {"SNMP", "SNMP", NULL, 80, 161},
    {"Zabbix", "Zabbix", NULL, 75, 10050},
    {"Nagios", "Nagios", NULL, 75, 5666},

    // 结束标记
    {NULL, NULL, NULL, 0, 0}
};

// 初始化资源池
BOOL initializeResourcePool() {
    if (g_resource_pool.initialized) {
        return TRUE;
    }

    // 创建互斥锁
    g_resource_pool.connection_mutex = CreateMutex(NULL, FALSE, NULL);
    g_resource_pool.buffer_mutex = CreateMutex(NULL, FALSE, NULL);
    g_resource_pool.cache_mutex = CreateMutex(NULL, FALSE, NULL);

    if (!g_resource_pool.connection_mutex || !g_resource_pool.buffer_mutex || !g_resource_pool.cache_mutex) {
        logAnalyzerError(ANALYZER_ERROR_MEMORY, "initializeResourcePool", "创建互斥锁失败");
        return FALSE;
    }

    // 初始化连接池
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        g_resource_pool.connections[i].socket = INVALID_SOCKET;
        g_resource_pool.connections[i].target_ip[0] = '\0';
        g_resource_pool.connections[i].port = 0;
        g_resource_pool.connections[i].last_used = 0;
        g_resource_pool.connections[i].in_use = FALSE;
        g_resource_pool.connections[i].is_valid = FALSE;
    }

    // 初始化缓冲区池
    for (int i = 0; i < MAX_BUFFERS; i++) {
        g_resource_pool.buffers[i].buffer = malloc(BUFFER_POOL_SIZE);
        if (!g_resource_pool.buffers[i].buffer) {
            logAnalyzerError(ANALYZER_ERROR_MEMORY, "initializeResourcePool", "分配缓冲区失败");
            return FALSE;
        }
        g_resource_pool.buffers[i].size = BUFFER_POOL_SIZE;
        g_resource_pool.buffers[i].in_use = FALSE;
    }

    // 初始化缓存
    for (int i = 0; i < MAX_CACHE_ENTRIES; i++) {
        g_resource_pool.cache[i].ip[0] = '\0';
        g_resource_pool.cache[i].port = 0;
        g_resource_pool.cache[i].service[0] = '\0';
        g_resource_pool.cache[i].version[0] = '\0';
        g_resource_pool.cache[i].timestamp = 0;
        g_resource_pool.cache[i].is_valid = FALSE;
    }

    g_resource_pool.initialized = TRUE;
    return TRUE;
}

// 清理资源池
void cleanupResourcePool() {
    if (!g_resource_pool.initialized) {
        return;
    }

    // 关闭所有连接
    WaitForSingleObject(g_resource_pool.connection_mutex, INFINITE);
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (g_resource_pool.connections[i].socket != INVALID_SOCKET) {
            closesocket(g_resource_pool.connections[i].socket);
            g_resource_pool.connections[i].socket = INVALID_SOCKET;
        }
    }
    ReleaseMutex(g_resource_pool.connection_mutex);

    // 释放缓冲区
    WaitForSingleObject(g_resource_pool.buffer_mutex, INFINITE);
    for (int i = 0; i < MAX_BUFFERS; i++) {
        if (g_resource_pool.buffers[i].buffer) {
            free(g_resource_pool.buffers[i].buffer);
            g_resource_pool.buffers[i].buffer = NULL;
        }
    }
    ReleaseMutex(g_resource_pool.buffer_mutex);

    // 关闭互斥锁
    if (g_resource_pool.connection_mutex) {
        CloseHandle(g_resource_pool.connection_mutex);
    }
    if (g_resource_pool.buffer_mutex) {
        CloseHandle(g_resource_pool.buffer_mutex);
    }
    if (g_resource_pool.cache_mutex) {
        CloseHandle(g_resource_pool.cache_mutex);
    }

    g_resource_pool.initialized = FALSE;
}

// 从连接池获取连接
SOCKET getConnectionFromPool(const char* ip, int port) {
    if (!g_resource_pool.initialized) {
        if (!initializeResourcePool()) {
            return INVALID_SOCKET;
        }
    }

    WaitForSingleObject(g_resource_pool.connection_mutex, INFINITE);

    DWORD current_time = GetTickCount();

    // 查找可重用的连接
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        ConnectionPoolEntry* entry = &g_resource_pool.connections[i];

        if (entry->is_valid && !entry->in_use &&
            strcmp(entry->target_ip, ip) == 0 && entry->port == port) {

            // 检查连接是否超时
            if (current_time - entry->last_used < CONNECTION_TIMEOUT_MS) {
                entry->in_use = TRUE;
                entry->last_used = current_time;
                g_perf_stats.connections_reused++;
                ReleaseMutex(g_resource_pool.connection_mutex);
                return entry->socket;
            } else {
                // 连接超时，关闭并标记为无效
                closesocket(entry->socket);
                entry->socket = INVALID_SOCKET;
                entry->is_valid = FALSE;
            }
        }
    }

    ReleaseMutex(g_resource_pool.connection_mutex);
    g_perf_stats.connections_created++;
    return INVALID_SOCKET;  // 没有找到可重用的连接
}

// 将连接返回到连接池
void returnConnectionToPool(SOCKET sock, const char* ip, int port) {
    if (!g_resource_pool.initialized || sock == INVALID_SOCKET) {
        return;
    }

    WaitForSingleObject(g_resource_pool.connection_mutex, INFINITE);

    // 查找对应的连接条目
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        ConnectionPoolEntry* entry = &g_resource_pool.connections[i];

        if (entry->socket == sock) {
            entry->in_use = FALSE;
            entry->last_used = GetTickCount();
            ReleaseMutex(g_resource_pool.connection_mutex);
            return;
        }
    }

    // 如果没有找到，尝试添加新连接到池中
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        ConnectionPoolEntry* entry = &g_resource_pool.connections[i];

        if (!entry->is_valid) {
            entry->socket = sock;
            safe_strncpy(entry->target_ip, ip, sizeof(entry->target_ip));
            entry->port = port;
            entry->last_used = GetTickCount();
            entry->in_use = FALSE;
            entry->is_valid = TRUE;
            ReleaseMutex(g_resource_pool.connection_mutex);
            return;
        }
    }

    ReleaseMutex(g_resource_pool.connection_mutex);
    // 连接池已满，直接关闭连接
    closesocket(sock);
}

// 从缓冲区池获取缓冲区
char* getBufferFromPool(size_t required_size) {
    if (!g_resource_pool.initialized) {
        if (!initializeResourcePool()) {
            return NULL;
        }
    }

    WaitForSingleObject(g_resource_pool.buffer_mutex, INFINITE);

    // 查找可用的缓冲区
    for (int i = 0; i < MAX_BUFFERS; i++) {
        BufferPoolEntry* entry = &g_resource_pool.buffers[i];

        if (!entry->in_use && entry->size >= required_size) {
            entry->in_use = TRUE;
            g_perf_stats.buffers_reused++;
            ReleaseMutex(g_resource_pool.buffer_mutex);
            return entry->buffer;
        }
    }

    ReleaseMutex(g_resource_pool.buffer_mutex);

    // 没有找到合适的缓冲区，分配新的
    g_perf_stats.buffers_allocated++;
    return malloc(required_size);
}

// 将缓冲区返回到缓冲区池
void returnBufferToPool(char* buffer) {
    if (!g_resource_pool.initialized || !buffer) {
        return;
    }

    WaitForSingleObject(g_resource_pool.buffer_mutex, INFINITE);

    // 查找对应的缓冲区条目
    for (int i = 0; i < MAX_BUFFERS; i++) {
        BufferPoolEntry* entry = &g_resource_pool.buffers[i];

        if (entry->buffer == buffer) {
            entry->in_use = FALSE;
            // 清理缓冲区内容
            memset(buffer, 0, entry->size);
            ReleaseMutex(g_resource_pool.buffer_mutex);
            return;
        }
    }

    ReleaseMutex(g_resource_pool.buffer_mutex);
    // 不是池中的缓冲区，直接释放
    free(buffer);
}

// 查找缓存条目
BOOL findCacheEntry(const char* ip, int port, PortInfo* portInfo) {
    if (!g_resource_pool.initialized || !ip || !portInfo) {
        return FALSE;
    }

    WaitForSingleObject(g_resource_pool.cache_mutex, INFINITE);

    DWORD current_time = GetTickCount();

    for (int i = 0; i < MAX_CACHE_ENTRIES; i++) {
        CacheEntry* entry = &g_resource_pool.cache[i];

        if (entry->is_valid && strcmp(entry->ip, ip) == 0 && entry->port == port) {
            // 检查缓存是否过期
            if (current_time - entry->timestamp < CACHE_TIMEOUT_MS) {
                safe_strncpy(portInfo->service, entry->service, sizeof(portInfo->service));
                safe_strncpy(portInfo->version, entry->version, sizeof(portInfo->version));
                g_perf_stats.cache_hits++;
                ReleaseMutex(g_resource_pool.cache_mutex);
                return TRUE;
            } else {
                // 缓存过期，标记为无效
                entry->is_valid = FALSE;
            }
        }
    }

    g_perf_stats.cache_misses++;
    ReleaseMutex(g_resource_pool.cache_mutex);
    return FALSE;
}

// 添加缓存条目
void addCacheEntry(const char* ip, int port, const PortInfo* portInfo) {
    if (!g_resource_pool.initialized || !ip || !portInfo) {
        return;
    }

    WaitForSingleObject(g_resource_pool.cache_mutex, INFINITE);

    // 查找空闲的缓存条目
    for (int i = 0; i < MAX_CACHE_ENTRIES; i++) {
        CacheEntry* entry = &g_resource_pool.cache[i];

        if (!entry->is_valid) {
            safe_strncpy(entry->ip, ip, sizeof(entry->ip));
            entry->port = port;
            safe_strncpy(entry->service, portInfo->service, sizeof(entry->service));
            safe_strncpy(entry->version, portInfo->version, sizeof(entry->version));
            entry->timestamp = GetTickCount();
            entry->is_valid = TRUE;
            ReleaseMutex(g_resource_pool.cache_mutex);
            return;
        }
    }

    // 缓存已满，使用LRU策略替换最旧的条目
    int oldest_index = 0;
    DWORD oldest_time = g_resource_pool.cache[0].timestamp;

    for (int i = 1; i < MAX_CACHE_ENTRIES; i++) {
        if (g_resource_pool.cache[i].timestamp < oldest_time) {
            oldest_time = g_resource_pool.cache[i].timestamp;
            oldest_index = i;
        }
    }

    CacheEntry* entry = &g_resource_pool.cache[oldest_index];
    safe_strncpy(entry->ip, ip, sizeof(entry->ip));
    entry->port = port;
    safe_strncpy(entry->service, portInfo->service, sizeof(entry->service));
    safe_strncpy(entry->version, portInfo->version, sizeof(entry->version));
    entry->timestamp = GetTickCount();
    entry->is_valid = TRUE;

    ReleaseMutex(g_resource_pool.cache_mutex);
}

// 清理过期的缓存条目
void cleanupExpiredCache() {
    if (!g_resource_pool.initialized) {
        return;
    }

    WaitForSingleObject(g_resource_pool.cache_mutex, INFINITE);

    DWORD current_time = GetTickCount();

    for (int i = 0; i < MAX_CACHE_ENTRIES; i++) {
        CacheEntry* entry = &g_resource_pool.cache[i];

        if (entry->is_valid && (current_time - entry->timestamp >= CACHE_TIMEOUT_MS)) {
            entry->is_valid = FALSE;
        }
    }

    ReleaseMutex(g_resource_pool.cache_mutex);
}

// 获取性能统计信息
void getPerformanceStats(PerformanceStats* stats) {
    if (stats) {
        *stats = g_perf_stats;
    }
}

// 重置性能统计信息
void resetPerformanceStats() {
    memset(&g_perf_stats, 0, sizeof(PerformanceStats));
}

// 更新网络状况统计
void updateNetworkCondition(BOOL success, int response_time_ms) {
    if (success) {
        g_network_condition.successful_connections++;
        // 更新平均响应时间（简单移动平均）
        if (g_network_condition.successful_connections == 1) {
            g_network_condition.average_response_time = response_time_ms;
        } else {
            g_network_condition.average_response_time =
                (g_network_condition.average_response_time * 0.8f) + (response_time_ms * 0.2f);
        }
    } else {
        g_network_condition.failed_connections++;
    }

    // 计算丢包率
    int total_attempts = g_network_condition.successful_connections + g_network_condition.failed_connections;
    if (total_attempts > 0) {
        g_network_condition.packet_loss_rate =
            (float)g_network_condition.failed_connections / total_attempts;
    }
}

// 根据服务类型获取重试配置
const RetryConfig* getRetryConfigForService(const char* service) {
    if (!service) return &default_retry_config;

    if (strcmp(service, "HTTP") == 0 || strcmp(service, "HTTPS") == 0) {
        return &service_retry_configs[0]; // HTTP配置
    } else if (strcmp(service, "SSH") == 0) {
        return &service_retry_configs[1]; // SSH配置
    } else if (strcmp(service, "FTP") == 0 || strcmp(service, "FTPS") == 0) {
        return &service_retry_configs[2]; // FTP配置
    } else if (strcmp(service, "SMTP") == 0 || strcmp(service, "SMTPS") == 0) {
        return &service_retry_configs[3]; // SMTP配置
    } else if (strcmp(service, "MySQL") == 0 || strcmp(service, "PostgreSQL") == 0 ||
               strcmp(service, "MSSQL") == 0 || strcmp(service, "Oracle") == 0 ||
               strcmp(service, "MongoDB") == 0 || strcmp(service, "Redis") == 0) {
        return &service_retry_configs[4]; // 数据库配置
    } else if (strcmp(service, "DNS") == 0) {
        return &service_retry_configs[5]; // DNS配置
    } else {
        return &service_retry_configs[6]; // 其他服务配置
    }
}

// 自适应超时计算
int calculateAdaptiveTimeout(const RetryConfig* config, int retry_attempt) {
    if (!config) config = &default_retry_config;

    // 基础超时时间
    int timeout = config->base_timeout_ms;

    // 根据重试次数递增超时时间
    for (int i = 0; i < retry_attempt; i++) {
        timeout = (int)(timeout * config->timeout_multiplier);
    }

    // 根据网络状况调整超时时间
    if (g_network_condition.packet_loss_rate > 0.3f) {
        // 高丢包率，增加超时时间
        timeout = (int)(timeout * 1.5f);
    } else if (g_network_condition.average_response_time > 2000) {
        // 响应时间较长，适当增加超时
        timeout = (int)(timeout * 1.2f);
    }

    // 限制最大超时时间
    if (timeout > config->max_timeout_ms) {
        timeout = config->max_timeout_ms;
    }

    return timeout;
}

// 通用的select超时函数（抽象自tcp_handler.c）
int waitForSocketReady(SOCKET sock, int timeout_ms, BOOL wait_for_write) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int result;
    if (wait_for_write) {
        result = select(0, NULL, &fds, NULL, &tv);
    } else {
        result = select(0, &fds, NULL, NULL, &tv);
    }

    return result;
}

// 带重试的探测函数
AnalyzerResult performProbeWithRetry(const char *ip, int port, const char *service,
                                    char *response, int responseSize) {
    if (!ip || !response || responseSize <= 0 || port <= 0 || port > 65535) {
        logAnalyzerError(ANALYZER_ERROR_INVALID_PARAM, "performProbeWithRetry", "无效的输入参数");
        return ANALYZER_ERROR_INVALID_PARAM;
    }

    const RetryConfig* config = getRetryConfigForService(service);
    AnalyzerResult last_result = ANALYZER_ERROR_CONNECTION;

    for (int attempt = 0; attempt <= config->max_retries; attempt++) {
        DWORD start_time = GetTickCount();

        // 计算当前尝试的超时时间
        int current_timeout = calculateAdaptiveTimeout(config, attempt);

        // 执行探测
        AnalyzerResult result = sendServiceProbeWithTimeout(ip, port, response, responseSize, current_timeout);

        DWORD end_time = GetTickCount();
        int response_time = end_time - start_time;

        // 更新网络状况统计
        updateNetworkCondition(result == ANALYZER_SUCCESS, response_time);

        if (result == ANALYZER_SUCCESS) {
            return ANALYZER_SUCCESS;
        }

        last_result = result;

        // 如果不是最后一次尝试，等待重试间隔
        if (attempt < config->max_retries) {
            Sleep(config->retry_delay_ms);
        }
    }

    return last_result;
}

// 带超时的服务探测函数（重构自原sendServiceProbe）
AnalyzerResult sendServiceProbeWithTimeout(const char *ip, int port, char *response,
                                          int responseSize, int timeout_ms) {
    if (!ip || !response || responseSize <= 0 || port <= 0 || port > 65535) {
        logAnalyzerError(ANALYZER_ERROR_INVALID_PARAM, "sendServiceProbeWithTimeout", "无效的输入参数");
        return ANALYZER_ERROR_INVALID_PARAM;
    }

    response[0] = '\0';

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        logAnalyzerError(ANALYZER_ERROR_SOCKET_CREATE, "sendServiceProbeWithTimeout", "Socket创建失败");
        return ANALYZER_ERROR_SOCKET_CREATE;
    }

    // 设置非阻塞模式
    u_long mode = 1;
    if (ioctlsocket(sock, FIONBIO, &mode) == SOCKET_ERROR) {
        logAnalyzerError(ANALYZER_ERROR_SOCKET_CONFIG, "sendServiceProbeWithTimeout", "设置非阻塞模式失败");
        closesocket(sock);
        return ANALYZER_ERROR_SOCKET_CONFIG;
    }

    struct sockaddr_in server = {0};
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    int inet_result = inet_pton(AF_INET, ip, &server.sin_addr);
    if (inet_result <= 0) {
        logAnalyzerError(ANALYZER_ERROR_INVALID_PARAM, "sendServiceProbeWithTimeout", "无效的IP地址格式");
        closesocket(sock);
        return ANALYZER_ERROR_INVALID_PARAM;
    }

    // 尝试连接
    int connect_result = connect(sock, (struct sockaddr*)&server, sizeof(server));
    if (connect_result == SOCKET_ERROR) {
        int error = WSAGetLastError();
        if (error != WSAEWOULDBLOCK) {
            logAnalyzerError(ANALYZER_ERROR_CONNECTION, "sendServiceProbeWithTimeout", "连接失败");
            closesocket(sock);
            return ANALYZER_ERROR_CONNECTION;
        }
    }

    // 等待连接完成
    int select_result = waitForSocketReady(sock, timeout_ms, TRUE);
    if (select_result != 1) {
        logAnalyzerError(ANALYZER_ERROR_TIMEOUT, "sendServiceProbeWithTimeout", "连接超时");
        closesocket(sock);
        return ANALYZER_ERROR_TIMEOUT;
    }

    // 检查连接是否真的成功
    int error = 0;
    int len = sizeof(error);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &len) == SOCKET_ERROR || error != 0) {
        logAnalyzerError(ANALYZER_ERROR_CONNECTION, "sendServiceProbeWithTimeout", "连接验证失败");
        closesocket(sock);
        return ANALYZER_ERROR_CONNECTION;
    }

    // 恢复阻塞模式
    mode = 0;
    ioctlsocket(sock, FIONBIO, &mode);

    // 设置socket超时
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_ms, sizeof(timeout_ms)) == SOCKET_ERROR) {
        logAnalyzerError(ANALYZER_ERROR_SOCKET_CONFIG, "sendServiceProbeWithTimeout", "设置接收超时失败");
    }
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout_ms, sizeof(timeout_ms)) == SOCKET_ERROR) {
        logAnalyzerError(ANALYZER_ERROR_SOCKET_CONFIG, "sendServiceProbeWithTimeout", "设置发送超时失败");
    }

    // 查找端口特定的探测策略
    const ProbeStrategy *strategy = findProbeStrategy(port);
    const char **probes = generic_probes;

    if (strategy) {
        probes = strategy->probes;
    }

    // 使用智能探测策略
    for (int i = 0; probes[i] != NULL && response[0] == '\0'; i++) {
        int send_result = send(sock, probes[i], strlen(probes[i]), 0);
        if (send_result == SOCKET_ERROR) {
            continue;
        }

        Sleep(100); // 等待服务器处理

        int recv_result = recv(sock, response, responseSize - 1, 0);
        if (recv_result > 0) {
            response[recv_result] = '\0';
            break;
        }
    }

    // 如果没有收到响应，尝试等待主动横幅
    if (response[0] == '\0') {
        Sleep(500);
        int recv_result = recv(sock, response, responseSize - 1, 0);
        if (recv_result > 0) {
            response[recv_result] = '\0';
        }
    }

    closesocket(sock);
    return ANALYZER_SUCCESS;
}

// 根据端口查找探测策略
const ProbeStrategy* findProbeStrategy(int port) {
    for (int i = 0; portStrategies[i].port != 0; i++) {
        if (portStrategies[i].port == port) {
            return &portStrategies[i];
        }
    }
    return NULL;  // 没有找到特定策略，使用默认策略
}

// UDP服务探测函数
AnalyzerResult sendUDPServiceProbe(const char *ip, int port, char *response, int responseSize) {
    if (!ip || !response || responseSize <= 0 || port <= 0 || port > 65535) {
        logAnalyzerError(ANALYZER_ERROR_INVALID_PARAM, "sendUDPServiceProbe", "无效的输入参数");
        return ANALYZER_ERROR_INVALID_PARAM;
    }

    response[0] = '\0';

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        logAnalyzerError(ANALYZER_ERROR_SOCKET_CREATE, "sendUDPServiceProbe", "UDP Socket创建失败");
        return ANALYZER_ERROR_SOCKET_CREATE;
    }

    struct sockaddr_in server = {0};
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    int inet_result = inet_pton(AF_INET, ip, &server.sin_addr);
    if (inet_result <= 0) {
        logAnalyzerError(ANALYZER_ERROR_INVALID_PARAM, "sendUDPServiceProbe", "无效的IP地址格式");
        closesocket(sock);
        return ANALYZER_ERROR_INVALID_PARAM;
    }

    // 设置超时
    int timeout = 2000;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) == SOCKET_ERROR) {
        logAnalyzerError(ANALYZER_ERROR_SOCKET_CONFIG, "sendUDPServiceProbe", "设置UDP接收超时失败");
        closesocket(sock);
        return ANALYZER_ERROR_SOCKET_CONFIG;
    }

    // 根据端口选择UDP探测包
    const char **probes = NULL;
    if (port == 53) {
        probes = dns_udp_probes;
    } else if (port == 161) {
        probes = snmp_udp_probes;
    } else if (port == 123) {
        probes = ntp_udp_probes;
    } else {
        // 默认UDP探测
        static const char *default_udp_probes[] = {"\x00", NULL};
        probes = default_udp_probes;
    }

    // 发送UDP探测包
    for (int i = 0; probes[i] != NULL && response[0] == '\0'; i++) {
        int probe_len = (port == 53) ? 29 : (port == 161) ? 37 : (port == 123) ? 48 : 1;

        if (sendto(sock, probes[i], probe_len, 0, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
            continue;  // 尝试下一个探测包
        }

        // 尝试接收响应
        struct sockaddr_in from_addr;
        int from_len = sizeof(from_addr);
        int recv_result = recvfrom(sock, response, responseSize - 1, 0,
                                   (struct sockaddr*)&from_addr, &from_len);

        if (recv_result > 0) {
            response[recv_result] = '\0';
            break;  // 收到响应，停止探测
        }
    }

    closesocket(sock);
    return ANALYZER_SUCCESS;
}

AnalyzerResult analyzeTCPResponse(const char *ip, int port, PortInfo *portInfo) {
    // 参数有效性检查
    if (!ip || !portInfo || port <= 0 || port > 65535) {
        logAnalyzerError(ANALYZER_ERROR_INVALID_PARAM, "analyzeTCPResponse", "无效的输入参数");
        return ANALYZER_ERROR_INVALID_PARAM;
    }

    // 首先检查缓存
    if (findCacheEntry(ip, port, portInfo)) {
        return ANALYZER_SUCCESS;
    }

    // 从缓冲区池获取缓冲区
    char* response = getBufferFromPool(BUFFER_SIZE);
    if (!response) {
        logAnalyzerError(ANALYZER_ERROR_MEMORY, "analyzeTCPResponse", "获取缓冲区失败");
        return ANALYZER_ERROR_MEMORY;
    }

    // 使用带重试的探测机制
    AnalyzerResult result = performProbeWithRetry(ip, port, NULL, response, BUFFER_SIZE);

    if (result == ANALYZER_SUCCESS && response[0] != '\0') {
        // 使用高级服务横幅分析，包含端口信息进行交叉验证
        analyzeServiceBannerAdvanced(response, port, portInfo);

        // 将结果添加到缓存
        addCacheEntry(ip, port, portInfo);
    }

    // 返回缓冲区到池中
    returnBufferToPool(response);

    return result;
}

AnalyzerResult sendServiceProbe(const char *ip, int port, char *response, int responseSize) {
    // 参数有效性检查
    if (!ip || !response || responseSize <= 0 || port <= 0 || port > 65535) {
        logAnalyzerError(ANALYZER_ERROR_INVALID_PARAM, "sendServiceProbe", "无效的输入参数");
        return ANALYZER_ERROR_INVALID_PARAM;
    }

    // 初始化响应缓冲区
    response[0] = '\0';

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        logAnalyzerError(ANALYZER_ERROR_SOCKET_CREATE, "sendServiceProbe", "Socket创建失败");
        return ANALYZER_ERROR_SOCKET_CREATE;
    }

    struct sockaddr_in server = {0};
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    // 检查 inet_pton 返回值
    int inet_result = inet_pton(AF_INET, ip, &server.sin_addr);
    if (inet_result <= 0) {
        logAnalyzerError(ANALYZER_ERROR_INVALID_PARAM, "sendServiceProbe", "无效的IP地址格式");
        closesocket(sock);
        return ANALYZER_ERROR_INVALID_PARAM;
    }

    // 设置超时并检查返回值
    int timeout = 3000;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) == SOCKET_ERROR) {
        logAnalyzerError(ANALYZER_ERROR_SOCKET_CONFIG, "sendServiceProbe", "设置接收超时失败");
        closesocket(sock);
        return ANALYZER_ERROR_SOCKET_CONFIG;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout)) == SOCKET_ERROR) {
        logAnalyzerError(ANALYZER_ERROR_SOCKET_CONFIG, "sendServiceProbe", "设置发送超时失败");
        closesocket(sock);
        return ANALYZER_ERROR_SOCKET_CONFIG;
    }

    // 查找端口特定的探测策略
    const ProbeStrategy *strategy = findProbeStrategy(port);
    const char **probes = generic_probes;  // 默认探测包
    int custom_timeout = timeout;

    if (strategy) {
        probes = strategy->probes;
        custom_timeout = strategy->timeout_ms;

        // 更新超时设置
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&custom_timeout, sizeof(custom_timeout)) == SOCKET_ERROR) {
            logAnalyzerError(ANALYZER_ERROR_SOCKET_CONFIG, "sendServiceProbe", "更新接收超时失败");
        }
        if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&custom_timeout, sizeof(custom_timeout)) == SOCKET_ERROR) {
            logAnalyzerError(ANALYZER_ERROR_SOCKET_CONFIG, "sendServiceProbe", "更新发送超时失败");
        }
    }

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == 0) {
        // 使用智能探测策略
        for (int i = 0; probes[i] != NULL && response[0] == '\0'; i++) {
            int send_result = send(sock, probes[i], strlen(probes[i]), 0);
            if (send_result == SOCKET_ERROR) {
                // 发送失败，尝试下一个探测包
                continue;
            }

            // 等待一小段时间让服务器处理请求
            Sleep(100);

            int recv_result = recv(sock, response, responseSize - 1, 0);
            if (recv_result == SOCKET_ERROR) {
                // 接收失败，但不一定是错误，可能是服务不响应
                continue;
            } else if (recv_result == 0) {
                // 连接被对方关闭，可能是某些服务的正常行为
                continue;
            } else if (recv_result > 0) {
                // 确保字符串以null结尾
                response[recv_result] = '\0';
                break;  // 收到响应，停止探测
            }
        }

        // 如果没有收到响应，尝试只连接不发送数据（某些服务会主动发送横幅）
        if (response[0] == '\0') {
            Sleep(500);  // 等待服务器主动发送横幅
            int recv_result = recv(sock, response, responseSize - 1, 0);
            if (recv_result > 0) {
                response[recv_result] = '\0';
            }
        }
    } else {
        logAnalyzerError(ANALYZER_ERROR_CONNECTION, "sendServiceProbe", "连接目标失败");
        closesocket(sock);
        return ANALYZER_ERROR_CONNECTION;
    }

    closesocket(sock);
    return ANALYZER_SUCCESS;
}

// 版本提取模式枚举已在头文件中定义

// 版本信息清理和验证
void cleanVersionString(char *version, size_t max_len) {
    if (!version) return;

    size_t len = strlen(version);
    if (len == 0) return;

    // 去除前导空格和特殊字符
    char *start = version;
    while (*start && (*start == ' ' || *start == '\t' || *start == '/' || *start == ':')) {
        start++;
    }

    // 去除尾部空格、换行符和特殊字符
    char *end = start + strlen(start) - 1;
    while (end > start && (*end == ' ' || *end == '\t' || *end == '\r' ||
           *end == '\n' || *end == ')' || *end == ']' || *end == '}' ||
           *end == '"' || *end == '\'' || *end == ';')) {
        *end = '\0';
        end--;
    }

    // 移动清理后的字符串到开头
    if (start != version) {
        memmove(version, start, strlen(start) + 1);
    }

    // 验证版本格式的合理性
    len = strlen(version);
    if (len > 0) {
        // 检查是否包含版本号特征（数字、点号）
        BOOL has_digit = FALSE;
        for (size_t i = 0; i < len; i++) {
            if (isdigit(version[i])) {
                has_digit = TRUE;
                break;
            }
        }

        // 如果没有数字且长度过长，可能不是版本号
        if (!has_digit && len > 20) {
            version[0] = '\0';
        }

        // 截断过长的版本字符串
        if (len > max_len - 1) {
            version[max_len - 1] = '\0';
        }
    }
}

// 高级版本信息提取函数
int extractVersionInfo(const char *banner, const char *service, const char *pattern,
                      VersionExtractionMode mode, char *version, size_t version_size) {
    if (!banner || !version || version_size == 0) {
        return -1;
    }

    version[0] = '\0';

    switch (mode) {
        case VERSION_MODE_HTTP_HEADER: {
            // HTTP Server头格式：Server: Apache/2.4.41 (Ubuntu)
            char *server_start = strstr(banner, "Server:");
            if (!server_start) server_start = strstr(banner, "server:");
            if (server_start) {
                server_start += 7;
                while (*server_start == ' ' || *server_start == '\t') server_start++;

                // 查找服务名后的版本号
                if (pattern && strstr(server_start, pattern)) {
                    char *ver_start = strstr(server_start, pattern) + strlen(pattern);
                    if (*ver_start == '/') ver_start++;

                    size_t i = 0;
                    while (i < version_size - 1 && *ver_start &&
                           *ver_start != ' ' && *ver_start != '\t' && *ver_start != '\r' &&
                           *ver_start != '\n' && *ver_start != '(' && *ver_start != ';') {
                        version[i++] = *ver_start++;
                    }
                    version[i] = '\0';
                } else {
                    // 提取整个Server头内容
                    size_t i = 0;
                    while (i < version_size - 1 && *server_start &&
                           *server_start != '\r' && *server_start != '\n') {
                        version[i++] = *server_start++;
                    }
                    version[i] = '\0';
                }
            }
            break;
        }

        case VERSION_MODE_FTP_BANNER: {
            // FTP横幅格式：220 (vsFTPd 3.0.3) 或 220 ProFTPD 1.3.6
            if (strstr(banner, "220")) {
                if (pattern) {
                    char *pattern_start = strstr(banner, pattern);
                    if (pattern_start) {
                        char *ver_start = pattern_start + strlen(pattern);
                        while (*ver_start == ' ' || *ver_start == '\t') ver_start++;

                        size_t i = 0;
                        while (i < version_size - 1 && *ver_start &&
                               *ver_start != ' ' && *ver_start != ')' && *ver_start != '\r' && *ver_start != '\n') {
                            version[i++] = *ver_start++;
                        }
                        version[i] = '\0';
                    }
                }
            }
            break;
        }

        case VERSION_MODE_SSH_BANNER: {
            // SSH横幅格式：SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
            if (strstr(banner, "SSH-")) {
                if (pattern) {
                    char *pattern_start = strstr(banner, pattern);
                    if (pattern_start) {
                        char *ver_start = pattern_start + strlen(pattern);

                        size_t i = 0;
                        while (i < version_size - 1 && *ver_start &&
                               *ver_start != ' ' && *ver_start != '\r' && *ver_start != '\n') {
                            version[i++] = *ver_start++;
                        }
                        version[i] = '\0';
                    }
                }
            }
            break;
        }

        case VERSION_MODE_SMTP_BANNER: {
            // SMTP横幅格式：220 hostname ESMTP Postfix (Ubuntu)
            if (strstr(banner, "220")) {
                if (pattern) {
                    char *pattern_start = strstr(banner, pattern);
                    if (pattern_start) {
                        // 查找版本信息（通常在括号中或服务名后）
                        char *ver_start = pattern_start + strlen(pattern);
                        while (*ver_start == ' ' || *ver_start == '\t') ver_start++;

                        if (*ver_start == '(') {
                            ver_start++;
                            size_t i = 0;
                            while (i < version_size - 1 && *ver_start && *ver_start != ')') {
                                version[i++] = *ver_start++;
                            }
                            version[i] = '\0';
                        } else {
                            size_t i = 0;
                            while (i < version_size - 1 && *ver_start &&
                                   *ver_start != ' ' && *ver_start != '\r' && *ver_start != '\n') {
                                version[i++] = *ver_start++;
                            }
                            version[i] = '\0';
                        }
                    }
                }
            }
            break;
        }

        case VERSION_MODE_MYSQL_BANNER: {
            // MySQL横幅格式：5.7.34-0ubuntu0.18.04.1
            if (pattern) {
                char *pattern_start = strstr(banner, pattern);
                if (pattern_start) {
                    char *ver_start = pattern_start + strlen(pattern);

                    size_t i = 0;
                    while (i < version_size - 1 && *ver_start &&
                           *ver_start != '-' && *ver_start != ' ' && *ver_start != '\r' && *ver_start != '\n') {
                        version[i++] = *ver_start++;
                    }
                    version[i] = '\0';
                }
            }
            break;
        }

        case VERSION_MODE_PARENTHESES: {
            // 括号模式：service (version)
            char *paren_start = strchr(banner, '(');
            if (paren_start) {
                paren_start++;
                char *paren_end = strchr(paren_start, ')');
                if (paren_end) {
                    size_t len = paren_end - paren_start;
                    if (len < version_size) {
                        strncpy(version, paren_start, len);
                        version[len] = '\0';
                    }
                }
            }
            break;
        }

        case VERSION_MODE_BRACKETS: {
            // 方括号模式：service [version]
            char *bracket_start = strchr(banner, '[');
            if (bracket_start) {
                bracket_start++;
                char *bracket_end = strchr(bracket_start, ']');
                if (bracket_end) {
                    size_t len = bracket_end - bracket_start;
                    if (len < version_size) {
                        strncpy(version, bracket_start, len);
                        version[len] = '\0';
                    }
                }
            }
            break;
        }

        case VERSION_MODE_QUOTED: {
            // 引号模式：service "version"
            char *quote_start = strchr(banner, '"');
            if (quote_start) {
                quote_start++;
                char *quote_end = strchr(quote_start, '"');
                if (quote_end) {
                    size_t len = quote_end - quote_start;
                    if (len < version_size) {
                        strncpy(version, quote_start, len);
                        version[len] = '\0';
                    }
                }
            }
            break;
        }

        case VERSION_MODE_SIMPLE:
        default: {
            // 简单模式：查找模式后的版本号
            if (pattern) {
                char *pattern_start = strstr(banner, pattern);
                if (pattern_start) {
                    char *ver_start = pattern_start + strlen(pattern);
                    while (*ver_start == ' ' || *ver_start == '\t' || *ver_start == '/') ver_start++;

                    size_t i = 0;
                    while (i < version_size - 1 && *ver_start &&
                           *ver_start != ' ' && *ver_start != '\t' && *ver_start != '\r' &&
                           *ver_start != '\n' && *ver_start != ')' && *ver_start != ']' && *ver_start != '}') {
                        version[i++] = *ver_start++;
                    }
                    version[i] = '\0';
                }
            }
            break;
        }
    }

    // 清理和验证版本字符串
    cleanVersionString(version, version_size);

    return (version[0] != '\0') ? 0 : -1;
}

// 简单的版本提取函数（保持向后兼容）
void extractVersionSimple(const char *banner, const char *pattern, char *version, size_t version_size) {
    if (!banner || !pattern || !version) return;

    extractVersionInfo(banner, NULL, pattern, VERSION_MODE_SIMPLE, version, version_size);
}

// 高级服务横幅分析函数
void analyzeServiceBannerAdvanced(const char *banner, int port, PortInfo *portInfo) {
    if (!banner || !portInfo) {
        logAnalyzerError(ANALYZER_ERROR_INVALID_PARAM, "analyzeServiceBannerAdvanced", "无效的输入参数");
        return;
    }

    int best_confidence = 0;
    int best_match = -1;

    // 遍历所有服务模式，找到最佳匹配
    for (int i = 0; servicePatterns[i].pattern != NULL; i++) {
        if (strstr(banner, servicePatterns[i].pattern)) {
            int confidence = servicePatterns[i].confidence;

            // 如果端口匹配，增加置信度
            if (servicePatterns[i].port_hint == port) {
                confidence += 10;
            } else if (servicePatterns[i].port_hint != 0) {
                // 端口不匹配，降低置信度
                confidence -= 20;
            }

            // 选择置信度最高的匹配
            if (confidence > best_confidence) {
                best_confidence = confidence;
                best_match = i;
            }
        }
    }

    // 如果找到匹配，设置服务信息
    if (best_match >= 0) {
        const ServicePattern *pattern = &servicePatterns[best_match];

        // 设置服务名称
        if (safe_strncpy(portInfo->service, pattern->service, sizeof(portInfo->service)) != 0) {
            logAnalyzerError(ANALYZER_ERROR_MEMORY, "analyzeServiceBannerAdvanced", "服务名称复制失败");
            return;
        }

        // 使用高级版本信息提取
        char temp_version[64] = {0};
        int extraction_result = -1;

        // 根据服务类型选择最佳的版本提取模式
        if (strcmp(pattern->service, "HTTP") == 0 || strcmp(pattern->service, "HTTPS") == 0) {
            // HTTP服务：优先尝试Server头模式
            extraction_result = extractVersionInfo(banner, pattern->service, "Apache", VERSION_MODE_HTTP_HEADER, temp_version, sizeof(temp_version));
            if (extraction_result != 0) {
                extraction_result = extractVersionInfo(banner, pattern->service, "nginx", VERSION_MODE_HTTP_HEADER, temp_version, sizeof(temp_version));
            }
            if (extraction_result != 0) {
                extraction_result = extractVersionInfo(banner, pattern->service, "Microsoft-IIS", VERSION_MODE_HTTP_HEADER, temp_version, sizeof(temp_version));
            }
            if (extraction_result != 0) {
                extraction_result = extractVersionInfo(banner, pattern->service, NULL, VERSION_MODE_HTTP_HEADER, temp_version, sizeof(temp_version));
            }
        } else if (strcmp(pattern->service, "SSH") == 0) {
            // SSH服务：使用SSH横幅模式
            extraction_result = extractVersionInfo(banner, pattern->service, "SSH-2.0-OpenSSH_", VERSION_MODE_SSH_BANNER, temp_version, sizeof(temp_version));
            if (extraction_result != 0) {
                extraction_result = extractVersionInfo(banner, pattern->service, "SSH-2.0-", VERSION_MODE_SSH_BANNER, temp_version, sizeof(temp_version));
            }
        } else if (strcmp(pattern->service, "FTP") == 0 || strcmp(pattern->service, "FTPS") == 0) {
            // FTP服务：使用FTP横幅模式
            extraction_result = extractVersionInfo(banner, pattern->service, "vsFTPd", VERSION_MODE_FTP_BANNER, temp_version, sizeof(temp_version));
            if (extraction_result != 0) {
                extraction_result = extractVersionInfo(banner, pattern->service, "ProFTPD", VERSION_MODE_FTP_BANNER, temp_version, sizeof(temp_version));
            }
            if (extraction_result != 0) {
                extraction_result = extractVersionInfo(banner, pattern->service, "FileZilla Server", VERSION_MODE_FTP_BANNER, temp_version, sizeof(temp_version));
            }
            // 尝试括号模式
            if (extraction_result != 0) {
                extraction_result = extractVersionInfo(banner, pattern->service, NULL, VERSION_MODE_PARENTHESES, temp_version, sizeof(temp_version));
            }
        } else if (strcmp(pattern->service, "SMTP") == 0 || strcmp(pattern->service, "SMTPS") == 0) {
            // SMTP服务：使用SMTP横幅模式
            extraction_result = extractVersionInfo(banner, pattern->service, "Postfix", VERSION_MODE_SMTP_BANNER, temp_version, sizeof(temp_version));
            if (extraction_result != 0) {
                extraction_result = extractVersionInfo(banner, pattern->service, "Sendmail", VERSION_MODE_SMTP_BANNER, temp_version, sizeof(temp_version));
            }
            if (extraction_result != 0) {
                extraction_result = extractVersionInfo(banner, pattern->service, "Microsoft ESMTP", VERSION_MODE_SMTP_BANNER, temp_version, sizeof(temp_version));
            }
            // 尝试括号模式
            if (extraction_result != 0) {
                extraction_result = extractVersionInfo(banner, pattern->service, NULL, VERSION_MODE_PARENTHESES, temp_version, sizeof(temp_version));
            }
        } else if (strcmp(pattern->service, "MySQL") == 0) {
            // MySQL服务：使用MySQL横幅模式
            extraction_result = extractVersionInfo(banner, pattern->service, "", VERSION_MODE_MYSQL_BANNER, temp_version, sizeof(temp_version));
        } else if (strcmp(pattern->service, "POP3") == 0 || strcmp(pattern->service, "POP3S") == 0 ||
                   strcmp(pattern->service, "IMAP") == 0 || strcmp(pattern->service, "IMAPS") == 0) {
            // 邮件服务：尝试多种模式
            extraction_result = extractVersionInfo(banner, pattern->service, "Dovecot", VERSION_MODE_SIMPLE, temp_version, sizeof(temp_version));
            if (extraction_result != 0) {
                extraction_result = extractVersionInfo(banner, pattern->service, NULL, VERSION_MODE_PARENTHESES, temp_version, sizeof(temp_version));
            }
            if (extraction_result != 0) {
                extraction_result = extractVersionInfo(banner, pattern->service, NULL, VERSION_MODE_BRACKETS, temp_version, sizeof(temp_version));
            }
        } else if (strcmp(pattern->service, "DNS") == 0) {
            // DNS服务：尝试BIND版本提取
            extraction_result = extractVersionInfo(banner, pattern->service, "BIND", VERSION_MODE_SIMPLE, temp_version, sizeof(temp_version));
            if (extraction_result != 0) {
                extraction_result = extractVersionInfo(banner, pattern->service, "dnsmasq", VERSION_MODE_SIMPLE, temp_version, sizeof(temp_version));
            }
        } else if (strcmp(pattern->service, "Proxy") == 0) {
            // 代理服务：尝试Squid版本提取
            extraction_result = extractVersionInfo(banner, pattern->service, "squid", VERSION_MODE_SIMPLE, temp_version, sizeof(temp_version));
        } else {
            // 其他服务：尝试通用模式
            if (pattern->version_pattern) {
                // 使用服务指纹中定义的模式
                if (strstr(pattern->version_pattern, "Apache/")) {
                    extraction_result = extractVersionInfo(banner, pattern->service, "Apache/", VERSION_MODE_SIMPLE, temp_version, sizeof(temp_version));
                } else if (strstr(pattern->version_pattern, "nginx/")) {
                    extraction_result = extractVersionInfo(banner, pattern->service, "nginx/", VERSION_MODE_SIMPLE, temp_version, sizeof(temp_version));
                } else if (strstr(pattern->version_pattern, "Microsoft-IIS/")) {
                    extraction_result = extractVersionInfo(banner, pattern->service, "Microsoft-IIS/", VERSION_MODE_SIMPLE, temp_version, sizeof(temp_version));
                } else {
                    // 尝试多种通用模式
                    extraction_result = extractVersionInfo(banner, pattern->service, NULL, VERSION_MODE_PARENTHESES, temp_version, sizeof(temp_version));
                    if (extraction_result != 0) {
                        extraction_result = extractVersionInfo(banner, pattern->service, NULL, VERSION_MODE_BRACKETS, temp_version, sizeof(temp_version));
                    }
                    if (extraction_result != 0) {
                        extraction_result = extractVersionInfo(banner, pattern->service, NULL, VERSION_MODE_QUOTED, temp_version, sizeof(temp_version));
                    }
                }
            } else {
                // 没有版本模式，尝试通用提取
                extraction_result = extractVersionInfo(banner, pattern->service, NULL, VERSION_MODE_PARENTHESES, temp_version, sizeof(temp_version));
                if (extraction_result != 0) {
                    extraction_result = extractVersionInfo(banner, pattern->service, NULL, VERSION_MODE_BRACKETS, temp_version, sizeof(temp_version));
                }
            }
        }

        // 如果成功提取到版本信息，保存到结果中
        if (extraction_result == 0 && temp_version[0] != '\0') {
            if (safe_strncpy(portInfo->version, temp_version, sizeof(portInfo->version)) != 0) {
                logAnalyzerError(ANALYZER_ERROR_MEMORY, "analyzeServiceBannerAdvanced", "版本信息复制失败");
                return;
            }
        }
    }
}

// 保持向后兼容的原始函数
void analyzeServiceBanner(const char *banner, PortInfo *portInfo) {
    // 参数有效性检查
    if (!banner || !portInfo) {
        logAnalyzerError(ANALYZER_ERROR_INVALID_PARAM, "analyzeServiceBanner", "无效的输入参数");
        return;
    }

    // 使用高级分析函数，端口设为0（表示不进行端口匹配）
    analyzeServiceBannerAdvanced(banner, 0, portInfo);
}