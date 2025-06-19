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

    char response[BUFFER_SIZE] = {0};

    // 发送服务探测包并接收响应
    AnalyzerResult result = sendServiceProbe(ip, port, response, BUFFER_SIZE);
    if (result != ANALYZER_SUCCESS) {
        return result;
    }

    if (response[0] != '\0') {
        // 使用高级服务横幅分析，包含端口信息进行交叉验证
        analyzeServiceBannerAdvanced(response, port, portInfo);
    }

    return ANALYZER_SUCCESS;
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