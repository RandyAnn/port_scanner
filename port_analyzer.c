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

// 增强的服务指纹数据库
typedef struct {
    const char *pattern;        // 匹配模式
    const char *service;        // 服务名称
    const char *version_pattern; // 版本提取模式
    int confidence;             // 置信度 (1-100)
    int port_hint;              // 端口提示 (0表示任意端口)
} ServicePattern;

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

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == 0) {
        // 发送探测数据
        const char *probes[] = {
            "HEAD / HTTP/1.0\r\n\r\n",  // HTTP
            "HELP\r\n",                 // FTP
            "\r\n",                     // SMTP
            NULL
        };

        for (int i = 0; probes[i] != NULL && response[0] == '\0'; i++) {
            int send_result = send(sock, probes[i], strlen(probes[i]), 0);
            if (send_result == SOCKET_ERROR) {
                logAnalyzerError(ANALYZER_ERROR_SEND, "sendServiceProbe", "发送探测数据失败");
                closesocket(sock);
                return ANALYZER_ERROR_SEND;
            }

            int recv_result = recv(sock, response, responseSize - 1, 0);
            if (recv_result == SOCKET_ERROR) {
                // 接收失败，但不一定是错误，可能是服务不响应
                continue;
            } else if (recv_result == 0) {
                // 连接被对方关闭
                continue;
            } else if (recv_result > 0) {
                // 确保字符串以null结尾
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

// 简单的版本提取函数（用于不支持正则表达式的情况）
void extractVersionSimple(const char *banner, const char *pattern, char *version, size_t version_size) {
    if (!banner || !pattern || !version) return;

    char *start = strstr(banner, pattern);
    if (!start) return;

    start += strlen(pattern);

    // 跳过空格
    while (*start == ' ' || *start == '\t') start++;

    // 提取版本号直到遇到空格、换行或其他分隔符
    size_t i = 0;
    while (i < version_size - 1 && *start &&
           *start != ' ' && *start != '\t' && *start != '\r' && *start != '\n' &&
           *start != ')' && *start != ']' && *start != '}') {
        version[i++] = *start++;
    }
    version[i] = '\0';
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

        // 尝试提取版本信息
        if (pattern->version_pattern) {
            // 简化的版本提取（不使用正则表达式）
            char temp_version[64] = {0};

            if (strstr(pattern->version_pattern, "Apache/")) {
                extractVersionSimple(banner, "Apache/", temp_version, sizeof(temp_version));
            } else if (strstr(pattern->version_pattern, "nginx/")) {
                extractVersionSimple(banner, "nginx/", temp_version, sizeof(temp_version));
            } else if (strstr(pattern->version_pattern, "Microsoft-IIS/")) {
                extractVersionSimple(banner, "Microsoft-IIS/", temp_version, sizeof(temp_version));
            } else if (strstr(pattern->version_pattern, "SSH-2.0-OpenSSH_")) {
                extractVersionSimple(banner, "SSH-2.0-OpenSSH_", temp_version, sizeof(temp_version));
            } else if (strstr(pattern->version_pattern, "SSH-2.0-")) {
                extractVersionSimple(banner, "SSH-2.0-", temp_version, sizeof(temp_version));
            } else if (strstr(pattern->version_pattern, "220 ProFTPD")) {
                extractVersionSimple(banner, "220 ProFTPD ", temp_version, sizeof(temp_version));
            } else if (strstr(pattern->version_pattern, "vsFTPd")) {
                extractVersionSimple(banner, "vsFTPd ", temp_version, sizeof(temp_version));
            } else {
                // 通用版本提取
                char *ver = strstr(banner, "Server:");
                if (ver) {
                    extractVersionSimple(banner, "Server:", temp_version, sizeof(temp_version));
                }
            }

            if (temp_version[0] != '\0') {
                if (safe_strncpy(portInfo->version, temp_version, sizeof(portInfo->version)) != 0) {
                    logAnalyzerError(ANALYZER_ERROR_MEMORY, "analyzeServiceBannerAdvanced", "版本信息复制失败");
                    return;
                }
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