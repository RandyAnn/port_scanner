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

// 服务指纹数据库（简化版）
static const struct {
    const char *pattern;
    const char *service;
    const char *version;
} servicePatterns[] = {
    {"SSH-2.0", "SSH", "2.0"},
    {"HTTP/1.", "HTTP", NULL},
    {"220 (vsFTPd", "FTP", "vsFTPd"},
    {"220 ProFTPD", "FTP", "ProFTPD"},
    {"*SMTP*", "SMTP", NULL},
    {"MySQL", "MySQL", NULL},
    {NULL, NULL, NULL}
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
        // 分析服务横幅信息
        analyzeServiceBanner(response, portInfo);
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

void analyzeServiceBanner(const char *banner, PortInfo *portInfo) {
    // 参数有效性检查
    if (!banner || !portInfo) {
        logAnalyzerError(ANALYZER_ERROR_INVALID_PARAM, "analyzeServiceBanner", "无效的输入参数");
        return;
    }

    for (int i = 0; servicePatterns[i].pattern != NULL; i++) {
        if (strstr(banner, servicePatterns[i].pattern)) {
            // 使用安全字符串复制函数
            if (safe_strncpy(portInfo->service, servicePatterns[i].service, sizeof(portInfo->service)) != 0) {
                logAnalyzerError(ANALYZER_ERROR_MEMORY, "analyzeServiceBanner", "服务名称复制失败");
                return;
            }

            if (servicePatterns[i].version) {
                if (safe_strncpy(portInfo->version, servicePatterns[i].version, sizeof(portInfo->version)) != 0) {
                    logAnalyzerError(ANALYZER_ERROR_MEMORY, "analyzeServiceBanner", "版本信息复制失败");
                    return;
                }
            } else {
                // 尝试从横幅中提取版本信息
                char *ver = strstr(banner, "Server:");
                if (ver) {
                    // 跳过 "Server:" 并去除前导空格
                    ver += 7;
                    while (*ver == ' ' || *ver == '\t') {
                        ver++;
                    }

                    // 安全复制版本信息
                    if (safe_strncpy(portInfo->version, ver, sizeof(portInfo->version)) != 0) {
                        logAnalyzerError(ANALYZER_ERROR_MEMORY, "analyzeServiceBanner", "版本信息提取失败");
                        return;
                    }

                    // 去除尾部的换行符和回车符
                    size_t len = strlen(portInfo->version);
                    while (len > 0 && (portInfo->version[len-1] == '\r' || portInfo->version[len-1] == '\n')) {
                        portInfo->version[len-1] = '\0';
                        len--;
                    }
                }
            }
            break;
        }
    }
}