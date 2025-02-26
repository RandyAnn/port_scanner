#define _WIN32_WINNT 0x0600
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h> 
#include "port_analyzer.h"

#define BUFFER_SIZE 1024

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

void analyzeTCPResponse(const char *ip, int port, PortInfo *portInfo) {
    char response[BUFFER_SIZE] = {0};
    
    // 发送服务探测包并接收响应
    sendServiceProbe(ip, port, response, BUFFER_SIZE);
    
    if (response[0] != '\0') {
        // 分析服务横幅信息
        analyzeServiceBanner(response, portInfo);
    }
}

void sendServiceProbe(const char *ip, int port, char *response, int responseSize) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return;
    }

    struct sockaddr_in server = {0};
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server.sin_addr);

    // 设置超时
    int timeout = 3000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == 0) {
        // 发送探测数据
        const char *probes[] = {
            "HEAD / HTTP/1.0\r\n\r\n",  // HTTP
            "HELP\r\n",                 // FTP
            "\r\n",                     // SMTP
            NULL
        };

        for (int i = 0; probes[i] != NULL && response[0] == '\0'; i++) {
            send(sock, probes[i], strlen(probes[i]), 0);
            recv(sock, response, responseSize - 1, 0);
        }
    }

    closesocket(sock);
}

void analyzeServiceBanner(const char *banner, PortInfo *portInfo) {
    for (int i = 0; servicePatterns[i].pattern != NULL; i++) {
        if (strstr(banner, servicePatterns[i].pattern)) {
            strcpy(portInfo->service, servicePatterns[i].service);
            if (servicePatterns[i].version) {
                strcpy(portInfo->version, servicePatterns[i].version);
            } else {
                // 尝试从横幅中提取版本信息
                char *ver = strstr(banner, "Server:");
                if (ver) {
                    strncpy(portInfo->version, ver + 7, sizeof(portInfo->version) - 1);
                }
            }
            break;
        }
    }
} 