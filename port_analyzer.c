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
        
        // 检测潜在漏洞
        detectVulnerabilities(ip, port, portInfo->service, portInfo);
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

BOOL detectVulnerabilities(const char *ip, int port, const char *service, PortInfo *portInfo) {
    // 简单的漏洞检测逻辑
    if (strcmp(service, "FTP") == 0) {
        // 检查匿名FTP访问
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock != INVALID_SOCKET) {
            struct sockaddr_in server = {0};
            server.sin_family = AF_INET;
            server.sin_port = htons(port);
            inet_pton(AF_INET, ip, &server.sin_addr);

            if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == 0) {
                char response[BUFFER_SIZE];
                recv(sock, response, sizeof(response) - 1, 0);
                
                send(sock, "USER anonymous\r\n", 15, 0);
                recv(sock, response, sizeof(response) - 1, 0);
                
                send(sock, "PASS anonymous@test.com\r\n", 24, 0);
                recv(sock, response, sizeof(response) - 1, 0);

                if (strstr(response, "230")) {
                    portInfo->isVulnerable = TRUE;
                    strcat(portInfo->version, " (允许匿名访问)");
                }
            }
            closesocket(sock);
        }
    }
    // 可以添加更多服务的漏洞检测逻辑

    return portInfo->isVulnerable;
} 