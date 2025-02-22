#define _WIN32_WINNT 0x0600
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include "tcp_handler.h"
#include "port_analyzer.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// 常见服务的默认端口和名称
static const struct {
    int port;
    const char *name;
} commonServices[] = {
    {21, "FTP"},
    {22, "SSH"},
    {23, "Telnet"},
    {25, "SMTP"},
    {53, "DNS"},
    {80, "HTTP"},
    {110, "POP3"},
    {143, "IMAP"},
    {443, "HTTPS"},
    {3306, "MySQL"},
    {3389, "RDP"},
    {0, NULL}
};

int performTCPScan(const char* target_ip, int port, int timeout) {
    if (tcpConnectScan(target_ip, port, timeout)) {
        return PORT_STATUS_OPEN;
    }
    return PORT_STATUS_CLOSED;
}

BOOL tcpConnectScan(const char *ip, int port, int timeout) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return FALSE;
    }

    // 设置非阻塞模式
    unsigned long mode = 1;
    if (ioctlsocket(sock, FIONBIO, &mode) != 0) {
        closesocket(sock);
        return FALSE;
    }

    struct sockaddr_in server = {0};
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server.sin_addr);

    // 尝试连接
    connect(sock, (struct sockaddr*)&server, sizeof(server));

    // 使用select来等待连接完成或超时
    fd_set write_fds;
    FD_ZERO(&write_fds);
    FD_SET(sock, &write_fds);

    struct timeval tv;
    tv.tv_sec = timeout / 1000;           // 秒
    tv.tv_usec = (timeout % 1000) * 1000; // 微秒

    int result = select(0, NULL, &write_fds, NULL, &tv);

    // 恢复阻塞模式
    mode = 0;
    ioctlsocket(sock, FIONBIO, &mode);

    if (result == 1) {
        // 检查是否真的连接成功
        int error = 0;
        int len = sizeof(error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &len);
        
        closesocket(sock);
        return error == 0;
    }

    closesocket(sock);
    return FALSE;
}