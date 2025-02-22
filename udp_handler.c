#define _WIN32_WINNT 0x0600
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "udp_handler.h"

int performUDPScan(const char* target_ip, int port, int timeout) {
    if (udpScan(target_ip, port, timeout)) {
        return PORT_STATUS_OPEN;
    }
    return PORT_STATUS_CLOSED;
}

BOOL udpScan(const char *ip, int port, int timeout) {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        return FALSE;
    }

    // 设置超时
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

    struct sockaddr_in server = {0};
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server.sin_addr);

    // 发送空UDP数据包
    char buffer[1] = {0};
    if (sendto(sock, buffer, 1, 0, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        closesocket(sock);
        return FALSE;
    }

    // 尝试接收响应
    char recv_buffer[256];
    struct sockaddr_in from_addr;
    int from_len = sizeof(from_addr);
    
    if (recvfrom(sock, recv_buffer, sizeof(recv_buffer), 0, 
                 (struct sockaddr*)&from_addr, &from_len) == SOCKET_ERROR) {
        int error = WSAGetLastError();
        closesocket(sock);
        
        // 如果是超时错误，可能表示端口开放（没有收到ICMP不可达消息）
        if (error == WSAETIMEDOUT) {
            return TRUE;
        }
        // 如果收到ICMP端口不可达消息，表示端口关闭
        else if (error == WSAECONNRESET) {
            return FALSE;
        }
        return FALSE;  // 其他错误情况
    }

    closesocket(sock);
    return TRUE;  // 收到响应，端口开放
} 