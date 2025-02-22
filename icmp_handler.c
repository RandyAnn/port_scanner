#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include "icmp_handler.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

int performICMPPing(const char* target_ip, int timeout) {
    if (icmpPing(target_ip, timeout)) {
        return PORT_STATUS_OPEN;
    }
    return PORT_STATUS_CLOSED;
}

BOOL icmpPing(const char *ip, int timeout) {
    HANDLE hIcmp;
    char SendData[] = "ICMP PING TEST";
    LPVOID ReplyBuffer;
    DWORD ReplySize;
    BOOL success = FALSE;

    // 创建ICMP句柄
    hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    // 分配响应缓冲区
    ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
    ReplyBuffer = malloc(ReplySize);
    if (ReplyBuffer == NULL) {
        IcmpCloseHandle(hIcmp);
        return FALSE;
    }

    // 发送ICMP Echo请求
    if (IcmpSendEcho(hIcmp, 
                     inet_addr(ip),
                     SendData, 
                     sizeof(SendData),
                     NULL,
                     ReplyBuffer,
                     ReplySize,
                     timeout)) {
        PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
        if (pEchoReply->Status == IP_SUCCESS) {
            success = TRUE;
        }
    }

    free(ReplyBuffer);
    IcmpCloseHandle(hIcmp);
    return success;
} 