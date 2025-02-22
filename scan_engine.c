#include <stdio.h>
#include "tcp_handler.h"
#include "scan_engine.h"
#include "udp_handler.h"
#include "icmp_handler.h"

int performScan(ScanConfig* config, int port) {
    // 如果是ICMP模式，直接返回ping结果，忽略端口
    if (config->scanMode == SCAN_TYPE_ICMP) {
        return performICMPPing(config->targetIP, config->timeout);
    }
    
    // 其他扫描模式需要指定端口
    switch(config->scanMode) {
        case SCAN_TYPE_TCP:
            return performTCPScan(config->targetIP, port, config->timeout);
        case SCAN_TYPE_UDP:
            return performUDPScan(config->targetIP, port, config->timeout);
        default:
            return PORT_STATUS_ERROR;
    }
}

void handleScanResult(int status, int port, BOOL verbose) {
    // 对于ICMP ping，不显示端口信息
    if (port == -1) {  // 使用-1表示ICMP ping
        switch(status) {
            case PORT_STATUS_OPEN:
                printf("主机状态: 在线\n");
                break;
            case PORT_STATUS_CLOSED:
                printf("主机状态: 离线\n");
                break;
            case PORT_STATUS_ERROR:
                printf("主机状态: 检测出错\n");
                break;
        }
        return;
    }

    // 其他扫描模式显示端口信息
    switch(status) {
        case PORT_STATUS_OPEN:
            printf("端口 %d: 开放\n", port);
            break;
        case PORT_STATUS_CLOSED:
            if (verbose) {
                printf("端口 %d: 关闭\n", port);
            }
            break;
        case PORT_STATUS_FILTERED:
            if (verbose) {
                printf("端口 %d: 被过滤\n", port);
            }
            break;
        case PORT_STATUS_ERROR:
            if (verbose) {
                printf("端口 %d: 扫描错误\n", port);
            }
            break;
    }
} 