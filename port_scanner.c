#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "scanner_utils.h"
#include "tcp_handler.h"
#include "port_analyzer.h"
#include "thread_pool.h"

#pragma comment(lib, "ws2_32.lib")

#define MAX_PORT 65535
#define MIN_PORT 1

void printBanner() {
    printf("************************************************\n");
    printf("*            高级端口扫描工具 v1.0             *\n");
    printf("*          支持TCP/UDP端口扫描和分析          *\n");
    printf("*          支持常见服务识别和漏洞检测         *\n");
    printf("************************************************\n\n");
}

void printUsage() {
    printf("使用方法:\n");
    printf("port_scanner.exe <目标IP> [选项]\n\n");
    printf("选项:\n");
    printf("-p <端口>        指定要扫描的端口 (例如: 80 或 1-100)\n");
    printf("-t <超时时间>    设置连接超时时间(毫秒)\n");
    printf("-m <扫描模式>    1=TCP连接扫描 2=ICMP Ping测试 3=UDP扫描\n");
    printf("-n <线程数>      设置扫描线程数(1-%d)\n", MAX_THREADS);
    printf("-v              显示详细信息\n");
    printf("-a              进行服务版本分析\n");
    printf("\n示例:\n");
    printf("扫描单个端口: port_scanner.exe 192.168.1.1 -p 80 -t 1000 -m 1 -v\n");
    printf("ICMP Ping测试: port_scanner.exe 192.168.1.1 -t 1000 -m 2 -v\n");
    printf("扫描端口范围: port_scanner.exe 192.168.1.1 -p 1-1000 -t 1000 -m 1 -v -n 4\n");
}

int main(int argc, char *argv[]) {
    WSADATA wsaData;
    ScanConfig config;
    int result;

    // 初始化WinSock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup失败: %d\n", WSAGetLastError());
        return 1;
    }

    printBanner();

    // 检查命令行参数
    if (argc < 2) {
        printUsage();
        WSACleanup();
        return 1;
    }

    // 初始化扫描配置
    initScanConfig(&config);
    
    // 解析命令行参数
    if (!parseCommandLine(argc, argv, &config)) {
        printUsage();
        WSACleanup();
        return 1;
    }

    // 开始扫描
    result = startScan(&config);

    if (result != 0) {
        printf("扫描过程中发生错误\n");
    }

    WSACleanup();
    return result;
}
