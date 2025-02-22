#ifndef SCANNER_UTILS_H
#define SCANNER_UTILS_H

#include <winsock2.h>
#include <windows.h>

#define MAX_IP_LENGTH 16
#define DEFAULT_TIMEOUT 1000
#define DEFAULT_SCAN_MODE 1

// 扫描类型定义
#define SCAN_TYPE_TCP 1
#define SCAN_TYPE_ICMP 2
#define SCAN_TYPE_UDP 3

// 端口状态定义
#define PORT_STATUS_OPEN 1
#define PORT_STATUS_CLOSED 2
#define PORT_STATUS_FILTERED 3
#define PORT_STATUS_ERROR 0

// 先定义 PortInfo 结构体
typedef struct {
    int port;
    char service[64];
    char version[128];
    char status[32];
    BOOL isVulnerable;
} PortInfo;

// 再定义 ScanConfig 结构体
typedef struct {
    char targetIP[MAX_IP_LENGTH];
    int startPort;
    int endPort;
    int timeout;
    int scanMode;
    BOOL verbose;
    BOOL analyzeServices;
    int threadCount;    // 添加线程数配置
} ScanConfig;

// 函数声明
void initScanConfig(ScanConfig *config);
BOOL parseCommandLine(int argc, char *argv[], ScanConfig *config);
BOOL isValidIPAddress(const char *ipAddress);
BOOL isPortInRange(int port);
void printProgress(int current, int total);
void saveResults(const char *filename, PortInfo *results, int count);
int startScan(ScanConfig *config);

#endif 