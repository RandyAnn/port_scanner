#ifndef SCAN_ENGINE_H
#define SCAN_ENGINE_H

#include "scanner_utils.h"
#include "tcp_handler.h"
#include "udp_handler.h"
#include "icmp_handler.h"

// 扫描函数声明
int performScan(ScanConfig* config, int port);
void handleScanResult(int status, int port, BOOL verbose);

// 具体扫描实现函数
int performTCPScan(const char* target_ip, int port, int timeout);
int performTCPSYNScan(const char* target_ip, int port, int timeout);
int performUDPScan(const char* target_ip, int port, int timeout);

#endif 