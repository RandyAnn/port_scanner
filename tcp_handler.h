#ifndef TCP_HANDLER_H
#define TCP_HANDLER_H

#include <winsock2.h>
#include "scanner_utils.h"

// TCP扫描函数声明
int performTCPScan(const char* target_ip, int port, int timeout);
BOOL tcpConnectScan(const char *ip, int port, int timeout);

#endif 