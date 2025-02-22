#ifndef UDP_HANDLER_H
#define UDP_HANDLER_H

#include <winsock2.h>
#include "scanner_utils.h"

// UDP扫描函数声明
int performUDPScan(const char* target_ip, int port, int timeout);
BOOL udpScan(const char *ip, int port, int timeout);

#endif 