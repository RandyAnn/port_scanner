#ifndef ICMP_HANDLER_H
#define ICMP_HANDLER_H

#include <winsock2.h>
#include "scanner_utils.h"

// ICMP扫描函数声明
int performICMPPing(const char* target_ip, int timeout);
BOOL icmpPing(const char *ip, int timeout);

#endif 