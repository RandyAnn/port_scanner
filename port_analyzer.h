#ifndef PORT_ANALYZER_H
#define PORT_ANALYZER_H

#include "scanner_utils.h"

// 服务识别函数
void analyzeTCPResponse(const char *ip, int port, PortInfo *portInfo);
BOOL detectVulnerabilities(const char *ip, int port, const char *service, PortInfo *portInfo);
void sendServiceProbe(const char *ip, int port, char *response, int responseSize);
void analyzeServiceBanner(const char *banner, PortInfo *portInfo);

#endif 