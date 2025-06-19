#ifndef PORT_ANALYZER_H
#define PORT_ANALYZER_H

#include "scanner_utils.h"

// 错误码定义
typedef enum {
    ANALYZER_SUCCESS = 0,
    ANALYZER_ERROR_NETWORK,
    ANALYZER_ERROR_TIMEOUT,
    ANALYZER_ERROR_MEMORY,
    ANALYZER_ERROR_INVALID_PARAM,
    ANALYZER_ERROR_SOCKET_CREATE,
    ANALYZER_ERROR_SOCKET_CONFIG,
    ANALYZER_ERROR_CONNECTION,
    ANALYZER_ERROR_SEND,
    ANALYZER_ERROR_RECV
} AnalyzerResult;

// 安全字符串处理函数
int safe_strncpy(char* dest, const char* src, size_t dest_size);
int safe_snprintf(char* buffer, size_t size, const char* format, ...);

// 错误日志记录函数
void logAnalyzerError(AnalyzerResult error, const char* function, const char* details);

// 探测策略结构体声明
typedef struct {
    int port;
    const char **probes;
    int timeout_ms;
    int max_retries;
    const char *description;
} ProbeStrategy;

// 版本提取模式枚举
typedef enum {
    VERSION_MODE_SIMPLE,
    VERSION_MODE_HTTP_HEADER,
    VERSION_MODE_FTP_BANNER,
    VERSION_MODE_SSH_BANNER,
    VERSION_MODE_SMTP_BANNER,
    VERSION_MODE_MYSQL_BANNER,
    VERSION_MODE_PARENTHESES,
    VERSION_MODE_BRACKETS,
    VERSION_MODE_QUOTED
} VersionExtractionMode;

// 服务识别函数
AnalyzerResult analyzeTCPResponse(const char *ip, int port, PortInfo *portInfo);
AnalyzerResult sendServiceProbe(const char *ip, int port, char *response, int responseSize);
AnalyzerResult sendUDPServiceProbe(const char *ip, int port, char *response, int responseSize);
void analyzeServiceBanner(const char *banner, PortInfo *portInfo);
void analyzeServiceBannerAdvanced(const char *banner, int port, PortInfo *portInfo);
void extractVersionSimple(const char *banner, const char *pattern, char *version, size_t version_size);
const ProbeStrategy* findProbeStrategy(int port);

// 高级版本提取函数
int extractVersionInfo(const char *banner, const char *service, const char *pattern,
                      VersionExtractionMode mode, char *version, size_t version_size);
void cleanVersionString(char *version, size_t max_len);

#endif