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

// 重试配置结构体
typedef struct {
    int max_retries;
    int base_timeout_ms;
    float timeout_multiplier;
    int max_timeout_ms;
    int retry_delay_ms;
} RetryConfig;

// 高级版本提取函数
int extractVersionInfo(const char *banner, const char *service, const char *pattern,
                      VersionExtractionMode mode, char *version, size_t version_size);
void cleanVersionString(char *version, size_t max_len);

// 性能统计结构体
typedef struct {
    int cache_hits;
    int cache_misses;
    int connections_reused;
    int connections_created;
    int buffers_reused;
    int buffers_allocated;
} PerformanceStats;

// 重试和超时机制函数
AnalyzerResult performProbeWithRetry(const char *ip, int port, const char *service,
                                    char *response, int responseSize);
AnalyzerResult sendServiceProbeWithTimeout(const char *ip, int port, char *response,
                                          int responseSize, int timeout_ms);
const RetryConfig* getRetryConfigForService(const char* service);
int calculateAdaptiveTimeout(const RetryConfig* config, int retry_attempt);
int waitForSocketReady(SOCKET sock, int timeout_ms, BOOL wait_for_write);
void updateNetworkCondition(BOOL success, int response_time_ms);

// 性能优化和资源管理函数
BOOL initializeResourcePool();
void cleanupResourcePool();
SOCKET getConnectionFromPool(const char* ip, int port);
void returnConnectionToPool(SOCKET sock, const char* ip, int port);
char* getBufferFromPool(size_t required_size);
void returnBufferToPool(char* buffer);
BOOL findCacheEntry(const char* ip, int port, PortInfo* portInfo);
void addCacheEntry(const char* ip, int port, const PortInfo* portInfo);
void cleanupExpiredCache();
void getPerformanceStats(PerformanceStats* stats);
void resetPerformanceStats();

#endif