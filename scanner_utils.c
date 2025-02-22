#define _WIN32_WINNT 0x0600
#include <stdio.h>
#include <string.h>
#include <ws2tcpip.h> 
#include "scanner_utils.h"
#include "scan_engine.h"
#include "port_analyzer.h"
#include "thread_pool.h"

void initScanConfig(ScanConfig *config) {
    memset(config, 0, sizeof(ScanConfig));
    config->startPort = 1;
    config->endPort = 1024;  // 默认扫描前1024个端口
    config->timeout = DEFAULT_TIMEOUT;
    config->scanMode = DEFAULT_SCAN_MODE;
    config->verbose = FALSE;
    config->analyzeServices = FALSE;
    config->threadCount = 8;  // 默认使用8个线程
}

BOOL parseCommandLine(int argc, char *argv[], ScanConfig *config) {
    if (!isValidIPAddress(argv[1])) {
        printf("错误: 无效的IP地址\n");
        return FALSE;
    }
    strncpy(config->targetIP, argv[1], MAX_IP_LENGTH - 1);

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            char *port_str = argv[++i];
            char *hyphen = strchr(port_str, '-');
            
            if (hyphen) {
                // 端口范围形式: 起始端口-结束端口
                sscanf(port_str, "%d-%d", &config->startPort, &config->endPort);
            } else {
                // 单个端口形式
                int port = atoi(port_str);
                config->startPort = port;
                config->endPort = port;
            }
            
            if (!isPortInRange(config->startPort) || !isPortInRange(config->endPort)) {
                printf("错误: 端口范围无效\n");
                return FALSE;
            }
        }
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            config->timeout = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            config->scanMode = atoi(argv[++i]);
            if (config->scanMode < 1 || config->scanMode > 3) {
                printf("错误: 无效的扫描模式\n");
                return FALSE;
            }
        }
        else if (strcmp(argv[i], "-v") == 0) {
            config->verbose = TRUE;
        }
        else if (strcmp(argv[i], "-a") == 0) {
            config->analyzeServices = TRUE;
        }
        else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            config->threadCount = atoi(argv[++i]);
            if (config->threadCount < 1 || config->threadCount > MAX_THREADS) {
                printf("错误: 线程数必须在1-%d之间\n", MAX_THREADS);
                return FALSE;
            }
        }
    }
    return TRUE;
}

BOOL isValidIPAddress(const char *ipAddress) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ipAddress, &(sa.sin_addr)) == 1;
}

BOOL isPortInRange(int port) {
    return port >= 1 && port <= 65535;
}

void printProgress(int current, int total) {
    float percentage = (float)current / total * 100;
    printf("\r扫描进度: [%3.1f%%] ", percentage);
    fflush(stdout);
}

void saveResults(const char *filename, PortInfo *results, int count) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        printf("无法创建报告文件\n");
        return;
    }

    fprintf(fp, "端口扫描报告\n");
    fprintf(fp, "=====================================\n\n");
    
    for (int i = 0; i < count; i++) {
        // 将状态码转换为对应的字符串
        const char* status_str;
        switch(atoi(results[i].status)) {  // 将字符串转换为数字进行比较
            case PORT_STATUS_OPEN:
                status_str = "开放";
                break;
            case PORT_STATUS_CLOSED:
                status_str = "关闭";
                break;
            case PORT_STATUS_FILTERED:
                status_str = "被过滤";
                break;
            case PORT_STATUS_ERROR:
                status_str = "错误";
                break;
            default:
                status_str = "未知";
                break;
        }

        fprintf(fp, "端口: %d\n", results[i].port);
        fprintf(fp, "服务: %s\n", results[i].service);
        fprintf(fp, "版本: %s\n", results[i].version);
        fprintf(fp, "状态: %s\n", status_str);
        fprintf(fp, "安全性: %s\n\n", results[i].isVulnerable ? "可能存在漏洞" : "未发现明显漏洞");
    }

    fclose(fp);
}

int startScan(ScanConfig* config) {
    printf("开始扫描目标 %s...\n", config->targetIP);
    
    // 如果是ICMP ping测试，只需要测试一次
    if (config->scanMode == SCAN_TYPE_ICMP) {
        int status = performScan(config, -1);
        handleScanResult(status, -1, config->verbose);
        return 0;
    }
    
    // 创建线程池
    ThreadPool* pool = createThreadPool(config->threadCount);
    if (!pool) {
        printf("创建线程池失败\n");
        return -1;
    }

    printf("扫描端口范围 %d-%d\n", config->startPort, config->endPort);
    int totalPorts = config->endPort - config->startPort + 1;
    PortInfo* results = (PortInfo*)calloc(totalPorts, sizeof(PortInfo));  // 使用 calloc 初始化为0
    
    if (!results) {
        printf("内存分配失败\n");
        destroyThreadPool(pool);
        return -1;
    }

    // 添加扫描任务到线程池
    for (int port = config->startPort; port <= config->endPort; port++) {
        int index = port - config->startPort;
        results[index].port = port;  // 预设端口号
        
        ScanTask task = {
            .port = port,
            .timeout = config->timeout,
            .scanType = config->scanMode,
            .config = config,
            .result = &results[index]  // 指向对应的结果结构
        };
        strncpy(task.ip, config->targetIP, sizeof(task.ip) - 1);
        
        while (!addTask(pool, task)) {
            Sleep(10);
        }
    }

    // 等待所有任务完成
    waitForCompletion(pool);
    destroyThreadPool(pool);
    
    printf("\n扫描完成!\n");
    
    // 保存结果到文件
    if (totalPorts > 0) {
        saveResults("scan_report.txt", results, totalPorts);
        printf("扫描报告已保存到 scan_report.txt\n");
    }
    
    free(results);
    return 0;
} 