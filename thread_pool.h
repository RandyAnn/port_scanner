#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <winsock2.h>
#include <windows.h>
#include "scanner_utils.h"

#define MAX_THREADS 16
#define MAX_QUEUE_SIZE 10000

typedef struct {
    int port;
    char ip[16];
    int timeout;
    int scanType;
    void *config;
    PortInfo *result;
} ScanTask;

typedef struct {
    HANDLE threads[MAX_THREADS];
    HANDLE mutex;
    HANDLE semaphore;
    HANDLE stopEvent;
    ScanTask *taskQueue;
    int queueSize;
    int front;
    int rear;
    int threadCount;
    BOOL isRunning;
} ThreadPool;

ThreadPool* createThreadPool(int threadCount);
void destroyThreadPool(ThreadPool* pool);
BOOL addTask(ThreadPool* pool, ScanTask task);
void waitForCompletion(ThreadPool* pool);

#endif 