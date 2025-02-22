#include <stdio.h>
#include <stdlib.h>
#include "scan_engine.h"
#include "thread_pool.h"

static DWORD WINAPI workerThread(LPVOID param);
static BOOL getTask(ThreadPool* pool, ScanTask* task);

ThreadPool* createThreadPool(int threadCount) {
    ThreadPool* pool = (ThreadPool*)malloc(sizeof(ThreadPool));
    if (!pool) return NULL;

    pool->taskQueue = (ScanTask*)malloc(sizeof(ScanTask) * MAX_QUEUE_SIZE);
    if (!pool->taskQueue) {
        free(pool);
        return NULL;
    }

    pool->mutex = CreateMutex(NULL, FALSE, NULL);
    pool->semaphore = CreateSemaphore(NULL, 0, MAX_QUEUE_SIZE, NULL);
    pool->stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    pool->queueSize = 0;
    pool->front = 0;
    pool->rear = 0;
    pool->isRunning = TRUE;
    pool->threadCount = threadCount;

    for (int i = 0; i < threadCount; i++) {
        pool->threads[i] = CreateThread(NULL, 0, workerThread, pool, 0, NULL);
    }

    return pool;
}

void destroyThreadPool(ThreadPool* pool) {
    if (!pool) return;

    pool->isRunning = FALSE;
    SetEvent(pool->stopEvent);

    // 等待所有线程结束
    WaitForMultipleObjects(pool->threadCount, pool->threads, TRUE, INFINITE);

    for (int i = 0; i < pool->threadCount; i++) {
        CloseHandle(pool->threads[i]);
    }

    CloseHandle(pool->mutex);
    CloseHandle(pool->semaphore);
    CloseHandle(pool->stopEvent);
    free(pool->taskQueue);
    free(pool);
}

BOOL addTask(ThreadPool* pool, ScanTask task) {
    WaitForSingleObject(pool->mutex, INFINITE);

    if (pool->queueSize >= MAX_QUEUE_SIZE) {
        ReleaseMutex(pool->mutex);
        return FALSE;
    }

    pool->taskQueue[pool->rear] = task;
    pool->rear = (pool->rear + 1) % MAX_QUEUE_SIZE;
    pool->queueSize++;

    ReleaseMutex(pool->mutex);
    ReleaseSemaphore(pool->semaphore, 1, NULL);
    return TRUE;
}

static BOOL getTask(ThreadPool* pool, ScanTask* task) {
    HANDLE handles[] = {pool->semaphore, pool->stopEvent};
    DWORD result = WaitForMultipleObjects(2, handles, FALSE, INFINITE);

    if (result == WAIT_OBJECT_0 + 1) return FALSE;  // 停止事件被触发

    WaitForSingleObject(pool->mutex, INFINITE);
    *task = pool->taskQueue[pool->front];
    pool->front = (pool->front + 1) % MAX_QUEUE_SIZE;
    pool->queueSize--;
    ReleaseMutex(pool->mutex);

    return TRUE;
}

static DWORD WINAPI workerThread(LPVOID param) {
    ThreadPool* pool = (ThreadPool*)param;
    ScanTask task;

    while (pool->isRunning) {
        if (!getTask(pool, &task)) break;

        // 执行扫描任务
        int status;
        if (task.scanType == SCAN_TYPE_TCP) {
            status = performTCPScan(task.ip, task.port, task.timeout);
        } else if (task.scanType == SCAN_TYPE_UDP) {
            status = performUDPScan(task.ip, task.port, task.timeout);
        }

        // 处理扫描结果
        handleScanResult(status, task.port, ((ScanConfig*)task.config)->verbose);
        
        // 保存扫描结果
        if (task.result) {
            sprintf(task.result->status, "%d", status);
            // 如果需要，这里可以添加服务识别等其他信息
        }
    }

    return 0;
}

void waitForCompletion(ThreadPool* pool) {
    while (1) {
        WaitForSingleObject(pool->mutex, INFINITE);
        if (pool->queueSize == 0) {
            ReleaseMutex(pool->mutex);
            break;
        }
        ReleaseMutex(pool->mutex);
        Sleep(100);
    }
} 