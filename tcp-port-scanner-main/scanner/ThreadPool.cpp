#include "ThreadPool.h"
#include <iostream>

ThreadPool::ThreadPool(int num_threads) : stop(false), active_tasks(0) {
    for (int i = 0; i < num_threads; i++) {
        workers.emplace_back([this] {
            while (true) {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lock(queue_mutex);
                    condition.wait(lock, [this] {
                        return stop.load() || !tasks.empty();
                    });
                    if (stop.load() && tasks.empty()) return;
                    task = std::move(tasks.front());
                    tasks.pop();
                    active_tasks++;
                }
                task();
                active_tasks--;
                done_condition.notify_all();
            }
        });
    }
    std::cout << "[+] Thread pool created with " << num_threads << " threads\n";
}

ThreadPool::~ThreadPool() {
    stop.store(true);
    condition.notify_all();
    for (std::thread &worker : workers) worker.join();
}

void ThreadPool::enqueue(std::function<void()> task) {
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        tasks.push(task);
    }
    condition.notify_one();
}

void ThreadPool::wait_all() {
    std::unique_lock<std::mutex> lock(done_mutex);
    done_condition.wait(lock, [this] {
        std::unique_lock<std::mutex> qlock(queue_mutex);
        return tasks.empty() && active_tasks.load() == 0;
    });
}