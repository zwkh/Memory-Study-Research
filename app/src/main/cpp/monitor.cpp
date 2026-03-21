#include "monitor.h"
#include <mutex>
#include <android/log.h>
#include <sys/mman.h>

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "struct_monitor", __VA_ARGS__)

MonitorManager& MonitorManager::GetInstance() {
    static MonitorManager instance;
    return instance;
}

// 注册监控对象
void MonitorManager::AddMonitorBlock(const MonitorBlock& block) {
    std::lock_guard<std::mutex> lock(mutex_);
    monitor_map_[block.address] = block;
}

// 获取监控对象
bool MonitorManager::GetMonitorBlock(uintptr_t addr, MonitorBlock& out_block) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = monitor_map_.find(addr);
    if (it != monitor_map_.end()) {
        out_block = it->second;
        return true;
    }
    return false;
}

// 删除监控对象
void MonitorManager::RemoveMonitorBlock(uintptr_t addr) {
    std::lock_guard<std::mutex> lock(mutex_);
    monitor_map_.erase(addr);
}

// 更新成员冷热状态
void MonitorManager::UpdateMemberHot(uintptr_t addr, uint32_t offset) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = monitor_map_.find(addr);
    if (it == monitor_map_.end()) return;
    for (auto& member : it->second.struct_meta.members) {
        if (offset >= member.start_offset && offset <= member.end_offset) {
            if (!member.is_hot) {
                member.is_hot = true;
                LOG("结构体监控：发现热点成员！结构体: %s, 成员: %s, 触发偏移: %u",
                    it->second.struct_meta.struct_name.c_str(),
                    member.member_name.c_str(),
                    offset);
            }
            break;
        }
    }
}

// 【改进】更新对应归属逻辑的访问次数
void MonitorManager::UpdateLogicAccess(uintptr_t addr, LogicID logic_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = monitor_map_.find(addr);
    if (it == monitor_map_.end()) return;
    it->second.logic_access_counts[logic_id]++;

    int current_count = it->second.logic_access_counts[logic_id];
    LOG("共享页监控：内存块 %p 被 LogicID(%d) 访问！该逻辑累计访问次数: %d",
        (void*)addr, (int)logic_id, current_count);
}

// 重新锁住内存块
void MonitorManager::ReprotectAllBlocks() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& pair : monitor_map_) {
        if (pair.second.is_monitored) {
            mprotect((void*)pair.second.address, pair.second.size, PROT_NONE);
        }
    }
}

void PendingMonitor::Pending(const StructMeta& meta){
    std::lock_guard lg(mux_);
    struct_meta_.push_back(meta);
}

PendingMonitor &PendingMonitor::GetInstance() {
    static PendingMonitor monitor;
    return monitor;
}

std::vector<StructMeta> PendingMonitor::GetStructMetas() {
    return struct_meta_;
}

extern "C" __attribute__((visibility("default")))
void RegisterMonitorStruct(const StructMeta* meta) {
    if (meta) {
        PendingMonitor::GetInstance().Pending(*meta);
        LOG("Hook层成功接收到业务层的结构体注册: %s", meta->struct_name.c_str());
    }
}