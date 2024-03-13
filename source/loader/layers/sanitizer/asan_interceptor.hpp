/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Part of the Unified-Runtime Project, under the Apache License v2.0 with LLVM Exceptions.
 * See LICENSE.TXT
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 * @file asan_interceptor.hpp
 *
 */

#pragma once

#include "asan_allocator.hpp"
#include "common.hpp"
#include "device_sanitizer_report.hpp"
#include "ur_sanitizer_layer.hpp"

#include <memory>
#include <optional>
#include <queue>
#include <unordered_map>
#include <vector>

namespace ur_sanitizer_layer {

struct ReferenceCounter {
    ReferenceCounter() : RefCount{1} {}

    // Reset the counter to the initial value.
    void reset() { RefCount = 1; }

    // Used when retaining an object.
    void increment() { RefCount++; }

    // Supposed to be used in ur*GetInfo* methods where ref count value is
    // requested.
    uint32_t load() { return RefCount.load(); }

    // This method allows to guard a code which needs to be executed when object's
    // ref count becomes zero after release. It is important to notice that only a
    // single thread can pass through this check. This is true because of several
    // reasons:
    //   1. Decrement operation is executed atomically.
    //   2. It is not allowed to retain an object after its refcount reaches zero.
    //   3. It is not allowed to release an object more times than the value of
    //   the ref count.
    // 2. and 3. basically means that we can't use an object at all as soon as its
    // refcount reaches zero. Using this check guarantees that code for deleting
    // an object and releasing its resources is executed once by a single thread
    // and we don't need to use any mutexes to guard access to this object in the
    // scope after this check. Of course if we access another objects in this code
    // (not the one which is being deleted) then access to these objects must be
    // guarded, for example with a mutex.
    bool decrementAndTest() { return --RefCount == 0; }

  private:
    std::atomic<uint32_t> RefCount;
};

class Quarantine;

struct AllocInfoList {
    std::vector<std::shared_ptr<AllocInfo>> List;
    ur_shared_mutex Mutex;
};

struct MemBuffer {
    // Buffer constructor
    MemBuffer(ur_context_handle_t Context, size_t Size, char *HostPtr)
        : Context(Context), Size(Size), HostPtr(HostPtr) {}

    // Sub-buffer constructor
    MemBuffer(std::shared_ptr<MemBuffer> Parent, size_t Origin, size_t Size)
        : Context(Parent->Context), Size(Size), SubBuffer{{Parent, Origin}} {}

    ur_result_t getHandle(ur_device_handle_t Device, char *&Handle);

    ur_result_t free();

    size_t getAlignment();

    std::unordered_map<ur_device_handle_t, char *> Allocations;

    enum AccessMode { UNKNOWN, READ_WRITE, READ_ONLY, WRITE_ONLY };

    struct Mapping {
        size_t Offset;
        size_t Size;
    };

    std::unordered_map<void *, Mapping> Mappings;

    ur_context_handle_t Context;
    size_t Size;
    char *HostPtr{nullptr};

    struct SubBuffer_t {
        std::shared_ptr<MemBuffer> Parent;
        size_t Origin;
    };

    std::optional<SubBuffer_t> SubBuffer;
    ReferenceCounter RefCount;
    ur_shared_mutex Mutex;
};

struct DeviceInfo {
    ur_device_handle_t Handle;

    DeviceType Type = DeviceType::UNKNOWN;
    size_t Alignment = 0;
    uptr ShadowOffset = 0;
    uptr ShadowOffsetEnd = 0;

    ur_mutex Mutex;
    std::queue<std::shared_ptr<AllocInfo>> Quarantine;
    size_t QuarantineSize = 0;

    explicit DeviceInfo(ur_device_handle_t Device) : Handle(Device) {
        [[maybe_unused]] auto Result =
            context.urDdiTable.Device.pfnRetain(Device);
        assert(Result == UR_RESULT_SUCCESS);
    }

    ~DeviceInfo() {
        [[maybe_unused]] auto Result =
            context.urDdiTable.Device.pfnRelease(Handle);
        assert(Result == UR_RESULT_SUCCESS);
    }

    ur_result_t allocShadowMemory(ur_context_handle_t Context);
};

struct QueueInfo {
    ur_queue_handle_t Handle;
    ur_mutex Mutex;
    ur_event_handle_t LastEvent;

    explicit QueueInfo(ur_queue_handle_t Queue)
        : Handle(Queue), LastEvent(nullptr) {
        [[maybe_unused]] auto Result =
            context.urDdiTable.Queue.pfnRetain(Queue);
        assert(Result == UR_RESULT_SUCCESS);
    }

    ~QueueInfo() {
        [[maybe_unused]] auto Result =
            context.urDdiTable.Queue.pfnRelease(Handle);
        assert(Result == UR_RESULT_SUCCESS);
    }
};

struct KernelInfo {
    ur_kernel_handle_t Handle;
    ur_shared_mutex Mutex;
    std::unordered_map<int, std::shared_ptr<MemBuffer>> ArgumentsMap;
};

struct ContextInfo {
    ur_context_handle_t Handle;

    std::vector<ur_device_handle_t> DeviceList;
    std::unordered_map<ur_device_handle_t, AllocInfoList> AllocInfosMap;

    explicit ContextInfo(ur_context_handle_t Context) : Handle(Context) {
        [[maybe_unused]] auto Result =
            context.urDdiTable.Context.pfnRetain(Context);
        assert(Result == UR_RESULT_SUCCESS);
    }

    ~ContextInfo() {
        [[maybe_unused]] auto Result =
            context.urDdiTable.Context.pfnRelease(Handle);
        assert(Result == UR_RESULT_SUCCESS);
    }

    void insertAllocInfo(const std::vector<ur_device_handle_t> &Devices,
                         std::shared_ptr<AllocInfo> &AI) {
        for (auto Device : Devices) {
            auto &AllocInfos = AllocInfosMap[Device];
            std::scoped_lock<ur_shared_mutex> Guard(AllocInfos.Mutex);
            AllocInfos.List.emplace_back(AI);
        }
    }
};

struct LaunchInfo {
    uptr LocalShadowOffset = 0;
    uptr LocalShadowOffsetEnd = 0;
    DeviceSanitizerReport SPIR_DeviceSanitizerReportMem;

    ur_context_handle_t Context = nullptr;
    size_t LocalWorkSize[3] = {0};

    explicit LaunchInfo(ur_context_handle_t Context);
    ~LaunchInfo();
};

struct DeviceGlobalInfo {
    uptr Size;
    uptr SizeWithRedZone;
    uptr Addr;
};

class SanitizerInterceptor {
  public:
    explicit SanitizerInterceptor();

    ~SanitizerInterceptor();

    ur_result_t allocateMemory(ur_context_handle_t Context,
                               ur_device_handle_t Device,
                               const ur_usm_desc_t *Properties,
                               ur_usm_pool_handle_t Pool, size_t Size,
                               void **ResultPtr, AllocType Type);
    ur_result_t releaseMemory(ur_context_handle_t Context, void *Ptr);

    ur_result_t registerDeviceGlobals(ur_context_handle_t Context,
                                      ur_program_handle_t Program);

    ur_result_t preLaunchKernel(ur_kernel_handle_t Kernel,
                                ur_queue_handle_t Queue, LaunchInfo &LaunchInfo,
                                uint32_t numWorkgroup);
    void postLaunchKernel(ur_kernel_handle_t Kernel, ur_queue_handle_t Queue,
                          ur_event_handle_t &Event, LaunchInfo &LaunchInfo);

    ur_result_t insertContext(ur_context_handle_t Context,
                              std::shared_ptr<ContextInfo> &CI);
    ur_result_t eraseContext(ur_context_handle_t Context);

    ur_result_t insertDevice(ur_device_handle_t Device,
                             std::shared_ptr<DeviceInfo> &CI);
    ur_result_t eraseDevice(ur_device_handle_t Device);

    ur_result_t insertKernel(ur_kernel_handle_t Kernel);

    ur_result_t insertMemBuffer(std::shared_ptr<MemBuffer> MemBuffer);

    ur_result_t eraseMemBuffer(ur_mem_handle_t MemHandle);

    std::shared_ptr<MemBuffer> getMemBuffer(ur_mem_handle_t MemHandle);

    std::shared_ptr<KernelInfo> getKernelInfo(ur_kernel_handle_t Kernel) {
        std::shared_lock<ur_shared_mutex> Guard(m_KernelMapMutex);
        assert(m_KernelMap.find(Kernel) != m_KernelMap.end());
        return m_KernelMap[Kernel];
    }

    std::optional<AllocationIterator> findAllocInfoByAddress(uptr Address);

  private:
    ur_result_t updateShadowMemory(std::shared_ptr<ContextInfo> &ContextInfo,
                                   std::shared_ptr<DeviceInfo> &DeviceInfo,
                                   ur_queue_handle_t Queue);
    ur_result_t enqueueAllocInfo(ur_context_handle_t Context,
                                 std::shared_ptr<DeviceInfo> &DeviceInfo,
                                 ur_queue_handle_t Queue,
                                 std::shared_ptr<AllocInfo> &AI);

    /// Initialize Global Variables & Kernel Name at first Launch
    ur_result_t prepareLaunch(ur_context_handle_t Context,
                              std::shared_ptr<DeviceInfo> &DeviceInfo,
                              ur_queue_handle_t Queue,
                              ur_kernel_handle_t Kernel, LaunchInfo &LaunchInfo,
                              uint32_t numWorkgroup);

    ur_result_t allocShadowMemory(ur_context_handle_t Context,
                                  std::shared_ptr<DeviceInfo> &DeviceInfo);
    ur_result_t enqueueMemSetShadow(ur_context_handle_t Context,
                                    std::shared_ptr<DeviceInfo> &DeviceInfo,
                                    ur_queue_handle_t Queue, uptr Addr,
                                    uptr Size, u8 Value);

    std::shared_ptr<ContextInfo> getContextInfo(ur_context_handle_t Context) {
        std::shared_lock<ur_shared_mutex> Guard(m_ContextMapMutex);
        assert(m_ContextMap.find(Context) != m_ContextMap.end());
        return m_ContextMap[Context];
    }

    std::shared_ptr<DeviceInfo> getDeviceInfo(ur_device_handle_t Device) {
        std::shared_lock<ur_shared_mutex> Guard(m_DeviceMapMutex);
        assert(m_DeviceMap.find(Device) != m_DeviceMap.end());
        return m_DeviceMap[Device];
    }

  private:
    std::unordered_map<ur_context_handle_t, std::shared_ptr<ContextInfo>>
        m_ContextMap;
    ur_shared_mutex m_ContextMapMutex;
    std::unordered_map<ur_device_handle_t, std::shared_ptr<DeviceInfo>>
        m_DeviceMap;
    ur_shared_mutex m_DeviceMapMutex;
    std::unordered_map<ur_kernel_handle_t, std::shared_ptr<KernelInfo>>
        m_KernelMap;
    ur_shared_mutex m_KernelMapMutex;
    std::unordered_map<ur_mem_handle_t, std::shared_ptr<MemBuffer>>
        m_MemBufferMap;
    ur_shared_mutex m_MemBufferMapMutex;

    /// Assumption: all usm chunks are allocated in one VA
    AllocationMap m_AllocationMap;
    ur_shared_mutex m_AllocationMapMutex;

    uint64_t cl_Debug = 0;
    uint32_t cl_MaxQuarantineSizeMB = 0;

    std::unique_ptr<Quarantine> m_Quarantine;
};

} // namespace ur_sanitizer_layer
