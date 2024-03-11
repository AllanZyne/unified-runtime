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

#include "common.hpp"
#include "device_sanitizer_report.hpp"
#include "ur_sanitizer_layer.hpp"

#include <map>
#include <memory>
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

enum class AllocType : uint32_t {
    DEVICE_USM,
    SHARED_USM,
    HOST_USM,
    MEM_BUFFER,
    DEVICE_GLOBAL
};

struct AllocInfo {
    uptr AllocBegin;
    uptr UserBegin;
    uptr UserEnd;
    size_t AllocSize;
    AllocType Type;
};

enum class DeviceType { UNKNOWN, CPU, GPU_PVC, GPU_DG2 };

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
    DeviceType Type;
    size_t Alignment;
    uptr ShadowOffset;
    uptr ShadowOffsetEnd;

    // Lock InitPool & AllocInfos
    ur_shared_mutex Mutex;
    std::vector<std::shared_ptr<AllocInfo>> AllocInfos;
};

struct QueueInfo {
    ur_mutex Mutex;
    ur_event_handle_t LastEvent;
};

struct KernelInfo {
    ur_shared_mutex Mutex;
    std::unordered_map<int, std::shared_ptr<MemBuffer>> ArgumentsMap;
};

struct ContextInfo {

    std::shared_ptr<DeviceInfo> getDeviceInfo(ur_device_handle_t Device) {
        std::shared_lock<ur_shared_mutex> Guard(Mutex);
        assert(DeviceMap.find(Device) != DeviceMap.end());
        return DeviceMap[Device];
    }

    std::shared_ptr<QueueInfo> getQueueInfo(ur_queue_handle_t Queue) {
        std::shared_lock<ur_shared_mutex> Guard(Mutex);
        assert(QueueMap.find(Queue) != QueueMap.end());
        return QueueMap[Queue];
    }

    std::shared_ptr<KernelInfo> getKernelInfo(ur_kernel_handle_t Kernel) {
        std::shared_lock<ur_shared_mutex> Guard(Mutex);
        assert(KernelMap.find(Kernel) != KernelMap.end());
        return KernelMap[Kernel];
    }

    std::shared_ptr<AllocInfo> getUSMAllocInfo(uptr Address) {
        std::shared_lock<ur_shared_mutex> Guard(Mutex);
        assert(AllocatedUSMMap.find(Address) != AllocatedUSMMap.end());
        return AllocatedUSMMap[Address];
    }

    ur_shared_mutex Mutex;
    std::unordered_map<ur_device_handle_t, std::shared_ptr<DeviceInfo>>
        DeviceMap;
    std::unordered_map<ur_queue_handle_t, std::shared_ptr<QueueInfo>> QueueMap;
    std::unordered_map<ur_kernel_handle_t, std::shared_ptr<KernelInfo>>
        KernelMap;

    /// key: USMAllocInfo.AllocBegin
    /// value: USMAllocInfo
    /// Use AllocBegin as key can help to detect underflow pointer
    std::map<uptr, std::shared_ptr<AllocInfo>> AllocatedUSMMap;
};

struct LaunchInfo {
    uptr LocalShadowOffset;
    uptr LocalShadowOffsetEnd;
    ur_context_handle_t Context;

    DeviceSanitizerReport SPIR_DeviceSanitizerReportMem;

    size_t LocalWorkSize[3];

    LaunchInfo()
        : LocalShadowOffset(0), LocalShadowOffsetEnd(0), Context(nullptr) {}
    ~LaunchInfo();
};

struct DeviceGlobalInfo {
    uptr Size;
    uptr SizeWithRedZone;
    uptr Addr;
};


class SanitizerInterceptor {
  public:
    SanitizerInterceptor();

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
                                ur_queue_handle_t Queue,
                                ur_event_handle_t &Event,
                                LaunchInfo &LaunchInfo, uint32_t numWorkgroup);
    void postLaunchKernel(ur_kernel_handle_t Kernel, ur_queue_handle_t Queue,
                          ur_event_handle_t &Event, LaunchInfo &LaunchInfo);

    ur_result_t insertContext(ur_context_handle_t Context);
    ur_result_t eraseContext(ur_context_handle_t Context);

    ur_result_t insertDevice(ur_context_handle_t Context,
                             ur_device_handle_t Device);

    ur_result_t insertQueue(ur_context_handle_t Context,
                            ur_queue_handle_t Queue);
    ur_result_t eraseQueue(ur_context_handle_t Context,
                           ur_queue_handle_t Queue);
    
    ur_result_t insertMemBuffer(std::shared_ptr<MemBuffer> MemBuffer);

    ur_result_t eraseMemBuffer(ur_mem_handle_t MemHandle);

    std::shared_ptr<MemBuffer> getMemBuffer(ur_mem_handle_t MemHandle);

    std::shared_ptr<KernelInfo> getKernelInfo(ur_kernel_handle_t Kernel);

    std::shared_ptr<ContextInfo> getContextInfo(ur_context_handle_t Context) {
        std::shared_lock<ur_shared_mutex> Guard(m_ContextMapMutex);
        assert(m_ContextMap.find(Context) != m_ContextMap.end());
        return m_ContextMap[Context];
    }

    std::shared_ptr<ContextInfo> getContextInfo(ur_program_handle_t Program);

  private:
    ur_result_t updateShadowMemory(ur_queue_handle_t Queue);
    ur_result_t enqueueAllocInfo(ur_context_handle_t Context,
                                 ur_device_handle_t Device,
                                 ur_queue_handle_t Queue,
                                 std::shared_ptr<AllocInfo> &AI,
                                 ur_event_handle_t &LastEvent);

    /// Initialize Global Variables & Kernel Name at first Launch
    ur_result_t prepareLaunch(ur_queue_handle_t Queue,
                              ur_kernel_handle_t Kernel, LaunchInfo &LaunchInfo,
                              uint32_t numWorkgroup);

    ur_result_t allocShadowMemory(ur_context_handle_t Context,
                                  std::shared_ptr<DeviceInfo> &DeviceInfo);
    ur_result_t enqueueMemSetShadow(ur_context_handle_t Context,
                                    ur_device_handle_t Device,
                                    ur_queue_handle_t Queue, uptr Addr,
                                    uptr Size, u8 Value,
                                    ur_event_handle_t DepEvent,
                                    ur_event_handle_t *OutEvent);

  private:
    std::unordered_map<ur_context_handle_t, std::shared_ptr<ContextInfo>>
        m_ContextMap;
    ur_shared_mutex m_ContextMapMutex;
    std::unordered_map<ur_mem_handle_t, std::shared_ptr<MemBuffer>>
        m_MemBufferMap;
    ur_shared_mutex m_MemBufferMapMutex;
    bool m_IsInASanContext;
    bool m_ShadowMemInited;
};

inline const char *ToString(AllocType Type) {
    switch (Type) {
    case AllocType::DEVICE_USM:
        return "Device USM";
    case AllocType::HOST_USM:
        return "Host USM";
    case AllocType::SHARED_USM:
        return "Shared USM";
    case AllocType::MEM_BUFFER:
        return "Memory Buffer";
    case AllocType::DEVICE_GLOBAL:
        return "Device Global";
    default:
        return "Unknown Type";
    }
}

inline ur_device_handle_t getDevice(ur_queue_handle_t Queue) {
    ur_device_handle_t Device;
    [[maybe_unused]] auto Result = context.urDdiTable.Queue.pfnGetInfo(
        Queue, UR_QUEUE_INFO_DEVICE, sizeof(ur_device_handle_t), &Device,
        nullptr);
    assert(Result == UR_RESULT_SUCCESS);
    return Device;
}

inline ur_context_handle_t getContext(ur_queue_handle_t Queue) {
    ur_context_handle_t Context;
    [[maybe_unused]] auto Result = context.urDdiTable.Queue.pfnGetInfo(
        Queue, UR_QUEUE_INFO_CONTEXT, sizeof(ur_context_handle_t), &Context,
        nullptr);
    assert(Result == UR_RESULT_SUCCESS);
    return Context;
}

} // namespace ur_sanitizer_layer
