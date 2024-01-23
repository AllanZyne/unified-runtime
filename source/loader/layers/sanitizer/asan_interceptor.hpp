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

#include <map>
#include <memory>
#include <vector>

namespace ur_sanitizer_layer {

enum class AllocType {
    DEVICE_USM,
    SHARED_USM,
    HOST_USM,
    MEM_BUFFER,
    DEVICE_GLOBAL
};

enum class DeviceType : uint32_t { UNKNOWN, CPU, GPU_PVC, GPU_DG2 };

struct AllocInfo {
    uptr AllocBegin;
    uptr UserBegin;
    uptr UserEnd;
    size_t AllocSize;
    AllocType Type;
};

struct MemBuffer {
    ur_mem_handle_t Buffer;
    size_t Size;
    size_t SizeWithRZ;

    AllocInfo getAllocInfo(ur_device_handle_t Device);
};

// struct MemBuffer2 {
//     // urMemBufferCreateWithNativeHandle
//     // void* RawMem;
//     std::unordered_map<DeviceType, void *> RawMem;
//     std::unordered_map<DeviceType, ur_mem_handle_t> Buffer;
//     size_t Size;
//     size_t SizeWithRZ;

//     AllocInfo getAllocInfo(ur_device_handle_t Device);
// };

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
    std::unordered_map<int, std::weak_ptr<MemBuffer>> ArgumentsMap;
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

struct LaunchInfoBase {
    uptr LocalShadowOffset = 0;
    uptr LocalShadowOffsetEnd = 0;
    DeviceSanitizerReport SPIR_DeviceSanitizerReportMem;
};

struct LaunchInfo : LaunchInfoBase {
    ur_context_handle_t Context = nullptr;
    size_t LocalWorkSize[3];

    ~LaunchInfo();
};

class SanitizerInterceptor {
  public:
    SanitizerInterceptor();

    ur_result_t allocateMemory(ur_context_handle_t Context,
                               ur_device_handle_t Device,
                               const ur_usm_desc_t *Properties,
                               ur_usm_pool_handle_t Pool, size_t Size,
                               void **ResultPtr, AllocType Type);
    ur_result_t releaseMemory(ur_context_handle_t Context, void *Ptr);

    ur_result_t
    preLaunchKernel(ur_kernel_handle_t Kernel, ur_queue_handle_t Queue,
                    ur_event_handle_t &Event,
                    std::unique_ptr<LaunchInfo, UrUSMFree> &LaunchInfo,
                    uint32_t numWorkgroup);
    void postLaunchKernel(ur_kernel_handle_t Kernel, ur_queue_handle_t Queue,
                          ur_event_handle_t &Event,
                          std::unique_ptr<LaunchInfo, UrUSMFree> &LaunchInfo);

    ur_result_t insertContext(ur_context_handle_t Context);
    ur_result_t eraseContext(ur_context_handle_t Context);

    ur_result_t insertDevice(ur_context_handle_t Context,
                             ur_device_handle_t Device);

    ur_result_t insertQueue(ur_context_handle_t Context,
                            ur_queue_handle_t Queue);
    ur_result_t eraseQueue(ur_context_handle_t Context,
                           ur_queue_handle_t Queue);

    void insertMemBuffer(std::shared_ptr<MemBuffer> MemBuffer) {
        std::scoped_lock<ur_shared_mutex> Guard(m_MemBufferMapMutex);
        assert(m_MemBufferMap.find(MemBuffer->Buffer) == m_MemBufferMap.end());
        m_MemBufferMap.emplace(
            reinterpret_cast<ur_mem_handle_t>(MemBuffer.get()), MemBuffer);
    }

    void eraseMemBuffer(ur_mem_handle_t MemHandle) {
        std::scoped_lock<ur_shared_mutex> Guard(m_MemBufferMapMutex);
        assert(m_MemBufferMap.find(MemHandle) != m_MemBufferMap.end());
        m_MemBufferMap.erase(MemHandle);
    }

    std::shared_ptr<MemBuffer> getMemBuffer(ur_mem_handle_t MemHandle) {
        std::shared_lock<ur_shared_mutex> Guard(m_MemBufferMapMutex);
        if (m_MemBufferMap.count(MemHandle)) {
            return m_MemBufferMap.at(MemHandle);
        }
        return nullptr;
    }

    ur_mem_handle_t getMemHandle(ur_mem_handle_t MemHandle) {
        std::shared_lock<ur_shared_mutex> Guard(m_MemBufferMapMutex);
        if (m_MemBufferMap.count(MemHandle)) {
            return m_MemBufferMap.at(MemHandle).get()->Buffer;
        }
        return MemHandle;
    }

    std::shared_ptr<ContextInfo> getContextInfo(ur_context_handle_t Context) {
        std::shared_lock<ur_shared_mutex> Guard(m_ContextMapMutex);
        assert(m_ContextMap.find(Context) != m_ContextMap.end());
        return m_ContextMap[Context];
    }

  private:
    ur_result_t updateShadowMemory(ur_kernel_handle_t Kernel,
                                   ur_queue_handle_t Queue);

    /// Initialize Global Variables & Kernel Name at first Launch
    ur_result_t
    prepareLaunch(ur_queue_handle_t Queue, ur_kernel_handle_t Kernel,
                  std::unique_ptr<LaunchInfo, UrUSMFree> &LaunchInfo,
                  uint32_t numWorkgroup);

    ur_result_t allocShadowMemory(ur_context_handle_t Context,
                                  std::shared_ptr<DeviceInfo> &DeviceInfo);

  private:
    std::unordered_map<ur_context_handle_t, std::shared_ptr<ContextInfo>>
        m_ContextMap;
    ur_shared_mutex m_ContextMapMutex;

    std::unordered_map<ur_mem_handle_t, std::shared_ptr<MemBuffer>>
        m_MemBufferMap;
    ur_shared_mutex m_MemBufferMapMutex;

    bool m_IsInASanContext;
};

} // namespace ur_sanitizer_layer
