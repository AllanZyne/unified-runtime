/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Part of the Unified-Runtime Project, under the Apache License v2.0 with LLVM Exceptions.
 * See LICENSE.TXT
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 * @file ur_sanddi.cpp
 *
 */

#include "asan_interceptor.hpp"
#include "ur_sanitizer_layer.hpp"
#include "ur_sanitizer_utils.hpp"

namespace ur_sanitizer_layer {

namespace {

ur_result_t setupContext(ur_context_handle_t Context, uint32_t numDevices,
                         const ur_device_handle_t *phDevices) {
    std::shared_ptr<ContextInfo> CI;
    UR_CALL(context.interceptor->insertContext(Context, CI));
    for (uint32_t i = 0; i < numDevices; ++i) {
        auto hDevice = phDevices[i];
        std::shared_ptr<DeviceInfo> DI;
        UR_CALL(context.interceptor->insertDevice(hDevice, DI));
        if (!DI->ShadowOffset) {
            UR_CALL(DI->allocShadowMemory(Context));
        }
        CI->DeviceList.emplace_back(hDevice);
        CI->AllocInfosMap[hDevice];
    }
    return UR_RESULT_SUCCESS;
}

} // namespace

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urUSMHostAlloc
__urdlllocal ur_result_t UR_APICALL urUSMHostAlloc(
    ur_context_handle_t hContext, ///< [in] handle of the context object
    const ur_usm_desc_t
        *pUSMDesc, ///< [in][optional] USM memory allocation descriptor
    ur_usm_pool_handle_t
        pool, ///< [in][optional] Pointer to a pool created using urUSMPoolCreate
    size_t
        size, ///< [in] size in bytes of the USM memory object to be allocated
    void **ppMem ///< [out] pointer to USM host memory object
) {
    auto pfnHostAlloc = context.urDdiTable.USM.pfnHostAlloc;

    if (nullptr == pfnHostAlloc) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urUSMHostAlloc");

    return context.interceptor->allocateMemory(
        hContext, nullptr, pUSMDesc, pool, size, AllocType::HOST_USM, ppMem);
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urUSMDeviceAlloc
__urdlllocal ur_result_t UR_APICALL urUSMDeviceAlloc(
    ur_context_handle_t hContext, ///< [in] handle of the context object
    ur_device_handle_t hDevice,   ///< [in] handle of the device object
    const ur_usm_desc_t
        *pUSMDesc, ///< [in][optional] USM memory allocation descriptor
    ur_usm_pool_handle_t
        pool, ///< [in][optional] Pointer to a pool created using urUSMPoolCreate
    size_t
        size, ///< [in] size in bytes of the USM memory object to be allocated
    void **ppMem ///< [out] pointer to USM device memory object
) {
    auto pfnDeviceAlloc = context.urDdiTable.USM.pfnDeviceAlloc;

    if (nullptr == pfnDeviceAlloc) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urUSMDeviceAlloc");

    return context.interceptor->allocateMemory(
        hContext, hDevice, pUSMDesc, pool, size, AllocType::DEVICE_USM, ppMem);
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urUSMSharedAlloc
__urdlllocal ur_result_t UR_APICALL urUSMSharedAlloc(
    ur_context_handle_t hContext, ///< [in] handle of the context object
    ur_device_handle_t hDevice,   ///< [in] handle of the device object
    const ur_usm_desc_t *
        pUSMDesc, ///< [in][optional] Pointer to USM memory allocation descriptor.
    ur_usm_pool_handle_t
        pool, ///< [in][optional] Pointer to a pool created using urUSMPoolCreate
    size_t
        size, ///< [in] size in bytes of the USM memory object to be allocated
    void **ppMem ///< [out] pointer to USM shared memory object
) {
    auto pfnSharedAlloc = context.urDdiTable.USM.pfnSharedAlloc;

    if (nullptr == pfnSharedAlloc) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urUSMSharedAlloc");

    return context.interceptor->allocateMemory(
        hContext, hDevice, pUSMDesc, pool, size, AllocType::SHARED_USM, ppMem);
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urUSMFree
__urdlllocal ur_result_t UR_APICALL urUSMFree(
    ur_context_handle_t hContext, ///< [in] handle of the context object
    void *pMem                    ///< [in] pointer to USM memory object
) {
    auto pfnFree = context.urDdiTable.USM.pfnFree;

    if (nullptr == pfnFree) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urUSMFree");

    return context.interceptor->releaseMemory(hContext, pMem);
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urProgramBuild
__urdlllocal ur_result_t UR_APICALL urProgramBuild(
    ur_context_handle_t hContext, ///< [in] handle of the context object
    ur_program_handle_t hProgram, ///< [in] handle of the program object
    const char *pOptions          ///< [in] string of build options
) {
    auto pfnProgramBuild = context.urDdiTable.Program.pfnBuild;

    if (nullptr == pfnProgramBuild) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urProgramBuild");

    UR_CALL(pfnProgramBuild(hContext, hProgram, pOptions));

    UR_CALL(context.interceptor->registerDeviceGlobals(hContext, hProgram));

    return UR_RESULT_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urProgramBuildExp
__urdlllocal ur_result_t UR_APICALL urProgramBuildExp(
    ur_program_handle_t hProgram, ///< [in] Handle of the program to build.
    uint32_t numDevices,          ///< [in] number of devices
    ur_device_handle_t *
        phDevices, ///< [in][range(0, numDevices)] pointer to array of device handles
    const char *
        pOptions ///< [in][optional] pointer to build options null-terminated string.
) {
    auto pfnBuildExp = context.urDdiTable.ProgramExp.pfnBuildExp;

    if (nullptr == pfnBuildExp) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urProgramBuildExp");

    UR_CALL(pfnBuildExp(hProgram, numDevices, phDevices, pOptions));
    UR_CALL(context.interceptor->registerDeviceGlobals(GetContext(hProgram),
                                                       hProgram));

    return UR_RESULT_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urEnqueueKernelLaunch
__urdlllocal ur_result_t UR_APICALL urEnqueueKernelLaunch(
    ur_queue_handle_t hQueue,   ///< [in] handle of the queue object
    ur_kernel_handle_t hKernel, ///< [in] handle of the kernel object
    uint32_t
        workDim, ///< [in] number of dimensions, from 1 to 3, to specify the global and
                 ///< work-group work-items
    const size_t *
        pGlobalWorkOffset, ///< [in] pointer to an array of workDim unsigned values that specify the
    ///< offset used to calculate the global ID of a work-item
    const size_t *
        pGlobalWorkSize, ///< [in] pointer to an array of workDim unsigned values that specify the
    ///< number of global work-items in workDim that will execute the kernel
    ///< function
    const size_t *
        pLocalWorkSize, ///< [in][optional] pointer to an array of workDim unsigned values that
    ///< specify the number of local work-items forming a work-group that will
    ///< execute the kernel function.
    ///< If nullptr, the runtime implementation will choose the work-group
    ///< size.
    uint32_t numEventsInWaitList, ///< [in] size of the event wait list
    const ur_event_handle_t *
        phEventWaitList, ///< [in][optional][range(0, numEventsInWaitList)] pointer to a list of
    ///< events that must be complete before the kernel execution.
    ///< If nullptr, the numEventsInWaitList must be 0, indicating that no wait
    ///< event.
    ur_event_handle_t *
        phEvent ///< [out][optional] return an event object that identifies this particular
                ///< kernel execution instance.
) {
    auto pfnKernelLaunch = context.urDdiTable.Enqueue.pfnKernelLaunch;

    if (nullptr == pfnKernelLaunch) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urEnqueueKernelLaunch");

    USMLaunchInfo LaunchInfo(GetContext(hQueue), GetDevice(hQueue),
                             pGlobalWorkSize, pLocalWorkSize, pGlobalWorkOffset,
                             workDim);
    UR_CALL(LaunchInfo.initialize());

    UR_CALL(context.interceptor->preLaunchKernel(hKernel, hQueue, LaunchInfo));

    ur_event_handle_t hEvent{};
    ur_result_t result = pfnKernelLaunch(
        hQueue, hKernel, workDim, pGlobalWorkOffset, pGlobalWorkSize,
        pLocalWorkSize, numEventsInWaitList, phEventWaitList, &hEvent);
    context.logger.debug("pfnKernelLaunch: {}", result);

    if (result == UR_RESULT_SUCCESS) {
        UR_CALL(context.interceptor->postLaunchKernel(hKernel, hQueue, hEvent,
                                                      LaunchInfo));
    }

    if (phEvent) {
        *phEvent = hEvent;
    }

    return result;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urContextCreate
__urdlllocal ur_result_t UR_APICALL urContextCreate(
    uint32_t numDevices, ///< [in] the number of devices given in phDevices
    const ur_device_handle_t
        *phDevices, ///< [in][range(0, numDevices)] array of handle of devices.
    const ur_context_properties_t *
        pProperties, ///< [in][optional] pointer to context creation properties.
    ur_context_handle_t
        *phContext ///< [out] pointer to handle of context object created
) {
    auto pfnCreate = context.urDdiTable.Context.pfnCreate;

    if (nullptr == pfnCreate) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urContextCreate");

    ur_result_t result =
        pfnCreate(numDevices, phDevices, pProperties, phContext);

    if (result == UR_RESULT_SUCCESS) {
        UR_CALL(setupContext(*phContext, numDevices, phDevices));
    }

    return result;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urContextCreateWithNativeHandle
__urdlllocal ur_result_t UR_APICALL urContextCreateWithNativeHandle(
    ur_native_handle_t
        hNativeContext,  ///< [in][nocheck] the native handle of the context.
    uint32_t numDevices, ///< [in] number of devices associated with the context
    const ur_device_handle_t *
        phDevices, ///< [in][range(0, numDevices)] list of devices associated with the context
    const ur_context_native_properties_t *
        pProperties, ///< [in][optional] pointer to native context properties struct
    ur_context_handle_t *
        phContext ///< [out] pointer to the handle of the context object created.
) {
    auto pfnCreateWithNativeHandle =
        context.urDdiTable.Context.pfnCreateWithNativeHandle;

    if (nullptr == pfnCreateWithNativeHandle) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urContextCreateWithNativeHandle");

    ur_result_t result = pfnCreateWithNativeHandle(
        hNativeContext, numDevices, phDevices, pProperties, phContext);

    if (result == UR_RESULT_SUCCESS) {
        UR_CALL(setupContext(*phContext, numDevices, phDevices));
    }

    return result;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urContextRelease
__urdlllocal ur_result_t UR_APICALL urContextRelease(
    ur_context_handle_t hContext ///< [in] handle of the context to release.
) {
    auto pfnRelease = context.urDdiTable.Context.pfnRelease;

    if (nullptr == pfnRelease) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urContextRelease");

    UR_CALL(context.interceptor->eraseContext(hContext));
    ur_result_t result = pfnRelease(hContext);

    return result;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urMemBufferCreate
__urdlllocal ur_result_t UR_APICALL urMemBufferCreate(
    ur_context_handle_t hContext, ///< [in] handle of the context object
    ur_mem_flags_t flags, ///< [in] allocation and usage information flags
    size_t size, ///< [in] size in bytes of the memory object to be allocated
    const ur_buffer_properties_t
        *pProperties, ///< [in][optional] pointer to buffer creation properties
    ur_mem_handle_t
        *phBuffer ///< [out] pointer to handle of the memory buffer created
) {
    auto pfnBufferCreate = context.urDdiTable.Mem.pfnBufferCreate;

    if (nullptr == pfnBufferCreate) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    if (nullptr == phBuffer) {
        return UR_RESULT_ERROR_INVALID_NULL_POINTER;
    }

    context.logger.debug("==== urMemBufferCreate");

    void *Host = nullptr;
    if (pProperties) {
        Host = pProperties->pHost;
    }

    char *hostPtrOrNull = (flags & UR_MEM_FLAG_USE_HOST_POINTER)
                              ? ur_cast<char *>(Host)
                              : nullptr;

    std::shared_ptr<MemBuffer> pMemBuffer =
        std::make_shared<MemBuffer>(hContext, size, hostPtrOrNull);
    ur_result_t result = context.interceptor->insertMemBuffer(pMemBuffer);
    *phBuffer = ur_cast<ur_mem_handle_t>(pMemBuffer.get());

    return result;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urMemGetInfo
__urdlllocal ur_result_t UR_APICALL urMemGetInfo(
    ur_mem_handle_t
        hMemory,            ///< [in] handle to the memory object being queried.
    ur_mem_info_t propName, ///< [in] type of the info to retrieve.
    size_t
        propSize, ///< [in] the number of bytes of memory pointed to by pPropValue.
    void *
        pPropValue, ///< [out][optional][typename(propName, propSize)] array of bytes holding
                    ///< the info.
    ///< If propSize is less than the real number of bytes needed to return
    ///< the info then the ::UR_RESULT_ERROR_INVALID_SIZE error is returned and
    ///< pPropValue is not used.
    size_t *
        pPropSizeRet ///< [out][optional] pointer to the actual size in bytes of the queried propName.
) {
    auto pfnGetInfo = context.urDdiTable.Mem.pfnGetInfo;

    if (nullptr == pfnGetInfo) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urMemGetInfo");

    if (auto MemBuffer = context.interceptor->getMemBuffer(hMemory)) {
        UrReturnHelper ReturnValue(propSize, pPropValue, pPropSizeRet);
        switch (propName) {
        case UR_MEM_INFO_CONTEXT: {
            return ReturnValue(MemBuffer->Context);
        }
        case UR_MEM_INFO_SIZE: {
            return ReturnValue(size_t{MemBuffer->Size});
        }
        default: {
            return UR_RESULT_ERROR_UNSUPPORTED_ENUMERATION;
        }
        }
    } else {
        UR_CALL(
            pfnGetInfo(hMemory, propName, propSize, pPropValue, pPropSizeRet));
    }

    return UR_RESULT_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urMemRetain
__urdlllocal ur_result_t UR_APICALL urMemRetain(
    ur_mem_handle_t hMem ///< [in] handle of the memory object to get access
) {
    auto pfnRetain = context.urDdiTable.Mem.pfnRetain;

    if (nullptr == pfnRetain) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urMemRetain");

    if (auto MemBuffer = context.interceptor->getMemBuffer(hMem)) {
        MemBuffer->RefCount++;
    } else {
        UR_CALL(pfnRetain(hMem));
    }

    return UR_RESULT_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urMemRelease
__urdlllocal ur_result_t UR_APICALL urMemRelease(
    ur_mem_handle_t hMem ///< [in] handle of the memory object to release
) {
    auto pfnRelease = context.urDdiTable.Mem.pfnRelease;

    if (nullptr == pfnRelease) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urMemRelease");

    if (auto MemBuffer = context.interceptor->getMemBuffer(hMem)) {
        if (--MemBuffer->RefCount != 0) {
            return UR_RESULT_SUCCESS;
        }
        UR_CALL(MemBuffer->free());
        UR_CALL(context.interceptor->eraseMemBuffer(hMem));
    } else {
        UR_CALL(pfnRelease(hMem));
    }

    return UR_RESULT_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urMemBufferPartition
__urdlllocal ur_result_t UR_APICALL urMemBufferPartition(
    ur_mem_handle_t
        hBuffer,          ///< [in] handle of the buffer object to allocate from
    ur_mem_flags_t flags, ///< [in] allocation and usage information flags
    ur_buffer_create_type_t bufferCreateType, ///< [in] buffer creation type
    const ur_buffer_region_t
        *pRegion, ///< [in] pointer to buffer create region information
    ur_mem_handle_t
        *phMem ///< [out] pointer to the handle of sub buffer created
) {
    auto pfnBufferPartition = context.urDdiTable.Mem.pfnBufferPartition;

    if (nullptr == pfnBufferPartition) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urMemBufferPartition");

    if (auto ParentBuffer = context.interceptor->getMemBuffer(hBuffer)) {
        if (ParentBuffer->Size < (pRegion->origin + pRegion->size)) {
            return UR_RESULT_ERROR_INVALID_BUFFER_SIZE;
        }
        std::shared_ptr<MemBuffer> SubBuffer = std::make_shared<MemBuffer>(
            ParentBuffer, pRegion->origin, pRegion->size);
        UR_CALL(context.interceptor->insertMemBuffer(SubBuffer));
        *phMem = reinterpret_cast<ur_mem_handle_t>(SubBuffer.get());
    } else {
        UR_CALL(pfnBufferPartition(hBuffer, flags, bufferCreateType, pRegion,
                                   phMem));
    }

    return UR_RESULT_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urMemGetNativeHandle
__urdlllocal ur_result_t UR_APICALL urMemGetNativeHandle(
    ur_mem_handle_t hMem, ///< [in] handle of the mem.
    ur_device_handle_t hDevice,
    ur_native_handle_t
        *phNativeMem ///< [out] a pointer to the native handle of the mem.
) {
    auto pfnGetNativeHandle = context.urDdiTable.Mem.pfnGetNativeHandle;

    if (nullptr == pfnGetNativeHandle) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urMemGetNativeHandle");

    if (auto MemBuffer = context.interceptor->getMemBuffer(hMem)) {
        char *Handle = nullptr;
        UR_CALL(MemBuffer->getHandle(hDevice, Handle));
        *phNativeMem = ur_cast<ur_native_handle_t>(Handle);
    } else {
        UR_CALL(pfnGetNativeHandle(hMem, hDevice, phNativeMem));
    }

    return UR_RESULT_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urEnqueueMemBufferRead
__urdlllocal ur_result_t UR_APICALL urEnqueueMemBufferRead(
    ur_queue_handle_t hQueue, ///< [in] handle of the queue object
    ur_mem_handle_t
        hBuffer, ///< [in][bounds(offset, size)] handle of the buffer object
    bool blockingRead, ///< [in] indicates blocking (true), non-blocking (false)
    size_t offset,     ///< [in] offset in bytes in the buffer object
    size_t size,       ///< [in] size in bytes of data being read
    void *pDst, ///< [in] pointer to host memory where data is to be read into
    uint32_t numEventsInWaitList, ///< [in] size of the event wait list
    const ur_event_handle_t *
        phEventWaitList, ///< [in][optional][range(0, numEventsInWaitList)] pointer to a list of
    ///< events that must be complete before this command can be executed.
    ///< If nullptr, the numEventsInWaitList must be 0, indicating that this
    ///< command does not wait on any event to complete.
    ur_event_handle_t *
        phEvent ///< [out][optional] return an event object that identifies this particular
                ///< command instance.
) {
    auto pfnMemBufferRead = context.urDdiTable.Enqueue.pfnMemBufferRead;

    if (nullptr == pfnMemBufferRead) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urEnqueueMemBufferRead");

    if (auto MemBuffer = context.interceptor->getMemBuffer(hBuffer)) {
        ur_device_handle_t Device = GetDevice(hQueue);
        char *pSrc = nullptr;
        UR_CALL(MemBuffer->getHandle(Device, pSrc));
        UR_CALL(context.urDdiTable.Enqueue.pfnUSMMemcpy(
            hQueue, blockingRead, pDst, pSrc + offset, size,
            numEventsInWaitList, phEventWaitList, phEvent));
    } else {
        UR_CALL(pfnMemBufferRead(hQueue, hBuffer, blockingRead, offset, size,
                                 pDst, numEventsInWaitList, phEventWaitList,
                                 phEvent));
    }

    return UR_RESULT_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urEnqueueMemBufferWrite
__urdlllocal ur_result_t UR_APICALL urEnqueueMemBufferWrite(
    ur_queue_handle_t hQueue, ///< [in] handle of the queue object
    ur_mem_handle_t
        hBuffer, ///< [in][bounds(offset, size)] handle of the buffer object
    bool
        blockingWrite, ///< [in] indicates blocking (true), non-blocking (false)
    size_t offset,     ///< [in] offset in bytes in the buffer object
    size_t size,       ///< [in] size in bytes of data being written
    const void
        *pSrc, ///< [in] pointer to host memory where data is to be written from
    uint32_t numEventsInWaitList, ///< [in] size of the event wait list
    const ur_event_handle_t *
        phEventWaitList, ///< [in][optional][range(0, numEventsInWaitList)] pointer to a list of
    ///< events that must be complete before this command can be executed.
    ///< If nullptr, the numEventsInWaitList must be 0, indicating that this
    ///< command does not wait on any event to complete.
    ur_event_handle_t *
        phEvent ///< [out][optional] return an event object that identifies this particular
                ///< command instance.
) {
    auto pfnMemBufferWrite = context.urDdiTable.Enqueue.pfnMemBufferWrite;

    if (nullptr == pfnMemBufferWrite) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urEnqueueMemBufferWrite");

    if (auto MemBuffer = context.interceptor->getMemBuffer(hBuffer)) {
        ur_device_handle_t Device = GetDevice(hQueue);
        char *pDst = nullptr;
        UR_CALL(MemBuffer->getHandle(Device, pDst));
        UR_CALL(context.urDdiTable.Enqueue.pfnUSMMemcpy(
            hQueue, blockingWrite, pDst + offset, pSrc, size,
            numEventsInWaitList, phEventWaitList, phEvent));
    } else {
        UR_CALL(pfnMemBufferWrite(hQueue, hBuffer, blockingWrite, offset, size,
                                  pSrc, numEventsInWaitList, phEventWaitList,
                                  phEvent));
    }

    return UR_RESULT_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urEnqueueMemBufferReadRect
__urdlllocal ur_result_t UR_APICALL urEnqueueMemBufferReadRect(
    ur_queue_handle_t hQueue, ///< [in] handle of the queue object
    ur_mem_handle_t
        hBuffer, ///< [in][bounds(bufferOrigin, region)] handle of the buffer object
    bool blockingRead, ///< [in] indicates blocking (true), non-blocking (false)
    ur_rect_offset_t bufferOrigin, ///< [in] 3D offset in the buffer
    ur_rect_offset_t hostOrigin,   ///< [in] 3D offset in the host region
    ur_rect_region_t
        region, ///< [in] 3D rectangular region descriptor: width, height, depth
    size_t
        bufferRowPitch, ///< [in] length of each row in bytes in the buffer object
    size_t
        bufferSlicePitch, ///< [in] length of each 2D slice in bytes in the buffer object being read
    size_t
        hostRowPitch, ///< [in] length of each row in bytes in the host memory region pointed by
                      ///< dst
    size_t
        hostSlicePitch, ///< [in] length of each 2D slice in bytes in the host memory region
                        ///< pointed by dst
    void *pDst, ///< [in] pointer to host memory where data is to be read into
    uint32_t numEventsInWaitList, ///< [in] size of the event wait list
    const ur_event_handle_t *
        phEventWaitList, ///< [in][optional][range(0, numEventsInWaitList)] pointer to a list of
    ///< events that must be complete before this command can be executed.
    ///< If nullptr, the numEventsInWaitList must be 0, indicating that this
    ///< command does not wait on any event to complete.
    ur_event_handle_t *
        phEvent ///< [out][optional] return an event object that identifies this particular
                ///< command instance.
) {
    auto pfnMemBufferReadRect = context.urDdiTable.Enqueue.pfnMemBufferReadRect;

    if (nullptr == pfnMemBufferReadRect) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urEnqueueMemBufferReadRect");

    if (auto MemBuffer = context.interceptor->getMemBuffer(hBuffer)) {
        char *SrcHandle = nullptr;
        ur_device_handle_t Device = GetDevice(hQueue);
        UR_CALL(MemBuffer->getHandle(Device, SrcHandle));

        UR_CALL(EnqueueMemCopyRectHelper(
            hQueue, SrcHandle, ur_cast<char *>(pDst), bufferOrigin, hostOrigin,
            region, bufferRowPitch, bufferSlicePitch, hostRowPitch,
            hostSlicePitch, blockingRead, numEventsInWaitList, phEventWaitList,
            phEvent));
    } else {
        UR_CALL(pfnMemBufferReadRect(
            hQueue, hBuffer, blockingRead, bufferOrigin, hostOrigin, region,
            bufferRowPitch, bufferSlicePitch, hostRowPitch, hostSlicePitch,
            pDst, numEventsInWaitList, phEventWaitList, phEvent));
    }

    return UR_RESULT_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urEnqueueMemBufferWriteRect
__urdlllocal ur_result_t UR_APICALL urEnqueueMemBufferWriteRect(
    ur_queue_handle_t hQueue, ///< [in] handle of the queue object
    ur_mem_handle_t
        hBuffer, ///< [in][bounds(bufferOrigin, region)] handle of the buffer object
    bool
        blockingWrite, ///< [in] indicates blocking (true), non-blocking (false)
    ur_rect_offset_t bufferOrigin, ///< [in] 3D offset in the buffer
    ur_rect_offset_t hostOrigin,   ///< [in] 3D offset in the host region
    ur_rect_region_t
        region, ///< [in] 3D rectangular region descriptor: width, height, depth
    size_t
        bufferRowPitch, ///< [in] length of each row in bytes in the buffer object
    size_t
        bufferSlicePitch, ///< [in] length of each 2D slice in bytes in the buffer object being
                          ///< written
    size_t
        hostRowPitch, ///< [in] length of each row in bytes in the host memory region pointed by
                      ///< src
    size_t
        hostSlicePitch, ///< [in] length of each 2D slice in bytes in the host memory region
                        ///< pointed by src
    void
        *pSrc, ///< [in] pointer to host memory where data is to be written from
    uint32_t numEventsInWaitList, ///< [in] size of the event wait list
    const ur_event_handle_t *
        phEventWaitList, ///< [in][optional][range(0, numEventsInWaitList)] points to a list of
    ///< events that must be complete before this command can be executed.
    ///< If nullptr, the numEventsInWaitList must be 0, indicating that this
    ///< command does not wait on any event to complete.
    ur_event_handle_t *
        phEvent ///< [out][optional] return an event object that identifies this particular
                ///< command instance.
) {
    auto pfnMemBufferWriteRect =
        context.urDdiTable.Enqueue.pfnMemBufferWriteRect;

    if (nullptr == pfnMemBufferWriteRect) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urEnqueueMemBufferWriteRect");

    if (auto MemBuffer = context.interceptor->getMemBuffer(hBuffer)) {
        char *DstHandle = nullptr;
        ur_device_handle_t Device = GetDevice(hQueue);
        UR_CALL(MemBuffer->getHandle(Device, DstHandle));

        UR_CALL(EnqueueMemCopyRectHelper(
            hQueue, ur_cast<char *>(pSrc), DstHandle, hostOrigin, bufferOrigin,
            region, hostRowPitch, hostSlicePitch, bufferRowPitch,
            bufferSlicePitch, blockingWrite, numEventsInWaitList,
            phEventWaitList, phEvent));
    } else {
        UR_CALL(pfnMemBufferWriteRect(
            hQueue, hBuffer, blockingWrite, bufferOrigin, hostOrigin, region,
            bufferRowPitch, bufferSlicePitch, hostRowPitch, hostSlicePitch,
            pSrc, numEventsInWaitList, phEventWaitList, phEvent));
    }

    return UR_RESULT_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urEnqueueMemBufferCopy
__urdlllocal ur_result_t UR_APICALL urEnqueueMemBufferCopy(
    ur_queue_handle_t hQueue, ///< [in] handle of the queue object
    ur_mem_handle_t
        hBufferSrc, ///< [in][bounds(srcOffset, size)] handle of the src buffer object
    ur_mem_handle_t
        hBufferDst, ///< [in][bounds(dstOffset, size)] handle of the dest buffer object
    size_t srcOffset, ///< [in] offset into hBufferSrc to begin copying from
    size_t dstOffset, ///< [in] offset info hBufferDst to begin copying into
    size_t size,      ///< [in] size in bytes of data being copied
    uint32_t numEventsInWaitList, ///< [in] size of the event wait list
    const ur_event_handle_t *
        phEventWaitList, ///< [in][optional][range(0, numEventsInWaitList)] pointer to a list of
    ///< events that must be complete before this command can be executed.
    ///< If nullptr, the numEventsInWaitList must be 0, indicating that this
    ///< command does not wait on any event to complete.
    ur_event_handle_t *
        phEvent ///< [out][optional] return an event object that identifies this particular
                ///< command instance.
) {
    auto pfnMemBufferCopy = context.urDdiTable.Enqueue.pfnMemBufferCopy;

    if (nullptr == pfnMemBufferCopy) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urEnqueueMemBufferCopy");

    auto SrcBuffer = context.interceptor->getMemBuffer(hBufferSrc);
    auto DstBuffer = context.interceptor->getMemBuffer(hBufferDst);

    UR_ASSERT((SrcBuffer && DstBuffer) || (!SrcBuffer && !DstBuffer),
              UR_RESULT_ERROR_INVALID_MEM_OBJECT);

    if (SrcBuffer && DstBuffer) {
        ur_device_handle_t Device = GetDevice(hQueue);
        char *SrcHandle = nullptr;
        UR_CALL(SrcBuffer->getHandle(Device, SrcHandle));

        char *DstHandle = nullptr;
        UR_CALL(DstBuffer->getHandle(Device, DstHandle));

        UR_CALL(context.urDdiTable.Enqueue.pfnUSMMemcpy(
            hQueue, false, DstHandle + dstOffset, SrcHandle + srcOffset, size,
            numEventsInWaitList, phEventWaitList, phEvent));
    } else {
        UR_CALL(pfnMemBufferCopy(hQueue, hBufferSrc, hBufferDst, srcOffset,
                                 dstOffset, size, numEventsInWaitList,
                                 phEventWaitList, phEvent));
    }

    return UR_RESULT_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urEnqueueMemBufferCopyRect
__urdlllocal ur_result_t UR_APICALL urEnqueueMemBufferCopyRect(
    ur_queue_handle_t hQueue, ///< [in] handle of the queue object
    ur_mem_handle_t
        hBufferSrc, ///< [in][bounds(srcOrigin, region)] handle of the source buffer object
    ur_mem_handle_t
        hBufferDst, ///< [in][bounds(dstOrigin, region)] handle of the dest buffer object
    ur_rect_offset_t srcOrigin, ///< [in] 3D offset in the source buffer
    ur_rect_offset_t dstOrigin, ///< [in] 3D offset in the destination buffer
    ur_rect_region_t
        region, ///< [in] source 3D rectangular region descriptor: width, height, depth
    size_t
        srcRowPitch, ///< [in] length of each row in bytes in the source buffer object
    size_t
        srcSlicePitch, ///< [in] length of each 2D slice in bytes in the source buffer object
    size_t
        dstRowPitch, ///< [in] length of each row in bytes in the destination buffer object
    size_t
        dstSlicePitch, ///< [in] length of each 2D slice in bytes in the destination buffer object
    uint32_t numEventsInWaitList, ///< [in] size of the event wait list
    const ur_event_handle_t *
        phEventWaitList, ///< [in][optional][range(0, numEventsInWaitList)] pointer to a list of
    ///< events that must be complete before this command can be executed.
    ///< If nullptr, the numEventsInWaitList must be 0, indicating that this
    ///< command does not wait on any event to complete.
    ur_event_handle_t *
        phEvent ///< [out][optional] return an event object that identifies this particular
                ///< command instance.
) {
    auto pfnMemBufferCopyRect = context.urDdiTable.Enqueue.pfnMemBufferCopyRect;

    if (nullptr == pfnMemBufferCopyRect) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urEnqueueMemBufferCopyRect");

    auto SrcBuffer = context.interceptor->getMemBuffer(hBufferSrc);
    auto DstBuffer = context.interceptor->getMemBuffer(hBufferDst);

    UR_ASSERT((SrcBuffer && DstBuffer) || (!SrcBuffer && !DstBuffer),
              UR_RESULT_ERROR_INVALID_MEM_OBJECT);

    if (SrcBuffer && DstBuffer) {
        ur_device_handle_t Device = GetDevice(hQueue);
        char *SrcHandle = nullptr;
        UR_CALL(SrcBuffer->getHandle(Device, SrcHandle));

        char *DstHandle = nullptr;
        UR_CALL(DstBuffer->getHandle(Device, DstHandle));

        UR_CALL(EnqueueMemCopyRectHelper(
            hQueue, SrcHandle, DstHandle, srcOrigin, dstOrigin, region,
            srcRowPitch, srcSlicePitch, dstRowPitch, dstSlicePitch, false,
            numEventsInWaitList, phEventWaitList, phEvent));
    } else {
        UR_CALL(pfnMemBufferCopyRect(
            hQueue, hBufferSrc, hBufferDst, srcOrigin, dstOrigin, region,
            srcRowPitch, srcSlicePitch, dstRowPitch, dstSlicePitch,
            numEventsInWaitList, phEventWaitList, phEvent));
    }

    return UR_RESULT_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urEnqueueMemBufferFill
__urdlllocal ur_result_t UR_APICALL urEnqueueMemBufferFill(
    ur_queue_handle_t hQueue, ///< [in] handle of the queue object
    ur_mem_handle_t
        hBuffer, ///< [in][bounds(offset, size)] handle of the buffer object
    const void *pPattern, ///< [in] pointer to the fill pattern
    size_t patternSize,   ///< [in] size in bytes of the pattern
    size_t offset,        ///< [in] offset into the buffer
    size_t size, ///< [in] fill size in bytes, must be a multiple of patternSize
    uint32_t numEventsInWaitList, ///< [in] size of the event wait list
    const ur_event_handle_t *
        phEventWaitList, ///< [in][optional][range(0, numEventsInWaitList)] pointer to a list of
    ///< events that must be complete before this command can be executed.
    ///< If nullptr, the numEventsInWaitList must be 0, indicating that this
    ///< command does not wait on any event to complete.
    ur_event_handle_t *
        phEvent ///< [out][optional] return an event object that identifies this particular
                ///< command instance.
) {
    auto pfnMemBufferFill = context.urDdiTable.Enqueue.pfnMemBufferFill;

    if (nullptr == pfnMemBufferFill) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urEnqueueMemBufferFill");

    if (auto MemBuffer = context.interceptor->getMemBuffer(hBuffer)) {
        char *Handle = nullptr;
        ur_device_handle_t Device = GetDevice(hQueue);
        UR_CALL(MemBuffer->getHandle(Device, Handle));
        UR_CALL(context.urDdiTable.Enqueue.pfnUSMFill(
            hQueue, Handle + offset, patternSize, pPattern, size,
            numEventsInWaitList, phEventWaitList, phEvent));
    } else {
        UR_CALL(pfnMemBufferFill(hQueue, hBuffer, pPattern, patternSize, offset,
                                 size, numEventsInWaitList, phEventWaitList,
                                 phEvent));
    }

    return UR_RESULT_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urEnqueueMemBufferMap
__urdlllocal ur_result_t UR_APICALL urEnqueueMemBufferMap(
    ur_queue_handle_t hQueue, ///< [in] handle of the queue object
    ur_mem_handle_t
        hBuffer, ///< [in][bounds(offset, size)] handle of the buffer object
    bool blockingMap, ///< [in] indicates blocking (true), non-blocking (false)
    ur_map_flags_t mapFlags, ///< [in] flags for read, write, readwrite mapping
    size_t offset, ///< [in] offset in bytes of the buffer region being mapped
    size_t size,   ///< [in] size in bytes of the buffer region being mapped
    uint32_t numEventsInWaitList, ///< [in] size of the event wait list
    const ur_event_handle_t *
        phEventWaitList, ///< [in][optional][range(0, numEventsInWaitList)] pointer to a list of
    ///< events that must be complete before this command can be executed.
    ///< If nullptr, the numEventsInWaitList must be 0, indicating that this
    ///< command does not wait on any event to complete.
    ur_event_handle_t *
        phEvent, ///< [out][optional] return an event object that identifies this particular
                 ///< command instance.
    void **ppRetMap ///< [out] return mapped pointer.  TODO: move it before
                    ///< numEventsInWaitList?
) {
    auto pfnMemBufferMap = context.urDdiTable.Enqueue.pfnMemBufferMap;

    if (nullptr == pfnMemBufferMap) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urEnqueueMemBufferMap");

    if (auto MemBuffer = context.interceptor->getMemBuffer(hBuffer)) {

        // Translate the host access mode info.
        MemBuffer::AccessMode AccessMode = MemBuffer::UNKNOWN;
        if (mapFlags & UR_MAP_FLAG_WRITE_INVALIDATE_REGION) {
            AccessMode = MemBuffer::WRITE_ONLY;
        } else {
            if (mapFlags & UR_MAP_FLAG_READ) {
                AccessMode = MemBuffer::READ_ONLY;
                if (mapFlags & UR_MAP_FLAG_WRITE) {
                    AccessMode = MemBuffer::READ_WRITE;
                }
            } else if (mapFlags & UR_MAP_FLAG_WRITE) {
                AccessMode = MemBuffer::WRITE_ONLY;
            }
        }

        UR_ASSERT(AccessMode != MemBuffer::UNKNOWN,
                  UR_RESULT_ERROR_INVALID_ARGUMENT);

        ur_device_handle_t Device = GetDevice(hQueue);
        // If the buffer used host pointer, then we just reuse it. If not, we
        // need to manually allocate a new host USM.
        if (MemBuffer->HostPtr) {
            *ppRetMap = MemBuffer->HostPtr + offset;
        } else {
            ur_context_handle_t Context = GetContext(hQueue);
            ur_usm_desc_t USMDesc{};
            USMDesc.align = MemBuffer->getAlignment();
            ur_usm_pool_handle_t Pool{};
            UR_CALL(context.interceptor->allocateMemory(
                Context, nullptr, &USMDesc, Pool, size, AllocType::HOST_USM,
                ppRetMap));
        }

        // Actually, if the access mode is write only, we don't need to do this
        // copy. However, in that way, we cannot generate a event to user. So,
        // we'll aways do copy here.
        char *SrcHandle = nullptr;
        UR_CALL(MemBuffer->getHandle(Device, SrcHandle));
        UR_CALL(context.urDdiTable.Enqueue.pfnUSMMemcpy(
            hQueue, blockingMap, *ppRetMap, SrcHandle + offset, size,
            numEventsInWaitList, phEventWaitList, phEvent));

        {
            std::scoped_lock<ur_shared_mutex> Guard(MemBuffer->Mutex);
            UR_ASSERT(MemBuffer->Mappings.find(*ppRetMap) ==
                          MemBuffer->Mappings.end(),
                      UR_RESULT_ERROR_INVALID_VALUE);
            MemBuffer->Mappings[*ppRetMap] = {offset, size};
        }
    } else {
        UR_CALL(pfnMemBufferMap(hQueue, hBuffer, blockingMap, mapFlags, offset,
                                size, numEventsInWaitList, phEventWaitList,
                                phEvent, ppRetMap));
    }

    return UR_RESULT_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urEnqueueMemUnmap
__urdlllocal ur_result_t UR_APICALL urEnqueueMemUnmap(
    ur_queue_handle_t hQueue, ///< [in] handle of the queue object
    ur_mem_handle_t
        hMem,         ///< [in] handle of the memory (buffer or image) object
    void *pMappedPtr, ///< [in] mapped host address
    uint32_t numEventsInWaitList, ///< [in] size of the event wait list
    const ur_event_handle_t *
        phEventWaitList, ///< [in][optional][range(0, numEventsInWaitList)] pointer to a list of
    ///< events that must be complete before this command can be executed.
    ///< If nullptr, the numEventsInWaitList must be 0, indicating that this
    ///< command does not wait on any event to complete.
    ur_event_handle_t *
        phEvent ///< [out][optional] return an event object that identifies this particular
                ///< command instance.
) {
    auto pfnMemUnmap = context.urDdiTable.Enqueue.pfnMemUnmap;

    if (nullptr == pfnMemUnmap) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urEnqueueMemUnmap");

    if (auto MemBuffer = context.interceptor->getMemBuffer(hMem)) {
        MemBuffer::Mapping Mapping{};
        {
            std::scoped_lock<ur_shared_mutex> Guard(MemBuffer->Mutex);
            auto It = MemBuffer->Mappings.find(pMappedPtr);
            UR_ASSERT(It != MemBuffer->Mappings.end(),
                      UR_RESULT_ERROR_INVALID_VALUE);
            Mapping = It->second;
            MemBuffer->Mappings.erase(It);
        }

        // Write back mapping memory data to device and release mapping memory
        // if we allocated a host USM. But for now, UR doesn't support event
        // call back, we can only do blocking copy here.
        char *DstHandle = nullptr;
        ur_context_handle_t Context = GetContext(hQueue);
        ur_device_handle_t Device = GetDevice(hQueue);
        UR_CALL(MemBuffer->getHandle(Device, DstHandle));
        UR_CALL(context.urDdiTable.Enqueue.pfnUSMMemcpy(
            hQueue, true, DstHandle + Mapping.Offset, pMappedPtr, Mapping.Size,
            numEventsInWaitList, phEventWaitList, phEvent));

        if (!MemBuffer->HostPtr) {
            UR_CALL(context.interceptor->releaseMemory(Context, pMappedPtr));
        }
    } else {
        UR_CALL(pfnMemUnmap(hQueue, hMem, pMappedPtr, numEventsInWaitList,
                            phEventWaitList, phEvent));
    }

    return UR_RESULT_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urKernelCreate
__urdlllocal ur_result_t UR_APICALL urKernelCreate(
    ur_program_handle_t hProgram, ///< [in] handle of the program instance
    const char *pKernelName,      ///< [in] pointer to null-terminated string.
    ur_kernel_handle_t
        *phKernel ///< [out] pointer to handle of kernel object created.
) {
    auto pfnCreate = context.urDdiTable.Kernel.pfnCreate;

    if (nullptr == pfnCreate) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urKernelCreate");

    UR_CALL(pfnCreate(hProgram, pKernelName, phKernel));
    UR_CALL(context.interceptor->insertKernel(*phKernel));

    return UR_RESULT_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urKernelRelease
__urdlllocal ur_result_t urKernelRelease(
    ur_kernel_handle_t hKernel ///< [in] handle for the Kernel to release
) {
    auto pfnRelease = context.urDdiTable.Kernel.pfnRelease;

    if (nullptr == pfnRelease) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urKernelRelease");
    UR_CALL(pfnRelease(hKernel));

    if (auto KernelInfo = context.interceptor->getKernelInfo(hKernel)) {
        uint32_t RefCount;
        UR_CALL(context.urDdiTable.Kernel.pfnGetInfo(
            hKernel, UR_KERNEL_INFO_REFERENCE_COUNT, sizeof(RefCount),
            &RefCount, nullptr));
        if (RefCount == 1) {
            UR_CALL(context.interceptor->eraseKernel(hKernel));
        }
    }

    return UR_RESULT_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urKernelSetArgValue
__urdlllocal ur_result_t UR_APICALL urKernelSetArgValue(
    ur_kernel_handle_t hKernel, ///< [in] handle of the kernel object
    uint32_t argIndex, ///< [in] argument index in range [0, num args - 1]
    size_t argSize,    ///< [in] size of argument type
    const ur_kernel_arg_value_properties_t
        *pProperties, ///< [in][optional] pointer to value properties.
    const void
        *pArgValue ///< [in] argument value represented as matching arg type.
) {
    auto pfnSetArgValue = context.urDdiTable.Kernel.pfnSetArgValue;

    if (nullptr == pfnSetArgValue) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urKernelSetArgValue");

    std::shared_ptr<MemBuffer> MemBuffer;
    if (argSize == sizeof(ur_mem_handle_t) &&
        (MemBuffer = context.interceptor->getMemBuffer(
             *ur_cast<const ur_mem_handle_t *>(pArgValue)))) {
        auto KernelInfo = context.interceptor->getKernelInfo(hKernel);
        std::scoped_lock<ur_shared_mutex> Guard(KernelInfo->Mutex);
        KernelInfo->BufferArgs[argIndex] = MemBuffer;
    } else {
        UR_CALL(
            pfnSetArgValue(hKernel, argIndex, argSize, pProperties, pArgValue));
    }

    return UR_RESULT_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urKernelSetArgMemObj
__urdlllocal ur_result_t UR_APICALL urKernelSetArgMemObj(
    ur_kernel_handle_t hKernel, ///< [in] handle of the kernel object
    uint32_t argIndex, ///< [in] argument index in range [0, num args - 1]
    const ur_kernel_arg_mem_obj_properties_t
        *pProperties, ///< [in][optional] pointer to Memory object properties.
    ur_mem_handle_t hArgValue ///< [in][optional] handle of Memory object.
) {
    auto pfnSetArgMemObj = context.urDdiTable.Kernel.pfnSetArgMemObj;

    if (nullptr == pfnSetArgMemObj) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urKernelSetArgMemObj");

    if (auto MemBuffer = context.interceptor->getMemBuffer(hArgValue)) {
        auto KernelInfo = context.interceptor->getKernelInfo(hKernel);
        std::scoped_lock<ur_shared_mutex> Guard(KernelInfo->Mutex);
        KernelInfo->BufferArgs[argIndex] = MemBuffer;
    } else {
        UR_CALL(pfnSetArgMemObj(hKernel, argIndex, pProperties, hArgValue));
    }

    return UR_RESULT_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urKernelSetArgLocal
__urdlllocal ur_result_t UR_APICALL urKernelSetArgLocal(
    ur_kernel_handle_t hKernel, ///< [in] handle of the kernel object
    uint32_t argIndex, ///< [in] argument index in range [0, num args - 1]
    size_t
        argSize, ///< [in] size of the local buffer to be allocated by the runtime
    const ur_kernel_arg_local_properties_t
        *pProperties ///< [in][optional] pointer to local buffer properties.
) {
    auto pfnSetArgLocal = context.urDdiTable.Kernel.pfnSetArgLocal;

    if (nullptr == pfnSetArgLocal) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }

    context.logger.debug("==== urKernelSetArgLocal (argIndex={}, argSize={})",
                         argIndex, argSize);

    {
        auto KI = context.interceptor->getKernelInfo(hKernel);
        std::scoped_lock<ur_shared_mutex> Guard(KI->Mutex);
        // TODO: get local variable alignment
        auto argSizeWithRZ = GetSizeAndRedzoneSizeForLocal(
            argSize, ASAN_SHADOW_GRANULARITY, ASAN_SHADOW_GRANULARITY);
        KI->LocalArgs[argIndex] = LocalArgsInfo{argSize, argSizeWithRZ};
        argSize = argSizeWithRZ;
    }

    ur_result_t result =
        pfnSetArgLocal(hKernel, argIndex, argSize, pProperties);

    return result;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Exported function for filling application's Context table
///        with current process' addresses
///
/// @returns
///     - ::UR_RESULT_SUCCESS
///     - ::UR_RESULT_ERROR_INVALID_NULL_POINTER
///     - ::UR_RESULT_ERROR_UNSUPPORTED_VERSION
__urdlllocal ur_result_t UR_APICALL urGetContextProcAddrTable(
    ur_api_version_t version, ///< [in] API version requested
    ur_context_dditable_t
        *pDdiTable ///< [in,out] pointer to table of DDI function pointers
) {
    if (nullptr == pDdiTable) {
        return UR_RESULT_ERROR_INVALID_NULL_POINTER;
    }

    if (UR_MAJOR_VERSION(ur_sanitizer_layer::context.version) !=
            UR_MAJOR_VERSION(version) ||
        UR_MINOR_VERSION(ur_sanitizer_layer::context.version) >
            UR_MINOR_VERSION(version)) {
        return UR_RESULT_ERROR_UNSUPPORTED_VERSION;
    }

    ur_result_t result = UR_RESULT_SUCCESS;

    pDdiTable->pfnCreate = ur_sanitizer_layer::urContextCreate;
    pDdiTable->pfnRelease = ur_sanitizer_layer::urContextRelease;

    pDdiTable->pfnCreateWithNativeHandle =
        ur_sanitizer_layer::urContextCreateWithNativeHandle;

    return result;
}
///////////////////////////////////////////////////////////////////////////////
/// @brief Exported function for filling application's Program table
///        with current process' addresses
///
/// @returns
///     - ::UR_RESULT_SUCCESS
///     - ::UR_RESULT_ERROR_INVALID_NULL_POINTER
///     - ::UR_RESULT_ERROR_UNSUPPORTED_VERSION
__urdlllocal ur_result_t UR_APICALL urGetProgramProcAddrTable(
    ur_api_version_t version, ///< [in] API version requested
    ur_program_dditable_t
        *pDdiTable ///< [in,out] pointer to table of DDI function pointers
) {
    if (nullptr == pDdiTable) {
        return UR_RESULT_ERROR_INVALID_NULL_POINTER;
    }

    if (UR_MAJOR_VERSION(ur_sanitizer_layer::context.version) !=
            UR_MAJOR_VERSION(version) ||
        UR_MINOR_VERSION(ur_sanitizer_layer::context.version) >
            UR_MINOR_VERSION(version)) {
        return UR_RESULT_ERROR_UNSUPPORTED_VERSION;
    }

    pDdiTable->pfnBuild = ur_sanitizer_layer::urProgramBuild;

    return UR_RESULT_SUCCESS;
}
///////////////////////////////////////////////////////////////////////////////
/// @brief Exported function for filling application's Kernel table
///        with current process' addresses
///
/// @returns
///     - ::UR_RESULT_SUCCESS
///     - ::UR_RESULT_ERROR_INVALID_NULL_POINTER
///     - ::UR_RESULT_ERROR_UNSUPPORTED_VERSION
__urdlllocal ur_result_t UR_APICALL urGetKernelProcAddrTable(
    ur_api_version_t version, ///< [in] API version requested
    ur_kernel_dditable_t
        *pDdiTable ///< [in,out] pointer to table of DDI function pointers
) {
    if (nullptr == pDdiTable) {
        return UR_RESULT_ERROR_INVALID_NULL_POINTER;
    }

    if (UR_MAJOR_VERSION(ur_sanitizer_layer::context.version) !=
            UR_MAJOR_VERSION(version) ||
        UR_MINOR_VERSION(ur_sanitizer_layer::context.version) >
            UR_MINOR_VERSION(version)) {
        return UR_RESULT_ERROR_UNSUPPORTED_VERSION;
    }

    ur_result_t result = UR_RESULT_SUCCESS;

    pDdiTable->pfnCreate = ur_sanitizer_layer::urKernelCreate;
    pDdiTable->pfnRelease = ur_sanitizer_layer::urKernelRelease;
    pDdiTable->pfnSetArgValue = ur_sanitizer_layer::urKernelSetArgValue;
    pDdiTable->pfnSetArgMemObj = ur_sanitizer_layer::urKernelSetArgMemObj;
    pDdiTable->pfnSetArgLocal = ur_sanitizer_layer::urKernelSetArgLocal;

    return result;
}
///////////////////////////////////////////////////////////////////////////////
/// @brief Exported function for filling application's Mem table
///        with current process' addresses
///
/// @returns
///     - ::UR_RESULT_SUCCESS
///     - ::UR_RESULT_ERROR_INVALID_NULL_POINTER
///     - ::UR_RESULT_ERROR_UNSUPPORTED_VERSION
__urdlllocal ur_result_t UR_APICALL urGetMemProcAddrTable(
    ur_api_version_t version, ///< [in] API version requested
    ur_mem_dditable_t
        *pDdiTable ///< [in,out] pointer to table of DDI function pointers
) {
    if (nullptr == pDdiTable) {
        return UR_RESULT_ERROR_INVALID_NULL_POINTER;
    }

    if (UR_MAJOR_VERSION(ur_sanitizer_layer::context.version) !=
            UR_MAJOR_VERSION(version) ||
        UR_MINOR_VERSION(ur_sanitizer_layer::context.version) >
            UR_MINOR_VERSION(version)) {
        return UR_RESULT_ERROR_UNSUPPORTED_VERSION;
    }

    ur_result_t result = UR_RESULT_SUCCESS;

    pDdiTable->pfnBufferCreate = ur_sanitizer_layer::urMemBufferCreate;
    pDdiTable->pfnRetain = ur_sanitizer_layer::urMemRetain;
    pDdiTable->pfnRelease = ur_sanitizer_layer::urMemRelease;
    pDdiTable->pfnBufferPartition = ur_sanitizer_layer::urMemBufferPartition;
    pDdiTable->pfnGetNativeHandle = ur_sanitizer_layer::urMemGetNativeHandle;
    pDdiTable->pfnGetInfo = ur_sanitizer_layer::urMemGetInfo;

    return result;
}
/// @brief Exported function for filling application's ProgramExp table
///        with current process' addresses
///
/// @returns
///     - ::UR_RESULT_SUCCESS
///     - ::UR_RESULT_ERROR_INVALID_NULL_POINTER
///     - ::UR_RESULT_ERROR_UNSUPPORTED_VERSION
__urdlllocal ur_result_t UR_APICALL urGetProgramExpProcAddrTable(
    ur_api_version_t version, ///< [in] API version requested
    ur_program_exp_dditable_t
        *pDdiTable ///< [in,out] pointer to table of DDI function pointers
) {
    if (nullptr == pDdiTable) {
        return UR_RESULT_ERROR_INVALID_NULL_POINTER;
    }

    if (UR_MAJOR_VERSION(ur_sanitizer_layer::context.version) !=
            UR_MAJOR_VERSION(version) ||
        UR_MINOR_VERSION(ur_sanitizer_layer::context.version) >
            UR_MINOR_VERSION(version)) {
        return UR_RESULT_ERROR_UNSUPPORTED_VERSION;
    }

    ur_result_t result = UR_RESULT_SUCCESS;

    pDdiTable->pfnBuildExp = ur_sanitizer_layer::urProgramBuildExp;

    return result;
}
///////////////////////////////////////////////////////////////////////////////
/// @brief Exported function for filling application's Enqueue table
///        with current process' addresses
///
/// @returns
///     - ::UR_RESULT_SUCCESS
///     - ::UR_RESULT_ERROR_INVALID_NULL_POINTER
///     - ::UR_RESULT_ERROR_UNSUPPORTED_VERSION
__urdlllocal ur_result_t UR_APICALL urGetEnqueueProcAddrTable(
    ur_api_version_t version, ///< [in] API version requested
    ur_enqueue_dditable_t
        *pDdiTable ///< [in,out] pointer to table of DDI function pointers
) {
    if (nullptr == pDdiTable) {
        return UR_RESULT_ERROR_INVALID_NULL_POINTER;
    }

    if (UR_MAJOR_VERSION(ur_sanitizer_layer::context.version) !=
            UR_MAJOR_VERSION(version) ||
        UR_MINOR_VERSION(ur_sanitizer_layer::context.version) >
            UR_MINOR_VERSION(version)) {
        return UR_RESULT_ERROR_UNSUPPORTED_VERSION;
    }

    ur_result_t result = UR_RESULT_SUCCESS;

    pDdiTable->pfnMemBufferRead = ur_sanitizer_layer::urEnqueueMemBufferRead;
    pDdiTable->pfnMemBufferWrite = ur_sanitizer_layer::urEnqueueMemBufferWrite;
    pDdiTable->pfnMemBufferReadRect =
        ur_sanitizer_layer::urEnqueueMemBufferReadRect;
    pDdiTable->pfnMemBufferWriteRect =
        ur_sanitizer_layer::urEnqueueMemBufferWriteRect;
    pDdiTable->pfnMemBufferCopy = ur_sanitizer_layer::urEnqueueMemBufferCopy;
    pDdiTable->pfnMemBufferCopyRect =
        ur_sanitizer_layer::urEnqueueMemBufferCopyRect;
    pDdiTable->pfnMemBufferFill = ur_sanitizer_layer::urEnqueueMemBufferFill;
    pDdiTable->pfnMemBufferMap = ur_sanitizer_layer::urEnqueueMemBufferMap;
    pDdiTable->pfnMemUnmap = ur_sanitizer_layer::urEnqueueMemUnmap;
    pDdiTable->pfnKernelLaunch = ur_sanitizer_layer::urEnqueueKernelLaunch;

    return result;
}
///////////////////////////////////////////////////////////////////////////////
/// @brief Exported function for filling application's USM table
///        with current process' addresses
///
/// @returns
///     - ::UR_RESULT_SUCCESS
///     - ::UR_RESULT_ERROR_INVALID_NULL_POINTER
///     - ::UR_RESULT_ERROR_UNSUPPORTED_VERSION
__urdlllocal ur_result_t UR_APICALL urGetUSMProcAddrTable(
    ur_api_version_t version, ///< [in] API version requested
    ur_usm_dditable_t
        *pDdiTable ///< [in,out] pointer to table of DDI function pointers
) {
    if (nullptr == pDdiTable) {
        return UR_RESULT_ERROR_INVALID_NULL_POINTER;
    }

    if (UR_MAJOR_VERSION(ur_sanitizer_layer::context.version) !=
            UR_MAJOR_VERSION(version) ||
        UR_MINOR_VERSION(ur_sanitizer_layer::context.version) >
            UR_MINOR_VERSION(version)) {
        return UR_RESULT_ERROR_UNSUPPORTED_VERSION;
    }

    ur_result_t result = UR_RESULT_SUCCESS;

    pDdiTable->pfnDeviceAlloc = ur_sanitizer_layer::urUSMDeviceAlloc;
    pDdiTable->pfnHostAlloc = ur_sanitizer_layer::urUSMHostAlloc;
    pDdiTable->pfnSharedAlloc = ur_sanitizer_layer::urUSMSharedAlloc;
    pDdiTable->pfnFree = ur_sanitizer_layer::urUSMFree;

    return result;
}

ur_result_t context_t::init(ur_dditable_t *dditable,
                            const std::set<std::string> &enabledLayerNames,
                            [[maybe_unused]] codeloc_data codelocData) {
    ur_result_t result = UR_RESULT_SUCCESS;

    if (enabledLayerNames.count("UR_LAYER_ASAN")) {
        context.enabledType = SanitizerType::AddressSanitizer;
    } else if (enabledLayerNames.count("UR_LAYER_MSAN")) {
        context.enabledType = SanitizerType::MemorySanitizer;
    } else if (enabledLayerNames.count("UR_LAYER_TSAN")) {
        context.enabledType = SanitizerType::ThreadSanitizer;
    }

    // Only support AddressSanitizer now
    if (context.enabledType != SanitizerType::AddressSanitizer) {
        return result;
    }

    if (context.enabledType == SanitizerType::AddressSanitizer) {
        if (!(dditable->VirtualMem.pfnReserve && dditable->VirtualMem.pfnMap &&
              dditable->VirtualMem.pfnGranularityGetInfo)) {
            die("Some VirtualMem APIs are needed to enable UR_LAYER_ASAN");
        }

        if (!dditable->PhysicalMem.pfnCreate) {
            die("Some PhysicalMem APIs are needed to enable UR_LAYER_ASAN");
        }
    }

    urDdiTable = *dditable;

    if (UR_RESULT_SUCCESS == result) {
        result = ur_sanitizer_layer::urGetContextProcAddrTable(
            UR_API_VERSION_CURRENT, &dditable->Context);
    }

    if (UR_RESULT_SUCCESS == result) {
        result = ur_sanitizer_layer::urGetProgramProcAddrTable(
            UR_API_VERSION_CURRENT, &dditable->Program);
    }

    if (UR_RESULT_SUCCESS == result) {
        result = ur_sanitizer_layer::urGetKernelProcAddrTable(
            UR_API_VERSION_CURRENT, &dditable->Kernel);
    }

    if (UR_RESULT_SUCCESS == result) {
        result = ur_sanitizer_layer::urGetMemProcAddrTable(
            UR_API_VERSION_CURRENT, &dditable->Mem);
    }

    if (UR_RESULT_SUCCESS == result) {
        result = ur_sanitizer_layer::urGetProgramExpProcAddrTable(
            UR_API_VERSION_CURRENT, &dditable->ProgramExp);
    }

    if (UR_RESULT_SUCCESS == result) {
        result = ur_sanitizer_layer::urGetEnqueueProcAddrTable(
            UR_API_VERSION_CURRENT, &dditable->Enqueue);
    }

    if (UR_RESULT_SUCCESS == result) {
        result = ur_sanitizer_layer::urGetUSMProcAddrTable(
            UR_API_VERSION_CURRENT, &dditable->USM);
    }

    return result;
}

} // namespace ur_sanitizer_layer
