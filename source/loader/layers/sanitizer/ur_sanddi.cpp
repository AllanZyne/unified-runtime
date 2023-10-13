/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Part of the Unified-Runtime Project, under the Apache License v2.0 with LLVM Exceptions.
 * See LICENSE.TXT
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 * @file ur_trcddi.cpp
 *
 */

#include "sanitizer_interceptor.hpp"
#include "ur_sanitizer_layer.hpp"

#include <iostream>
#include <stdio.h>

namespace ur_sanitizer_layer {

// ///////////////////////////////////////////////////////////////////////////////
// /// @brief Intercept function for urUSMHostAlloc
// __urdlllocal ur_result_t UR_APICALL urUSMHostAlloc(
//     ur_context_handle_t hContext, ///< [in] handle of the context object
//     const ur_usm_desc_t
//         *pUSMDesc, ///< [in][optional] USM memory allocation descriptor
//     ur_usm_pool_handle_t
//         pool, ///< [in][optional] Pointer to a pool created using urUSMPoolCreate
//     size_t
//         size, ///< [in] size in bytes of the USM memory object to be allocated
//     void **ppMem ///< [out] pointer to USM host memory object
// ) {
//     auto pfnHostAlloc = context.urDdiTable.USM.pfnHostAlloc;

//     if (nullptr == pfnHostAlloc) {
//         return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
//     }

//     ur_usm_host_alloc_params_t params = {&hContext, &pUSMDesc, &pool, &size,
//                                          &ppMem};
//     uint64_t instance = context.notify_begin(UR_FUNCTION_USM_HOST_ALLOC,
//                                              "urUSMHostAlloc", &params);

//     ur_result_t result = pfnHostAlloc(hContext, pUSMDesc, pool, size, ppMem);

//     context.notify_end(UR_FUNCTION_USM_HOST_ALLOC, "urUSMHostAlloc", &params,
//                        &result, instance);

//     return result;
// }

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
    std::cerr << "=== urUSMDeviceAlloc" << std::endl;

    return context.interceptor->allocateMemory(
        hContext, hDevice, pUSMDesc, pool, size, ppMem, USMMemoryType::DEVICE);
}

// ///////////////////////////////////////////////////////////////////////////////
// /// @brief Intercept function for urUSMSharedAlloc
// __urdlllocal ur_result_t UR_APICALL urUSMSharedAlloc(
//     ur_context_handle_t hContext, ///< [in] handle of the context object
//     ur_device_handle_t hDevice,   ///< [in] handle of the device object
//     const ur_usm_desc_t *
//         pUSMDesc, ///< [in][optional] Pointer to USM memory allocation descriptor.
//     ur_usm_pool_handle_t
//         pool, ///< [in][optional] Pointer to a pool created using urUSMPoolCreate
//     size_t
//         size, ///< [in] size in bytes of the USM memory object to be allocated
//     void **ppMem ///< [out] pointer to USM shared memory object
// ) {
//     auto pfnSharedAlloc = context.urDdiTable.USM.pfnSharedAlloc;

//     if (nullptr == pfnSharedAlloc) {
//         return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
//     }

//     ur_usm_shared_alloc_params_t params = {&hContext, &hDevice, &pUSMDesc,
//                                            &pool,     &size,    &ppMem};
//     uint64_t instance = context.notify_begin(UR_FUNCTION_USM_SHARED_ALLOC,
//                                              "urUSMSharedAlloc", &params);

//     ur_result_t result =
//         pfnSharedAlloc(hContext, hDevice, pUSMDesc, pool, size, ppMem);

//     context.notify_end(UR_FUNCTION_USM_SHARED_ALLOC, "urUSMSharedAlloc",
//                        &params, &result, instance);

//     return result;
// }

// ///////////////////////////////////////////////////////////////////////////////
// /// @brief Intercept function for urUSMFree
// __urdlllocal ur_result_t UR_APICALL urUSMFree(
//     ur_context_handle_t hContext, ///< [in] handle of the context object
//     void *pMem                    ///< [in] pointer to USM memory object
// ) {
//     auto pfnFree = context.urDdiTable.USM.pfnFree;

//     if (nullptr == pfnFree) {
//         return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
//     }

//     ur_usm_free_params_t params = {&hContext, &pMem};
//     uint64_t instance =
//         context.notify_begin(UR_FUNCTION_USM_FREE, "urUSMFree", &params);

//     ur_result_t result = pfnFree(hContext, pMem);

//     context.notify_end(UR_FUNCTION_USM_FREE, "urUSMFree", &params, &result,
//                        instance);

//     return result;
// }

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
    std::cerr << "=== urKernelCreate" << std::endl;

    ur_result_t result = pfnCreate(hProgram, pKernelName, phKernel);
    if (result == UR_RESULT_SUCCESS) {
        context.interceptor->addKernel(hProgram, *phKernel);
    }

    return result;
}

///////////////////////////////////////////////////////////////////////////////
/// @brief Intercept function for urQueueCreate
__urdlllocal ur_result_t UR_APICALL urQueueCreate(
    ur_context_handle_t hContext, ///< [in] handle of the context object
    ur_device_handle_t hDevice,   ///< [in] handle of the device object
    const ur_queue_properties_t
        *pProperties, ///< [in][optional] pointer to queue creation properties.
    ur_queue_handle_t
        *phQueue ///< [out] pointer to handle of queue object created
) {
    auto pfnCreate = context.urDdiTable.Queue.pfnCreate;

    if (nullptr == pfnCreate) {
        return UR_RESULT_ERROR_UNSUPPORTED_FEATURE;
    }
    std::cerr << "=== urQueueCreate" << std::endl;

    ur_result_t result = pfnCreate(hContext, hDevice, pProperties, phQueue);
    if (result == UR_RESULT_SUCCESS) {
        context.interceptor->addQueue(hContext, hDevice, *phQueue);
    }

    return result;
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

    std::cerr << "=== urEnqueueKernelLaunch" << std::endl;
    ur_event_handle_t lk_event{};
    std::vector<ur_event_handle_t> events(numEventsInWaitList + 1);
    for (unsigned i = 0; i < numEventsInWaitList; ++i) {
        events.push_back(phEventWaitList[i]);
    }

    // launchKernel must append to num_events_in_wait_list, not prepend
    context.interceptor->launchKernel(hKernel, hQueue, lk_event);
    if (lk_event) {
        events.push_back(lk_event);
    }

    ur_result_t result = pfnKernelLaunch(
        hQueue, hKernel, workDim, pGlobalWorkOffset, pGlobalWorkSize,
        pLocalWorkSize, numEventsInWaitList, phEventWaitList, phEvent);

    if (result == UR_RESULT_SUCCESS) {
        context.interceptor->postLaunchKernel(hKernel, hQueue, phEvent, false);
    }

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
    // auto &dditable = ur_sanitizer_layer::context.urDdiTable.Enqueue;

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

    // dditable.pfnKernelLaunch = pDdiTable->pfnKernelLaunch;
    pDdiTable->pfnKernelLaunch = ur_sanitizer_layer::urEnqueueKernelLaunch;

    return result;
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
    // auto &dditable = ur_sanitizer_layer::context.urDdiTable.Kernel;

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

    // dditable.pfnCreate = pDdiTable->pfnCreate;
    pDdiTable->pfnCreate = ur_sanitizer_layer::urKernelCreate;

    return result;
}
///////////////////////////////////////////////////////////////////////////////
/// @brief Exported function for filling application's Queue table
///        with current process' addresses
///
/// @returns
///     - ::UR_RESULT_SUCCESS
///     - ::UR_RESULT_ERROR_INVALID_NULL_POINTER
///     - ::UR_RESULT_ERROR_UNSUPPORTED_VERSION
__urdlllocal ur_result_t UR_APICALL urGetQueueProcAddrTable(
    ur_api_version_t version, ///< [in] API version requested
    ur_queue_dditable_t
        *pDdiTable ///< [in,out] pointer to table of DDI function pointers
) {
    // auto &dditable = ur_sanitizer_layer::context.urDdiTable.Queue;

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

    // dditable.pfnCreate = pDdiTable->pfnCreate;
    pDdiTable->pfnCreate = ur_sanitizer_layer::urQueueCreate;

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
    // auto &dditable = ur_sanitizer_layer::context.urDdiTable.USM;

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

    // dditable.pfnHostAlloc = pDdiTable->pfnHostAlloc;
    // pDdiTable->pfnHostAlloc = ur_sanitizer_layer::urUSMHostAlloc;

    // dditable.pfnDeviceAlloc = pDdiTable->pfnDeviceAlloc;
    pDdiTable->pfnDeviceAlloc = ur_sanitizer_layer::urUSMDeviceAlloc;

    // dditable.pfnSharedAlloc = pDdiTable->pfnSharedAlloc;
    // pDdiTable->pfnSharedAlloc = ur_sanitizer_layer::urUSMSharedAlloc;

    // dditable.pfnFree = pDdiTable->pfnFree;
    // pDdiTable->pfnFree = ur_sanitizer_layer::urUSMFree;

    return result;
}

ur_result_t context_t::init(ur_dditable_t *dditable,
                            const std::set<std::string> &enabledLayerNames) {
    ur_result_t result = UR_RESULT_SUCCESS;

    std::cout << "ur_sanitizer_layer context_t::init\n";

    // if (!enabledLayerNames.count(name)) {
    //     return result;
    // }

    if (UR_RESULT_SUCCESS == result) {
        // FIXME: Just copy needed APIs?
        urDdiTable = *dditable;

        result = ur_sanitizer_layer::urGetEnqueueProcAddrTable(
            UR_API_VERSION_CURRENT, &dditable->Enqueue);

        result = ur_sanitizer_layer::urGetKernelProcAddrTable(
            UR_API_VERSION_CURRENT, &dditable->Kernel);

        result = ur_sanitizer_layer::urGetQueueProcAddrTable(
            UR_API_VERSION_CURRENT, &dditable->Queue);

        result = ur_sanitizer_layer::urGetUSMProcAddrTable(
            UR_API_VERSION_CURRENT, &dditable->USM);
    }

    return result;
}
} // namespace ur_sanitizer_layer