/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Part of the Unified-Runtime Project, under the Apache License v2.0 with LLVM Exceptions.
 * See LICENSE.TXT
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 * @file asan_buffer.cpp
 *
 */

#include "asan_buffer.hpp"
#include "asan_interceptor.hpp"
#include "ur_sanitizer_layer.hpp"
#include "ur_sanitizer_utils.hpp"

namespace ur_sanitizer_layer {

ur_result_t MemBuffer::getHandle(ur_device_handle_t Device, char *&Handle) {
    // Sub-buffers don't maintain own allocations but rely on parent buffer.
    if (SubBuffer) {
        UR_CALL(SubBuffer->Parent->getHandle(Device, Handle));
        Handle += SubBuffer->Origin;
        return UR_RESULT_SUCCESS;
    }

    auto &Allocation = Allocations[Device];
    if (!Allocation) {
        ur_usm_desc_t USMDesc{};
        USMDesc.align = getAlignment();
        ur_usm_pool_handle_t Pool{};
        ur_result_t URes = context.interceptor->allocateMemory(
            Context, Device, &USMDesc, Pool, Size, (void **)&Allocation,
            AllocType::MEM_BUFFER);
        if (URes != UR_RESULT_SUCCESS) {
            context.logger.error(
                "Failed to allocate {} bytes memory for buffer {}", Size, this);
            return URes;
        }

        if (HostPtr) {
            ManagedQueue Queue(Context, Device);
            URes = context.urDdiTable.Enqueue.pfnUSMMemcpy(
                Queue, true, Allocation, HostPtr, Size, 0, nullptr, nullptr);
            if (URes != UR_RESULT_SUCCESS) {
                context.logger.error("Failed to copy {} bytes data from host "
                                     "pointer {} to buffer {}",
                                     Size, HostPtr, this);
                return URes;
            }
        }
        Handle = Allocation;
    } else {
        Handle = Allocation;
    }

    return UR_RESULT_SUCCESS;
}

ur_result_t MemBuffer::free() {
    for (const auto &[_, Ptr] : Allocations) {
        ur_result_t URes = context.interceptor->releaseMemory(Context, Ptr);
        if (URes != UR_RESULT_SUCCESS) {
            context.logger.error("Failed to free buffer handle {}", Ptr);
        }
    }
    Allocations.clear();
    return UR_RESULT_SUCCESS;
}

size_t MemBuffer::getAlignment() {
    // Choose an alignment that is at most 64 and is the next power of 2
    // for sizes less than 64.
    size_t MsbIdx = 63 - __builtin_clz(Size);
    size_t Alignment = (1 << (MsbIdx + 1));
    if (Alignment > 64) {
        Alignment = 64;
    }
    return Alignment;
}

} // namespace ur_sanitizer_layer
