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
        UR_CALL(context.interceptor->allocateMemory(
            Context, Device, &USMDesc, Pool, Size, (void **)&Allocation,
            AllocType::MEM_BUFFER));

        if (HostPtr) {
            ur_queue_handle_t Queue;
            UR_CALL(context.urDdiTable.Queue.pfnCreate(Context, Device, nullptr,
                                                       &Queue));
            UR_CALL(context.urDdiTable.Enqueue.pfnUSMMemcpy(
                Queue, true, Allocation, HostPtr, Size, 0, nullptr, nullptr));
        }
        Handle = Allocation;
    } else {
        Handle = Allocation;
    }

    return UR_RESULT_SUCCESS;
}

ur_result_t MemBuffer::free() {
    for (auto &Pair : Allocations) {
        void *Ptr = Pair.second;
        context.logger.debug("MemBuffer::free(Trying to release pointer {})",
                             Ptr);
        UR_CALL(context.interceptor->releaseMemory(Context, Ptr));
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