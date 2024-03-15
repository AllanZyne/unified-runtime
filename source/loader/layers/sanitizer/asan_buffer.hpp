/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Part of the Unified-Runtime Project, under the Apache License v2.0 with LLVM Exceptions.
 * See LICENSE.TXT
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 * @file asan_buffer.hpp
 *
 */

#pragma once

#include <atomic>
#include <memory>
#include <optional>

#include "common.hpp"

namespace ur_sanitizer_layer {

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

    char *HostPtr{};

    struct SubBuffer_t {
        std::shared_ptr<MemBuffer> Parent;
        size_t Origin;
    };

    std::optional<SubBuffer_t> SubBuffer;

    std::atomic<int32_t> RefCount;

    ur_shared_mutex Mutex;
};

} // namespace ur_sanitizer_layer
