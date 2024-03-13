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

} // namespace ur_sanitizer_layer