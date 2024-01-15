/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Part of the Unified-Runtime Project, under the Apache License v2.0 with LLVM Exceptions.
 * See LICENSE.TXT
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 * @file common.cpp
 *
 */

#pragma once

#include "ur_sanitizer_layer.hpp"

#include "ur/ur.hpp"
#include "ur_ddi.h"

#include <cassert>

namespace ur_sanitizer_layer {

ur_context_handle_t getContext(ur_kernel_handle_t Kernel) {
    ur_context_handle_t Context;
    [[maybe_unused]] auto Result = context.urDdiTable.Kernel.pfnGetInfo(
        Kernel, UR_KERNEL_INFO_CONTEXT, sizeof(ur_context_handle_t), &Context,
        nullptr);
    assert(Result == UR_RESULT_SUCCESS);
    return Context;
}

ur_context_handle_t getContext(ur_queue_handle_t Queue) {
    ur_context_handle_t Context;
    [[maybe_unused]] auto Result = context.urDdiTable.Queue.pfnGetInfo(
        Queue, UR_QUEUE_INFO_CONTEXT, sizeof(ur_context_handle_t), &Context,
        nullptr);
    assert(Result == UR_RESULT_SUCCESS);
    return Context;
}

ur_context_handle_t getContext(ur_program_handle_t Program) {
    ur_context_handle_t Context;
    [[maybe_unused]] auto Result = context.urDdiTable.Program.pfnGetInfo(
        Program, UR_PROGRAM_INFO_CONTEXT, sizeof(ur_context_handle_t), &Context,
        nullptr);
    assert(Result == UR_RESULT_SUCCESS);
    return Context;
}

ur_device_handle_t getDevice(ur_queue_handle_t Queue) {
    ur_device_handle_t Device;
    [[maybe_unused]] auto Result = context.urDdiTable.Queue.pfnGetInfo(
        Queue, UR_QUEUE_INFO_DEVICE, sizeof(ur_device_handle_t), &Device,
        nullptr);
    assert(Result == UR_RESULT_SUCCESS);
    return Device;
}

ur_program_handle_t getProgram(ur_kernel_handle_t Kernel) {
    ur_program_handle_t Program;
    [[maybe_unused]] auto Result = context.urDdiTable.Kernel.pfnGetInfo(
        Kernel, UR_KERNEL_INFO_PROGRAM, sizeof(ur_program_handle_t), &Program,
        nullptr);
    assert(Result == UR_RESULT_SUCCESS);
    return Program;
}

} // namespace ur_sanitizer_layer
