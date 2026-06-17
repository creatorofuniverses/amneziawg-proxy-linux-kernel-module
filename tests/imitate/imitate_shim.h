/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IMITATE_SHIM_H
#define IMITATE_SHIM_H
#include <stdint.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/* Kernel annotation shims for userspace builds. */
#ifndef __maybe_unused
#define __maybe_unused __attribute__((__unused__))
#endif
#endif
