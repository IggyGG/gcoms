#ifndef GCOMS_MOBILE_H
#define GCOMS_MOBILE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* ABI v1; link exactly one role. All buffers belong to the caller. */
uint32_t gcoms_mobile_abi_version(void);
uint32_t gcoms_mobile_role(void); /* 1 client, 2 relay */
uint64_t gcoms_mobile_create(void); /* 0 on resource exhaustion */
/* Copies input before returning; 0 means rejected, never accepted. */
uint64_t gcoms_mobile_submit(uint64_t session, const uint8_t *input, size_t length);
/* 0 pending, -1 stale ticket/session, -2 contained panic.
 * Positive: required byte count. NULL queries without consuming.
 * A successful copy consumes the ticket. Output is UTF-8 JSON, not NUL terminated. */
intptr_t gcoms_mobile_take(uint64_t session, uint64_t ticket, uint8_t *output, size_t capacity);
/* Queued work skipped. Running durable work completes; reconcile before retry.
 * Frees retained response and invalidates the ticket. */
int32_t gcoms_mobile_cancel(uint64_t session, uint64_t ticket);
/* Blocking graceful shutdown; call from a background thread. */
int32_t gcoms_mobile_destroy(uint64_t session);
#ifdef __cplusplus
}
#endif
#endif
