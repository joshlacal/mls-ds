#ifndef MLS_FFI_H
#define MLS_FFI_H

#pragma once

/* Generated with cbindgen:0.26.0 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * FFI-safe result type
 */
typedef struct MLSResult {
  bool success;
  char *error_message;
  uint8_t *data;
  uintptr_t data_len;
} MLSResult;

/**
 * Initialize the MLS FFI library
 * Returns a context handle for subsequent operations
 */
uintptr_t mls_init(void);

/**
 * Free an MLS context
 */
void mls_free_context(uintptr_t context_id);

/**
 * Create a new MLS group
 * Returns serialized group ID
 */
struct MLSResult mls_create_group(uintptr_t context_id,
                                  const uint8_t *identity_bytes,
                                  uintptr_t identity_len);

/**
 * Add members to an MLS group
 * Input: TLS-encoded KeyPackage bytes concatenated
 * Output: [commit_len_le: u64][commit_bytes][welcome_bytes]
 */
struct MLSResult mls_add_members(uintptr_t context_id,
                                 const uint8_t *group_id,
                                 uintptr_t group_id_len,
                                 const uint8_t *key_packages_bytes,
                                 uintptr_t key_packages_len);

/**
 * Encrypt a message for the group
 */
struct MLSResult mls_encrypt_message(uintptr_t context_id,
                                     const uint8_t *group_id,
                                     uintptr_t group_id_len,
                                     const uint8_t *plaintext,
                                     uintptr_t plaintext_len);

/**
 * Decrypt a message from the group
 */
struct MLSResult mls_decrypt_message(uintptr_t context_id,
                                     const uint8_t *group_id,
                                     uintptr_t group_id_len,
                                     const uint8_t *ciphertext,
                                     uintptr_t ciphertext_len);

/**
 * Create a key package for joining groups
 */
struct MLSResult mls_create_key_package(uintptr_t context_id,
                                        const uint8_t *identity_bytes,
                                        uintptr_t identity_len);

/**
 * Process a Welcome message to join a group
 */
struct MLSResult mls_process_welcome(uintptr_t context_id,
                                     const uint8_t *welcome_bytes,
                                     uintptr_t welcome_len,
                                     const uint8_t *_identity_bytes,
                                     uintptr_t _identity_len);

/**
 * Export a secret from the group's key schedule
 */
struct MLSResult mls_export_secret(uintptr_t context_id,
                                   const uint8_t *group_id,
                                   uintptr_t group_id_len,
                                   const char *label,
                                   const uint8_t *context_bytes,
                                   uintptr_t context_len,
                                   uintptr_t key_length);

/**
 * Get the current epoch of the group
 */
uint64_t mls_get_epoch(uintptr_t context_id, const uint8_t *group_id, uintptr_t group_id_len);

/**
 * Process a commit message and update group state
 * This is used for epoch synchronization - processing commits from other members
 * to keep the local group state up-to-date with the server's current epoch.
 *
 * # Arguments
 * * `context_id` - The MLS context handle
 * * `group_id` - The group identifier
 * * `commit_bytes` - TLS-encoded MlsMessage containing a commit
 *
 * # Returns
 * MLSResult with success=true if commit was processed successfully,
 * or success=false with error message on failure.
 */
struct MLSResult mls_process_commit(uintptr_t context_id,
                                    const uint8_t *group_id,
                                    uintptr_t group_id_len,
                                    const uint8_t *commit_bytes,
                                    uintptr_t commit_len);

/**
 * Free a result object
 */
void mls_free_result(struct MLSResult result);

/**
 * Get the last error message (for debugging)
 */
char *mls_get_last_error(void);

/**
 * Free an error message string
 */
void mls_free_string(char *s);

#endif /* MLS_FFI_H */
