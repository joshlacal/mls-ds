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
 * Contains success status, error message, and data buffer
 */
typedef struct MLSResult {
  bool success;
  char *error_message;
  uint8_t *data;
  uintptr_t data_len;
} MLSResult;

/**
 * Initialize the MLS FFI library
 * Returns a context handle (non-zero on success, 0 on failure)
 */
uintptr_t mls_init(void);

/**
 * Free an MLS context and all associated resources
 */
void mls_free_context(uintptr_t context_id);

/**
 * Create a new MLS group
 * Parameters:
 *   - context_id: MLS context handle
 *   - identity_bytes: User identity (email, username, etc.)
 *   - identity_len: Length of identity bytes
 * Returns: MLSResult containing group ID on success
 */
struct MLSResult mls_create_group(uintptr_t context_id,
                                  const uint8_t *identity_bytes,
                                  uintptr_t identity_len);

/**
 * Add members to an existing MLS group
 * Parameters:
 *   - context_id: MLS context handle
 *   - group_id: Group identifier
 *   - group_id_len: Length of group ID
 *   - key_packages_bytes: Serialized key packages of members to add
 *   - key_packages_len: Length of key packages data
 * Returns: MLSResult containing commit and welcome messages
 */
struct MLSResult mls_add_members(uintptr_t context_id,
                                 const uint8_t *group_id,
                                 uintptr_t group_id_len,
                                 const uint8_t *key_packages_bytes,
                                 uintptr_t key_packages_len);

/**
 * Encrypt a message for the group
 * Parameters:
 *   - context_id: MLS context handle
 *   - group_id: Group identifier
 *   - group_id_len: Length of group ID
 *   - plaintext: Message to encrypt
 *   - plaintext_len: Length of plaintext
 * Returns: MLSResult containing encrypted message
 */
struct MLSResult mls_encrypt_message(uintptr_t context_id,
                                     const uint8_t *group_id,
                                     uintptr_t group_id_len,
                                     const uint8_t *plaintext,
                                     uintptr_t plaintext_len);

/**
 * Decrypt a message from the group
 * Parameters:
 *   - context_id: MLS context handle
 *   - group_id: Group identifier
 *   - group_id_len: Length of group ID
 *   - ciphertext: Encrypted message
 *   - ciphertext_len: Length of ciphertext
 * Returns: MLSResult containing decrypted message
 */
struct MLSResult mls_decrypt_message(uintptr_t context_id,
                                     const uint8_t *group_id,
                                     uintptr_t group_id_len,
                                     const uint8_t *ciphertext,
                                     uintptr_t ciphertext_len);

/**
 * Create a key package for joining groups
 * Parameters:
 *   - context_id: MLS context handle
 *   - identity_bytes: User identity
 *   - identity_len: Length of identity
 * Returns: MLSResult containing serialized key package
 */
struct MLSResult mls_create_key_package(uintptr_t context_id,
                                        const uint8_t *identity_bytes,
                                        uintptr_t identity_len);

/**
 * Process a Welcome message to join a group
 * Parameters:
 *   - context_id: MLS context handle
 *   - welcome_bytes: Serialized Welcome message
 *   - welcome_len: Length of Welcome message
 *   - identity_bytes: User identity
 *   - identity_len: Length of identity
 * Returns: MLSResult containing group ID
 */
struct MLSResult mls_process_welcome(uintptr_t context_id,
                                     const uint8_t *welcome_bytes,
                                     uintptr_t welcome_len,
                                     const uint8_t *identity_bytes,
                                     uintptr_t identity_len);

/**
 * Export a secret from the group's key schedule
 * Parameters:
 *   - context_id: MLS context handle
 *   - group_id: Group identifier
 *   - group_id_len: Length of group ID
 *   - label: Label for the exported secret (null-terminated string)
 *   - context_bytes: Context data for secret derivation
 *   - context_len: Length of context data
 *   - key_length: Desired length of exported secret
 * Returns: MLSResult containing exported secret
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
 * Parameters:
 *   - context_id: MLS context handle
 *   - group_id: Group identifier
 *   - group_id_len: Length of group ID
 * Returns: Epoch number (0 on error)
 */
uint64_t mls_get_epoch(uintptr_t context_id, const uint8_t *group_id, uintptr_t group_id_len);

/**
 * Free a result object and its associated memory
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
