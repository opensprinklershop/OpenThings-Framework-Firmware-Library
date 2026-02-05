#ifndef OTF_ESP32LOCALSERVER_CONFIG_H
#define OTF_ESP32LOCALSERVER_CONFIG_H

/**
 * @file Esp32LocalServer_Config.h
 * @brief Configuration for OpenThings Framework ESP32 multi-client support
 * 
 * Simplified configuration - PSRAM allocation handled by global malloc override.
 * See psram_utils.cpp for memory management details.
 */

// ============================================================================
// CONNECTION POOL CONFIGURATION
// ============================================================================

/** Maximum number of simultaneous TCP connections allowed */
#ifndef OTF_MAX_CONCURRENT_CLIENTS
  #define OTF_MAX_CONCURRENT_CLIENTS 4
#endif

/** Size of the connection pool (should be >= OTF_MAX_CONCURRENT_CLIENTS) */
#ifndef OTF_CLIENT_POOL_SIZE
  #define OTF_CLIENT_POOL_SIZE 6
#endif

// ============================================================================
// BUFFER CONFIGURATION
// ============================================================================

/** Size of read buffer per HTTP client (in bytes) - allocated in PSRAM via global malloc */
#ifndef OTF_CLIENT_READ_BUFFER_SIZE
  #define OTF_CLIENT_READ_BUFFER_SIZE 4096
#endif

/** Size of write buffer per client (in bytes) - allocated in PSRAM via global malloc */
#ifndef OTF_CLIENT_WRITE_BUFFER_SIZE
  #define OTF_CLIENT_WRITE_BUFFER_SIZE 8192
#endif

// ============================================================================
// PERFORMANCE & OPTIMIZATION
// ============================================================================

/** Timeout for idle client connections (in milliseconds) */
#ifndef OTF_CLIENT_IDLE_TIMEOUT_MS
  #define OTF_CLIENT_IDLE_TIMEOUT_MS 30000  // 30 seconds
#endif

/** SSL/TLS handshake timeout (milliseconds) */
#ifndef OTF_SSL_HANDSHAKE_TIMEOUT_MS
  #define OTF_SSL_HANDSHAKE_TIMEOUT_MS 5000
#endif

// ============================================================================
// DEBUG & MONITORING
// ============================================================================

/** Enable detailed memory allocation logging */
#ifndef OTF_DEBUG_MEMORY
  #define OTF_DEBUG_MEMORY 0
#endif

/** Enable connection pool monitoring logs */
#ifndef OTF_DEBUG_CONNECTION_POOL
  #define OTF_DEBUG_CONNECTION_POOL 0
#endif

/** Enable TLS handshake debug logging */
#ifndef OTF_DEBUG_TLS_HANDSHAKE
  #define OTF_DEBUG_TLS_HANDSHAKE 0
#endif

/** Monitor client connection/disconnection events */
#ifndef OTF_DEBUG_CLIENT_LIFECYCLE
  #define OTF_DEBUG_CLIENT_LIFECYCLE 1
#endif

// ============================================================================
// PLATFORM-SPECIFIC CONFIGURATION
// ============================================================================

#if defined(CONFIG_IDF_TARGET_ESP32C5)
  // ESP32-C5: 8MB PSRAM via global malloc override
  #undef OTF_MAX_CONCURRENT_CLIENTS
  #define OTF_MAX_CONCURRENT_CLIENTS 6
  
  #undef OTF_CLIENT_READ_BUFFER_SIZE
  #define OTF_CLIENT_READ_BUFFER_SIZE 8192
  
  #undef OTF_CLIENT_WRITE_BUFFER_SIZE
  #define OTF_CLIENT_WRITE_BUFFER_SIZE 16384
  
#elif defined(CONFIG_IDF_TARGET_ESP32C3)
  // ESP32-C3: No PSRAM - keep buffers small
  #undef OTF_MAX_CONCURRENT_CLIENTS
  #define OTF_MAX_CONCURRENT_CLIENTS 3
  
  #undef OTF_CLIENT_READ_BUFFER_SIZE
  #define OTF_CLIENT_READ_BUFFER_SIZE 2048
  
  #undef OTF_CLIENT_WRITE_BUFFER_SIZE
  #define OTF_CLIENT_WRITE_BUFFER_SIZE 4096
  
#elif defined(CONFIG_IDF_TARGET_ESP32S3)
  // ESP32-S3: PSRAM available via global malloc
  #undef OTF_MAX_CONCURRENT_CLIENTS
  #define OTF_MAX_CONCURRENT_CLIENTS 8
  
#elif defined(CONFIG_IDF_TARGET_ESP32)
  // Standard ESP32: Default configuration
  #undef OTF_MAX_CONCURRENT_CLIENTS
  #define OTF_MAX_CONCURRENT_CLIENTS 4
#endif

// ============================================================================
// VALIDATION & DEFAULTS
// ============================================================================

// Ensure pool size >= max clients
#if OTF_CLIENT_POOL_SIZE < OTF_MAX_CONCURRENT_CLIENTS
  #undef OTF_CLIENT_POOL_SIZE
  #define OTF_CLIENT_POOL_SIZE (OTF_MAX_CONCURRENT_CLIENTS + 2)
#endif

#endif /* OTF_ESP32LOCALSERVER_CONFIG_H */
