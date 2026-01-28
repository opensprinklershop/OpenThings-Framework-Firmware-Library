#ifndef OTF_ESP32LOCALSERVER_CONFIG_H
#define OTF_ESP32LOCALSERVER_CONFIG_H

/**
 * @file Esp32LocalServer_Config.h
 * @brief Configuration and optimization settings for OpenThings Framework ESP32 multi-client support
 * 
 * This header provides compile-time configuration for:
 * - Connection pool management
 * - PSRAM usage and memory optimization
 * - Performance tuning and caching
 * - Debug settings
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

/** Enable round-robin client selection (load balancing) */
#ifndef OTF_ENABLE_ROUND_ROBIN
  #define OTF_ENABLE_ROUND_ROBIN 1
#endif

// ============================================================================
// PSRAM CONFIGURATION
// ============================================================================

/** Enable PSRAM usage for buffers and data structures (if available on ESP32) */
#ifndef OTF_USE_PSRAM
  #define OTF_USE_PSRAM 1
#endif

/** Use PSRAM for SSL/TLS context when available (increases number of concurrent HTTPS connections) */
#ifndef OTF_USE_PSRAM_FOR_SSL
  #define OTF_USE_PSRAM_FOR_SSL 1
#endif

/** Enable memory pool allocator using PSRAM for reduced fragmentation */
#ifndef OTF_ENABLE_PSRAM_POOL
  #define OTF_ENABLE_PSRAM_POOL 1  // Enabled for ESP32-C5 with 8MB PSRAM
#endif

// ============================================================================
// BUFFER CONFIGURATION
// ============================================================================

/** Size of read buffer per HTTP client (in bytes) */
#ifndef OTF_CLIENT_READ_BUFFER_SIZE
  #define OTF_CLIENT_READ_BUFFER_SIZE 4096
#endif

/** Size of write buffer per client (in bytes) */
#ifndef OTF_CLIENT_WRITE_BUFFER_SIZE
  #define OTF_CLIENT_WRITE_BUFFER_SIZE 8192
#endif

/** Enable write buffering to reduce fragmented writes */
#ifndef OTF_ENABLE_WRITE_BUFFERING
  #define OTF_ENABLE_WRITE_BUFFERING 1
#endif

/** Enable read-ahead caching for sequential reads */
#ifndef OTF_ENABLE_READ_CACHE
  #define OTF_ENABLE_READ_CACHE 1
#endif

// ============================================================================
// PERFORMANCE & OPTIMIZATION
// ============================================================================

/** Cache HTTP response headers to reduce parsing overhead */
#ifndef OTF_ENABLE_HEADER_CACHE
  #define OTF_ENABLE_HEADER_CACHE 1
#endif

/** Enable TCP_NODELAY (disable Nagle's algorithm) for low-latency responses */
#ifndef OTF_ENABLE_TCP_NODELAY
  #define OTF_ENABLE_TCP_NODELAY 1
#endif

/** Timeout for idle client connections (in milliseconds) */
#ifndef OTF_CLIENT_IDLE_TIMEOUT_MS
  #define OTF_CLIENT_IDLE_TIMEOUT_MS 30000  // 30 seconds
#endif

/** Enable connection keep-alive with periodic pings */
#ifndef OTF_ENABLE_KEEP_ALIVE
  #define OTF_ENABLE_KEEP_ALIVE 1
#endif

/** Keep-alive interval in milliseconds */
#ifndef OTF_KEEP_ALIVE_INTERVAL_MS
  #define OTF_KEEP_ALIVE_INTERVAL_MS 15000  // 15 seconds
#endif

// ============================================================================
// SSL/TLS OPTIMIZATION
// ============================================================================

/** Force TLS 1.3 only (disable TLS 1.2 for maximum security) */
#ifndef OTF_FORCE_TLS_1_3_ONLY
  #define OTF_FORCE_TLS_1_3_ONLY 1
#endif

/** Disable cipher suite configuration in code (use ESP-IDF config only) */
#ifndef OTF_USE_ESPIDF_CIPHER_CONFIG
  #define OTF_USE_ESPIDF_CIPHER_CONFIG 1
#endif

/** Use only hardware-accelerated AES cipher suites (GCM mode preferred) */
#ifndef OTF_USE_HW_ACCELERATED_CIPHERS_ONLY
  #define OTF_USE_HW_ACCELERATED_CIPHERS_ONLY 1
#endif

/** Maximum TLS record size to reduce memory pressure (bytes) */
#ifndef OTF_TLS_MAX_RECORD_SIZE
  #define OTF_TLS_MAX_RECORD_SIZE 4096
#endif

/** Enable session caching for TLS handshake optimization */
#ifndef OTF_ENABLE_TLS_SESSION_CACHE
  #define OTF_ENABLE_TLS_SESSION_CACHE 1
#endif

/** TLS session cache size (number of sessions) */
#ifndef OTF_TLS_SESSION_CACHE_SIZE
  #define OTF_TLS_SESSION_CACHE_SIZE 2
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

#if defined(CONFIG_IDF_TARGET_ESP32C5) || defined(CONFIG_IDF_TARGET_ESP32C3)
  // ESP32-C5/C3: Lower memory profile, optimize aggressively
  #undef OTF_MAX_CONCURRENT_CLIENTS
  #define OTF_MAX_CONCURRENT_CLIENTS 3
  
  #undef OTF_CLIENT_READ_BUFFER_SIZE
  #define OTF_CLIENT_READ_BUFFER_SIZE 2048
  
  #undef OTF_CLIENT_WRITE_BUFFER_SIZE
  #define OTF_CLIENT_WRITE_BUFFER_SIZE 4096
  
  #undef OTF_USE_PSRAM
  #define OTF_USE_PSRAM 0  // No PSRAM on C5/C3
  
#elif defined(CONFIG_IDF_TARGET_ESP32S3)
  // ESP32-S3: Has PSRAM, more generous configuration
  #undef OTF_MAX_CONCURRENT_CLIENTS
  #define OTF_MAX_CONCURRENT_CLIENTS 8
  
  #undef OTF_USE_PSRAM
  #define OTF_USE_PSRAM 1
  
  #undef OTF_ENABLE_PSRAM_POOL
  #define OTF_ENABLE_PSRAM_POOL 1
  
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
