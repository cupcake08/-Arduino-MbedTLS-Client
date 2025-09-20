/**
 * @file MbedTLSClient.h
 * @author Ankit Bhankharia
 * @brief Provides a TLS/SSL wrapper for any Arduino Client object using mbedTLS.
 * @version 1.1.0
 * @date 2025-09-20
 *
 * @copyright Copyright (c) 2025
 *
 * This class implements the Arduino Client interface and provides a secure TLS 1.2
 * layer on top of an existing, non-secure transport Client (like WiFiClient,
 * EthernetClient, or TinyGsmClient). It is designed for platforms like the ESP32
 * that have a built-in mbedTLS library.
 */

 #ifndef MBEDTLS_CLIENT_H
 #define MBEDTLS_CLIENT_H
 
 #include "Client.h"
 #include <memory>
 
 // mbedTLS headers (typically provided by the board's core framework)
 #include "mbedtls/platform.h"
 #include "mbedtls/ssl.h"
 #include "mbedtls/entropy.h"
 #include "mbedtls/ctr_drbg.h"
 #include "mbedtls/error.h"
 #include "mbedtls/x509_crt.h"
 #include "mbedtls/pk.h"
 
 /**
  * @class MbedTLSClient
  * @brief A TLS/SSL Client wrapper for Arduino.
  *
  * This class acts as a secure layer, taking an existing Client object that handles
  * the underlying TCP connection and adding TLS encryption on top. It implements the
  * standard Arduino Client interface, making it a drop-in replacement for insecure
  * clients when connecting to secure services (e.g., MQTT over TLS, HTTPS).
  */
 class MbedTLSClient : public Client {
 public:
     /**
      * @brief Construct a new MbedTLSClient object.
      * @param transport A reference to the underlying network client (e.g., WiFiClient).
      * This object must remain in scope for the lifetime of the MbedTLSClient.
      */
     MbedTLSClient(Client &transport);
 
     /**
      * @brief Destroy the MbedTLSClient object, freeing all mbedTLS resources.
      */
     ~MbedTLSClient();
 
     // --- Configuration Methods ---
 
     /**
      * @brief Sets the Root CA certificate for server verification.
      * @param root_ca A null-terminated string containing the server's root CA in PEM format.
      * This is required for verifying the server's identity.
      */
     void setCACert(const char *root_ca);
 
     /**
      * @brief Sets the client certificate and private key for mutual authentication (mTLS).
      * @param client_cert A null-terminated string containing the client certificate in PEM format.
      * @param client_key A null-terminated string containing the client's private key in PEM format.
      */
     void setClientCert(const char *client_cert, const char *client_key);
 
     /**
      * @brief Sets the timeout for the TLS handshake and read operations.
      * @param timeout_ms The timeout duration in milliseconds. Defaults to 30000 (30 seconds).
      */
     void setTimeout(uint32_t timeout_ms);
 
     // --- Arduino Client API Implementation ---
 
     /**
      * @brief Establishes a secure TLS connection to a server.
      * @param ip The IP address of the server.
      * @param port The port to connect to.
      * @return 1 on success, 0 on failure.
      */
     int connect(IPAddress ip, uint16_t port) override;
 
     /**
      * @brief Establishes a secure TLS connection to a server.
      * @param host The hostname of the server. The hostname is used for Server Name Indication (SNI).
      * @param port The port to connect to.
      * @return 1 on success, 0 on failure.
      */
     int connect(const char *host, uint16_t port) override;
 
     /**
      * @brief Writes a single byte to the secure stream.
      * @param b The byte to write.
      * @return The number of bytes written (1 on success, 0 on failure).
      */
     size_t write(uint8_t b) override;
 
     /**
      * @brief Writes a buffer of bytes to the secure stream.
      * @param buf Pointer to the buffer to write.
      * @param size The number of bytes to write from the buffer.
      * @return The number of bytes written.
      */
     size_t write(const uint8_t *buf, size_t size) override;
 
     /**
      * @brief Checks how many decrypted bytes are available to be read.
      *
      * @details This method proactively tries to read from the underlying transport
      * to decrypt new data if the internal buffer is empty. This is crucial
      * for compatibility with libraries like PubSubClient.
      * @return The number of bytes available to read.
      */
     int available() override;
 
     /**
      * @brief Reads a single byte from the secure stream.
      * @return The byte read, or -1 if no data is available.
      */
     int read() override;
 
     /**
      * @brief Reads a specified number of bytes from the secure stream into a buffer.
      *
      * @details This is a blocking call that will wait until data is available or a
      * timeout occurs.
      * @param buf Pointer to the buffer to store the read data.
      * @param size The maximum number of bytes to read.
      * @return The number of bytes read, or -1 on error.
      */
     int read(uint8_t *buf, size_t size) override;
 
     /**
      * @brief Peeks at the next available byte without consuming it.
      * @note Not currently implemented.
      * @return -1
      */
     int peek() override;
 
     /**
      * @brief Flushes the underlying transport stream.
      */
     void flush() override;
 
     /**
      * @brief Closes the TLS connection and the underlying transport.
      */
     void stop() override;
 
     /**
      * @brief Checks if the client is connected and the TLS handshake is complete.
      * @return 1 if connected, 0 otherwise.
      */
     uint8_t connected() override;
 
     /**
      * @brief Boolean operator to check connection status.
      * @return true if connected, false otherwise.
      */
     operator bool() override;
 
 private:
     /**
      * @brief Frees all allocated mbedTLS resources and re-initializes contexts.
      * Called by stop() and the destructor.
      */
     void cleanup();
 
     /**
      * @enum HandshakeState
      * @brief Manages the state of the TLS handshake process.
      */
     enum class HandshakeState {
         NOT_STARTED,
         IN_PROGRESS,
         COMPLETED,
         FAILED
     };
 
     Client *_transport;
     uint32_t _timeout_ms = 30000;
     HandshakeState _handshake_state = HandshakeState::NOT_STARTED;
 
     // mbedTLS context structures
     mbedtls_entropy_context _entropy;
     mbedtls_ctr_drbg_context _ctr_drbg;
     mbedtls_ssl_context _ssl;
     mbedtls_ssl_config _conf;
     mbedtls_x509_crt _cacert;
     mbedtls_x509_crt _clicert;
     mbedtls_pk_context _pk;
 
     // Smart pointers for securely managing certificate buffers
     std::unique_ptr<char[]> _ca_cert_buf;
     std::unique_ptr<char[]> _client_cert_buf;
     std::unique_ptr<char[]> _client_key_buf;
 
     /**
      * @brief mbedTLS BIO (Blocking I/O) send callback.
      * This static function is registered with mbedTLS to handle sending encrypted data.
      * It bridges mbedTLS's output to the underlying transport's write() method.
      */
     static int ssl_send(void *ctx, const unsigned char *buf, size_t len);
 
     /**
      * @brief mbedTLS BIO (Blocking I/O) receive callback.
      * This static function is registered with mbedTLS to handle receiving encrypted data.
      * It bridges the underlying transport's read() method to mbedTLS's input.
      */
     static int ssl_recv(void *ctx, unsigned char *buf, size_t len);
 };
 
 #endif // MBEDTLS_CLIENT_H
 