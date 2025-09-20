/**
 * @file MbedTLSClient.cpp
 * @brief Implementation of the MbedTLSClient class.
 */

 #include "MbedTLSClient.h"
 #include "Arduino.h" // For Serial, millis(), delay()
 
 // To enable debugging, add the following to your platformio.ini:
 // build_flags = -DMBEDTLS_CLIENT_DEBUG
 #ifdef MBEDTLS_CLIENT_DEBUG
 #define MBEDTLS_LOG(format, ...) Serial.printf(format, ##__VA_ARGS__)
 #else
 #define MBEDTLS_LOG(format, ...)
 #endif

 #define TLS_YIELD() delay(20)
 
 /**
  * @brief Validates a PEM string and copies it into a managed buffer.
  * @param pem_string The PEM formatted string.
  * @param type A string describing the certificate type for logging (e.g., "CA cert").
  * @return A unique_ptr to the new buffer, or nullptr on failure.
  */
 static std::unique_ptr<char[]> prepare_pem_buffer(const char *pem_string, const char *type) {
     if (!pem_string || strlen(pem_string) == 0) {
         MBEDTLS_LOG("ERROR: Provided %s is null or empty.\n", type);
         return nullptr;
     }
     if (strstr(pem_string, "-----BEGIN") == nullptr || strstr(pem_string, "-----END") == nullptr) {
         MBEDTLS_LOG("ERROR: Invalid %s format: Missing '-----BEGIN' or '-----END' marker.\n", type);
         return nullptr;
     }
     size_t len = strlen(pem_string);
     auto buf = std::unique_ptr<char[]>(new char[len + 1]);
     memcpy(buf.get(), pem_sring, len);
     buf[len] = '\0';
     MBEDTLS_LOG("DEBUG: Successfully prepared %s buffer.\n", type);
     return buf;
 }
 
 MbedTLSClient::MbedTLSClient(Client &transport) : _transport(&transport) {
     mbedtls_ssl_init(&_ssl);
     mbedtls_ssl_config_init(&_conf);
     mbedtls_ctr_drbg_init(&_ctr_drbg);
     mbedtls_x509_crt_init(&_cacert);
     mbedtls_x509_crt_init(&_clicert);
     mbedtls_pk_init(&_pk);
     mbedtls_entropy_init(&_entropy);
 }
 
 MbedTLSClient::~MbedTLSClient() {
     stop();
     mbedtls_ctr_drbg_free(&_ctr_drbg);
     mbedtls_entropy_free(&_entropy);
 }
 
 // Frees SSL-specific resources to allow for reconnection.
 void MbedTLSClient::cleanup() {
     mbedtls_x509_crt_free(&_cacert);
     mbedtls_x509_crt_free(&_clicert);
     mbedtls_pk_free(&_pk);
     mbedtls_ssl_free(&_ssl);
     mbedtls_ssl_config_free(&_conf);
 
     mbedtls_ssl_init(&_ssl);
     mbedtls_ssl_config_init(&_conf);
     mbedtls_x509_crt_init(&_cacert);
     mbedtls_x509_crt_init(&_clicert);
     mbedtls_pk_init(&_pk);
 
     _handshake_state = HandshakeState::NOT_STARTED;
 }
 
 void MbedTLSClient::setCACert(const char *root_ca) {
     _ca_cert_buf = prepare_pem_buffer(root_ca, "CA cert");
 }
 
 void MbedTLSClient::setClientCert(const char *client_cert, const char *client_key) {
     _client_cert_buf = prepare_pem_buffer(client_cert, "Client cert");
     _client_key_buf = prepare_pem_buffer(client_key, "Client key");
 }
 
 void MbedTLSClient::setTimeout(uint32_t timeout_ms) {
     _timeout_ms = timeout_ms;
 }
 
 int MbedTLSClient::connect(const char *host, uint16_t port) {
     int ret;
 
     if (connected()) {
         stop();
     }
 
     if (!_ca_cert_buf) {
         MBEDTLS_LOG("ERROR: Cannot connect: CA Certificate is not set.\n");
         return 0;
     }
 
     if (!_transport->connect(host, port)) {
         MBEDTLS_LOG("ERROR: Underlying transport connection failed.\n");
         return 0;
     }
     MBEDTLS_LOG("INFO: Transport connected.\n");
 
     // Initialize mbedTLS context and configuration
     MBEDTLS_LOG("INFO: Setting up mbedTLS configuration...\n");
     mbedtls_ctr_drbg_seed(&_ctr_drbg, mbedtls_entropy_func, &_entropy, NULL, 0);
     mbedtls_ssl_config_defaults(&_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
 
     // Parse certificates and configure authentication
     mbedtls_x509_crt_parse(&_cacert, (const unsigned char *)_ca_cert_buf.get(), strlen(_ca_cert_buf.get()) + 1);
     mbedtls_ssl_conf_authmode(&_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
     mbedtls_ssl_conf_ca_chain(&_conf, &_cacert, NULL);
 
     if (_client_cert_buf && _client_key_buf) {
         mbedtls_x509_crt_parse(&_clicert, (const unsigned char *)_client_cert_buf.get(), strlen(_client_cert_buf.get()) + 1);
         mbedtls_pk_parse_key(&_pk, (const unsigned char *)_client_key_buf.get(), strlen(_client_key_buf.get()) + 1, NULL, 0);
         mbedtls_ssl_conf_own_cert(&_conf, &_clicert, &_pk);
     }
     mbedtls_ssl_conf_rng(&_conf, mbedtls_ctr_drbg_random, &_ctr_drbg);
     mbedtls_ssl_conf_read_timeout(&_conf, _timeout_ms);
 
     // Setup SSL context and BIO callbacks
     mbedtls_ssl_setup(&_ssl, &_conf);
     mbedtls_ssl_set_hostname(&_ssl, host);
     mbedtls_ssl_set_bio(&_ssl, this, ssl_send, ssl_recv, NULL);
 
     // Perform the TLS handshake in a blocking manner
     MBEDTLS_LOG("INFO: Starting TLS handshake (blocking)...\n");
     _handshake_state = HandshakeState::IN_PROGRESS;
     unsigned long start_time = millis();
     while (_handshake_state == HandshakeState::IN_PROGRESS) {
         ret = mbedtls_ssl_handshake(&_ssl);
         if (ret == 0) {
             _handshake_state = HandshakeState::COMPLETED;
             break; // Success
         } else if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
             char error_buf[100];
             mbedtls_strerror(ret, error_buf, sizeof(error_buf));
             MBEDTLS_LOG("ERROR: mbedtls_ssl_handshake failed: -0x%x : %s\n", -ret, error_buf);
             _handshake_state = HandshakeState::FAILED;
             stop();
             return 0;
         }
         if (millis() - start_time > _timeout_ms) {
             MBEDTLS_LOG("ERROR: TLS handshake timed out.\n");
             _handshake_state = HandshakeState::FAILED;
             stop();
             return 0;
         }

         TLS_YIELD();
     }
 
     // Verify the server certificate post-handshake
     if (_handshake_state == HandshakeState::COMPLETED) {
         MBEDTLS_LOG("INFO: TLS handshake successful!\n");
         if (mbedtls_ssl_get_verify_result(&_ssl) != 0) {
             char vrfy_buf[512];
             mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", mbedtls_ssl_get_verify_result(&_ssl));
             MBEDTLS_LOG("ERROR: Server certificate verification failed:\n%s\n", vrfy_buf);
             _handshake_state = HandshakeState::FAILED;
             stop();
             return 0;
         }
         MBEDTLS_LOG("INFO: Server certificate verified.\n");
         return 1; // SUCCESS
     }
     return 0;
 }
 
 int MbedTLSClient::connect(IPAddress ip, uint16_t port) {
     return connect(ip.toString().c_str(), port);
 }
 
 size_t MbedTLSClient::write(const uint8_t *buf, size_t size) {
     if (!connected()) return 0;
 
     size_t written = 0;
     unsigned long start_time = millis();
     while (written < size) {
         int ret = mbedtls_ssl_write(&_ssl, buf + written, size - written);
         if (ret > 0) {
             written += ret;
             start_time = millis(); // Reset timeout on progress
         } else if (ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_WANT_READ) {
             MBEDTLS_LOG("ERROR: mbedtls_ssl_write failed: -0x%x\n", -ret);
             stop();
             return 0;
         }
 
         // If transport buffer is full (WANT_WRITE), yield to the network stack.
         TLS_YIELD();
 
         if (millis() - start_time > _timeout_ms) {
             MBEDTLS_LOG("ERROR: TLS write timed out.\n");
             stop();
             return 0;
         }
     }
     return written;
 }
 
 size_t MbedTLSClient::write(uint8_t b) {
     return write(&b, 1);
 }
 
 int MbedTLSClient::available() {
     if (!connected()) return 0;
 
     // Check for data already decrypted and buffered by mbedTLS.
     if (mbedtls_ssl_get_bytes_avail(&_ssl) > 0) {
         return mbedtls_ssl_get_bytes_avail(&_ssl);
     }
 
     // If no data is buffered, proactively poll the transport for new TLS records.
     // This is critical for compatibility with libraries that check available() before read().
     int ret = mbedtls_ssl_read(&_ssl, NULL, 0);
     if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
         MBEDTLS_LOG("WARN: available() detected connection error: -0x%x\n", -ret);
         stop();
         return 0;
     }
 
     return mbedtls_ssl_get_bytes_avail(&_ssl);
 }
 
 int MbedTLSClient::read(uint8_t *buf, size_t size) {
     if (!connected() || size == 0) return -1;
 
     unsigned long start_time = millis();
     // This loop makes the read() call blocking, as expected by the Arduino Client API.
     while (connected()) {
         int ret = mbedtls_ssl_read(&_ssl, buf, size);
         if (ret > 0) {
             return ret; // Success
         }
         if (ret == 0 || (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)) {
             MBEDTLS_LOG("INFO: mbedtls_ssl_read failed or connection closed: -0x%x\n", -ret);
             stop();
             return -1;
         }
         if (millis() - start_time > _timeout_ms) {
             MBEDTLS_LOG("ERROR: TLS read timed out.\n");
             return -1;
         }
         TLS_YIELD(); // Yield while waiting for data
     }
     return -1;
 }
 
 int MbedTLSClient::read() {
     uint8_t b;
     return (read(&b, 1) > 0) ? (int)b : -1;
 }
 
 void MbedTLSClient::stop() {
     if (_transport && _transport->connected()) {
         MBEDTLS_LOG("INFO: Closing TLS connection.\n");
         mbedtls_ssl_close_notify(&_ssl); // Send TLS close alert
         _transport->stop();
     }
     cleanup();
 }
 
 uint8_t MbedTLSClient::connected() {
     // True only if the underlying transport is connected AND the TLS handshake is complete.
     return _transport && _transport->connected() && _handshake_state == HandshakeState::COMPLETED;
 }
 
 int MbedTLSClient::peek() {
     return -1;
 }
 
 void MbedTLSClient::flush() {
     if (connected()) {
         _transport->flush();
     }
 }
 
 MbedTLSClient::operator bool() {
     return connected();
 }
 
 int MbedTLSClient::ssl_send(void *ctx, const unsigned char *buf, size_t len) {
     MbedTLSClient *client = static_cast<MbedTLSClient *>(ctx);
     
     // Modem and other constrained transports have small send buffers. To avoid
     // overwhelming them, we fragment the data mbedTLS wants to send into smaller,
     // manageable chunks. This prevents transport write failures and timeouts.
     const size_t max_fragment_size = 256;
     size_t sent = 0;
     while (sent < len) {
         size_t chunk_size = len - sent;
         if (chunk_size > max_fragment_size) {
             chunk_size = max_fragment_size;
         }
         int ret = client->_transport->write(buf + sent, chunk_size);
         if (ret > 0) {
             sent += ret;
         } else if (ret == 0) {
             // Transport buffer is full. If we sent nothing, report WANT_WRITE.
             // Otherwise, return what we did send and mbedTLS will call again for the rest.
             return (sent == 0) ? MBEDTLS_ERR_SSL_WANT_WRITE : sent;
         } else {
             return MBEDTLS_ERR_SSL_WANT_WRITE; // Transport-level error
         }
     }
     return sent;
 }
 
 int MbedTLSClient::ssl_recv(void *ctx, unsigned char *buf, size_t len) {
     MbedTLSClient *client = static_cast<MbedTLSClient *>(ctx);
     if (client->_transport->available() == 0) {
         return MBEDTLS_ERR_SSL_WANT_READ;
     }
     int ret = client->_transport->read(buf, len);
     if (ret <= 0) {
         return MBEDTLS_ERR_SSL_WANT_READ;
     }
     return ret;
 }
 
 