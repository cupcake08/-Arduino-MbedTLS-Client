/**
 * @file MbedTLSClient.cpp
 * @brief Implementation of the MbedTLSClient class.
 */

 #include "MbedTLSClient.h"
 #include "Arduino.h" // For Serial, millis(), delay()
 
 // To enable debugging, add the following to your platformio.ini:
 // build_flags = -DMBEDTLS_CLIENT_DEBUG
 #ifdef MBEDTLS_CLIENT_DEBUG
   // ANSI Color Codes for "pretty" logging
   #define MBEDTLS_CLIENT_COLOR_RED     "\x1b[31m"
   #define MBEDTLS_CLIENT_COLOR_GREEN   "\x1b[32m"
   #define MBEDTLS_CLIENT_COLOR_YELLOW  "\x1b[33m"
   #define MBEDTLS_CLIENT_COLOR_CYAN    "\x1b[36m"
   #define MBEDTLS_CLIENT_COLOR_RESET   "\x1b[0m"
 
   // Formatted logging macros with log levels
   #define MBEDTLS_LOG_E(format, ...) Serial.printf(MBEDTLS_CLIENT_COLOR_RED   "[TLS-E] " format MBEDTLS_CLIENT_COLOR_RESET "\n", ##__VA_ARGS__)
   #define MBEDTLS_LOG_W(format, ...) Serial.printf(MBEDTLS_CLIENT_COLOR_YELLOW "[TLS-W] " format MBEDTLS_CLIENT_COLOR_RESET "\n", ##__VA_ARGS__)
   #define MBEDTLS_LOG_I(format, ...) Serial.printf(MBEDTLS_CLIENT_COLOR_CYAN   "[TLS-I] " format MBEDTLS_CLIENT_COLOR_RESET "\n", ##__VA_ARGS__)
   #define MBEDTLS_LOG_D(format, ...) Serial.printf("[TLS-D] " format "\n", ##__VA_ARGS__)
 #else
   // If debugging is disabled, macros do nothing
   #define MBEDTLS_LOG_E(format, ...)
   #define MBEDTLS_LOG_W(format, ...)
   #define MBEDTLS_LOG_I(format, ...)
   #define MBEDTLS_LOG_D(format, ...)
 #endif
 
 /**
  * @brief Validates a PEM string and copies it into a managed buffer.
  * @param pem_string The PEM formatted string.
  * @param type A string describing the certificate type for logging (e.g., "CA cert").
  * @return A unique_ptr to the new buffer, or nullptr on failure.
  */
 static std::unique_ptr<char[]> prepare_pem_buffer(const char *pem_string, const char *type) {
     if (!pem_string || strlen(pem_string) == 0) {
         MBEDTLS_LOG_E("Provided %s is null or empty.", type);
         return nullptr;
     }
     if (strstr(pem_string, "-----BEGIN") == nullptr || strstr(pem_string, "-----END") == nullptr) {
         MBEDTLS_LOG_E("Invalid %s format: Missing '-----BEGIN' or '-----END' marker.", type);
         return nullptr;
     }
     size_t len = strlen(pem_string);
     auto buf = std::unique_ptr<char[]>(new char[len + 1]);
     memcpy(buf.get(), pem_string, len);
     buf[len] = '\0';
     MBEDTLS_LOG_D("Successfully prepared %s buffer.", type);
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
     if (connected()) stop();
 
     if (!_ca_cert_buf) {
         MBEDTLS_LOG_E("Cannot connect: CA Certificate is not set.");
         return 0;
     }
 
     if (!_transport->connect(host, port)) {
         MBEDTLS_LOG_E("Underlying transport connection failed.");
         return 0;
     }
     MBEDTLS_LOG_I("Transport connected.");
     MBEDTLS_LOG_I("Setting up mbedTLS configuration...");
     mbedtls_ctr_drbg_seed(&_ctr_drbg, mbedtls_entropy_func, &_entropy, NULL, 0);
     mbedtls_ssl_config_defaults(&_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
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
     mbedtls_ssl_setup(&_ssl, &_conf);
     mbedtls_ssl_set_hostname(&_ssl, host);
     mbedtls_ssl_set_bio(&_ssl, this, ssl_send, ssl_recv, NULL);
 
     MBEDTLS_LOG_I("Starting TLS handshake (blocking)...");
     _handshake_state = HandshakeState::IN_PROGRESS;
     unsigned long start_time = millis();
     while (_handshake_state == HandshakeState::IN_PROGRESS) {
         ret = mbedtls_ssl_handshake(&_ssl);
         if (ret == 0) {
             _handshake_state = HandshakeState::COMPLETED;
             break;
         } else if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
             char error_buf[100];
             mbedtls_strerror(ret, error_buf, sizeof(error_buf));
             MBEDTLS_LOG_E("mbedtls_ssl_handshake failed: -0x%x : %s", -ret, error_buf);
             _handshake_state = HandshakeState::FAILED;
             stop();
             return 0;
         }
         if (millis() - start_time > _timeout_ms) {
             MBEDTLS_LOG_E("TLS handshake timed out.");
             _handshake_state = HandshakeState::FAILED;
             stop();
             return 0;
         }
         delay(10);
     }
 
     if (_handshake_state == HandshakeState::COMPLETED) {
         MBEDTLS_LOG_I("TLS handshake successful!");
         if (mbedtls_ssl_get_verify_result(&_ssl) != 0) {
             char vrfy_buf[512];
             mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", mbedtls_ssl_get_verify_result(&_ssl));
             MBEDTLS_LOG_E("Server certificate verification failed:\n%s", vrfy_buf);
             _handshake_state = HandshakeState::FAILED;
             stop();
             return 0;
         }
         MBEDTLS_LOG_I("Server certificate verified.");
         return 1;
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
             start_time = millis();
         } else if (ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_WANT_READ) {
             MBEDTLS_LOG_E("mbedtls_ssl_write failed: -0x%x", -ret);
             stop();
             return 0;
         }
         delay(10);
         if (millis() - start_time > _timeout_ms) {
             MBEDTLS_LOG_E("TLS write timed out.");
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
     if (mbedtls_ssl_get_bytes_avail(&_ssl) > 0) {
         return mbedtls_ssl_get_bytes_avail(&_ssl);
     }
     int ret = mbedtls_ssl_read(&_ssl, NULL, 0);
     if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
         MBEDTLS_LOG_W("available() detected connection error: -0x%x", -ret);
         stop();
         return 0;
     }
     return mbedtls_ssl_get_bytes_avail(&_ssl);
 }
 
 int MbedTLSClient::read(uint8_t *buf, size_t size) {
     if (!connected() || size == 0) return -1;
     unsigned long start_time = millis();
     while (connected()) {
         int ret = mbedtls_ssl_read(&_ssl, buf, size);
         if (ret > 0) return ret;
         if (ret == 0 || (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)) {
             MBEDTLS_LOG_I("mbedtls_ssl_read failed or connection closed: -0x%x", -ret);
             stop();
             return -1;
         }
         if (millis() - start_time > _timeout_ms) {
             MBEDTLS_LOG_E("TLS read timed out.");
             return -1;
         }
         delay(10);
     }
     return -1;
 }
 
 int MbedTLSClient::read() {
     uint8_t b;
     return (read(&b, 1) > 0) ? (int)b : -1;
 }
 
 void MbedTLSClient::stop() {
     if (_transport && _transport->connected()) {
         MBEDTLS_LOG_I("Closing TLS connection.");
         mbedtls_ssl_close_notify(&_ssl);
         _transport->stop();
     }
     cleanup();
 }
 
 uint8_t MbedTLSClient::connected() {
     return _transport && _transport->connected() && _handshake_state == HandshakeState::COMPLETED;
 }
 
 int MbedTLSClient::peek() { return -1; }
 void MbedTLSClient::flush() { if (connected()) _transport->flush(); }
 MbedTLSClient::operator bool() { return connected(); }
 
 int MbedTLSClient::ssl_send(void *ctx, const unsigned char *buf, size_t len) {
     MbedTLSClient *client = static_cast<MbedTLSClient *>(ctx);
     const size_t max_fragment_size = 256;
     size_t sent = 0;
     while (sent < len) {
         size_t chunk_size = len - sent;
         if (chunk_size > max_fragment_size) chunk_size = max_fragment_size;
         int ret = client->_transport->write(buf + sent, chunk_size);
         if (ret > 0) {
             sent += ret;
         } else if (ret == 0) {
             return (sent == 0) ? MBEDTLS_ERR_SSL_WANT_WRITE : sent;
         } else {
             return MBEDTLS_ERR_SSL_WANT_WRITE;
         }
     }
     return sent;
 }
 
 int MbedTLSClient::ssl_recv(void *ctx, unsigned char *buf, size_t len) {
     MbedTLSClient *client = static_cast<MbedTLSClient *>(ctx);
     if (client->_transport->available() == 0) return MBEDTLS_ERR_SSL_WANT_READ;
     int ret = client->_transport->read(buf, len);
     if (ret <= 0) return MBEDTLS_ERR_SSL_WANT_READ;
     return ret;
 }
 
 