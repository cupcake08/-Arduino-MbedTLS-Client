# MbedTLSClient for Arduino

<!-- [![PlatformIO Registry](https://img.shields.io/badge/PlatformIO-Registry-orange)](https://registry.platformio.org/libraries/cupcake08/MbedTLSClient) -->
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A straightforward TLS/SSL client for Arduino platforms (like ESP32) that have a built-in mbedTLS library. It's designed to wrap any underlying Arduino `Client` object (e.g., `WiFiClient`, `EthernetClient`, `TinyGsmClient`) to provide a secure TLS 1.2 connection.

This library is ideal for connecting to secure services like MQTT brokers or HTTPS APIs when you need client certificate authentication.

## ✨ Features

-   **Wraps any `Client`:** Provides a TLS layer for `WiFiClient`, `EthernetClient`, `TinyGsmClient`, and more.
-   **Simple API:** Mimics the standard Arduino `Client` API for easy integration.
-   **Based on mbedTLS:** Leverages the robust and memory-efficient mbedTLS library included with frameworks like ESP-IDF.
-   **Client Certificate Authentication:** Easily configure a client certificate and private key for mutual TLS (mTLS) authentication.
-   **Non-Blocking Compatible:** Designed to work correctly with libraries like `PubSubClient` that have their own connection and timeout logic.
-   **Configurable Debugging:** Enable detailed logging via a simple build flag.

## ⚙️ Installation

### PlatformIO

This library can be installed by adding its GitHub repository URL to your project's `platformio.ini` file.

```ini
lib_deps = 
    https://github.com/cupcake08/Arduino-MbedTLS-Client.git
```

## 🚀 Usage
The library acts as a "wrapper." You first create your standard network client (like a WiFiClient) and then pass it to the `MbedTLSClient` constructor. You then use the ` MbedTLSClient` object just like you would any other Client.

```ino
#include <WiFi.h>
#include "MbedTLSClient.h"
#include "PubSubClient.h"

// Your network credentials
const char* ssid = "YourSSID";
const char* password = "YourPassword";

// Your server and certificates 
const char* mqtt_server = "your_mqtt_broker.com";
const char* root_ca = "-----BEGIN CERTIFICATE-----\n...";
const char* client_cert = "-----BEGIN CERTIFICATE-----\n...";
const char* client_key = "-----BEGIN RSA PRIVATE KEY-----\n...";

// 1. Create the underlying transport client
WiFiClient wifiClient;

// 2. Wrap it with the MbedTLSClient
MbedTLSClient tlsClient(wifiClient);

// 3. Use the secure client with other libraries
PubSubClient pubSubClient(tlsClient);

void setup() {
  Serial.begin(115200);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  // 4. Configure the TLS client with certificates
  tlsClient.setCACert(root_ca);
  tlsClient.setClientCert(client_cert, client_key);

  // 5. Connect using the PubSubClient (which will use tlsClient.connect)
  pubSubClient.setServer(mqtt_server, 8883);
  if (pubSubClient.connect("my-esp32-client")) {
    Serial.println("Connected to MQTT broker!");
    pubSubClient.publish("esp32/status", "online");
  } else {
    Serial.print("MQTT connection failed, state: ");
    Serial.println(pubSubClient.state());
  }
}

void loop() {
  pubSubClient.loop();
}
```

## 📜 API

- `MbedTLSClient(Client &transport)`: Constructor. Takes a reference to the underlying transport client.
- `void setCACert(const char *root_ca)`: Sets the PEM-formatted CA certificate to verify the server.
- `void setClientCert(const char *client_cert, const char *client_key)`: Sets the PEM-formatted client certificate and private key for client authentication.
- `void setTimeout(uint32_t timeout_ms)`: Sets the timeout for the TLS handshake and read operations (in milliseconds). Default is 30000.
- Standard Client methods (`connect`, `write`, `read`, `available`, `connected`, `stop`) are all implemented.

## 🐞 Debugging
To enable verbose logging from the library, add the following build flag to your `platformio.ini`:
```ini
build_flags = -DMBEDTLS_CLIENT_DEBUG
```
This will print detailed information about the TLS handshake, read/write operations, and errors to the Serial monitor.

## 📄 License
This library is released under the MIT License. See the `LICENSE` file for details.