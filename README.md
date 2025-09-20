# MbedTLSClient for Arduino

[![PlatformIO Registry](https://img.shields.io/badge/PlatformIO-Registry-orange)](https://registry.platformio.org/libraries/your-username/MbedTLSClient)
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

1.  Open the PlatformIO Home screen and navigate to the "Libraries" tab.
2.  Search for `MbedTLSClient`.
3.  Click "Install" to add it to your project.

Alternatively, add it to your `platformio.ini` file:

```ini
lib_deps = cupcake08/Arduino-MbedTLS-Client