/**
 * @file MbedTLS_AWS_IoT_TinyGSM.ino
 * @author Ankit Bhankharia
 * @brief Demonstrates a robust connection to AWS IoT Core using MQTT over a cellular
 * modem (e.g., SIM7600) with the MbedTLSClient library.
 * @version 1.0
 * @date 2025-09-18
 *
 * @details This example covers:
 * 1.  Initializing a cellular modem with TinyGSM.
 * 2.  Connecting to the GPRS network.
 * 3.  **Crucially, synchronizing the device's internal clock using the network time.**
 * AWS IoT requires a correct system time for TLS certificate validation.
 * 4.  Wrapping a TinyGsmClient with the MbedTLSClient for a secure connection.
 * 5.  Connecting to AWS IoT Core using PubSubClient.
 * 6.  Periodically publishing data and handling incoming messages safely.
 *
 * Required Libraries:
 * - MbedTLSClient (this library)
 * - TinyGSM by Volodymyr Shymanskyy
 * - PubSubClient by Nick O'Leary
 */

 #include <Arduino.h>
 #include "PubSubClient.h"
 #include "MbedTLSClient.h"
 
 // --- 1. MODEM & NETWORK CONFIGURATION ---
 #define TINY_GSM_MODEM_SIM7600
 #include "TinyGsmClient.h"
 
 // Define the serial port for your modem
 #define MODEM_SERIAL Serial1
 #define MODEM_BAUD 115200
 #define MODEM_TX 27 // ESP32 TX pin connected to modem RX
 #define MODEM_RX 26 // ESP32 RX pin connected to modem TX
 
 // Your GPRS APN credentials
 const char apn[]      = "your_apn"; // e.g., "airtelgprs.com"
 const char gprsUser[] = "";
 const char gprsPass[] = "";
 
 
 // --- 2. AWS IOT CORE CONFIGURATION ---
 
 // Your AWS IoT Core endpoint. Find this in your AWS console:
 // IoT Core -> Settings -> Custom endpoint
 const char* aws_iot_endpoint = "xxxxxxxxxxxxxx-ats.iot.us-east-1.amazonaws.com";
 
 // A unique name for this device
 const char* mqtt_client_id = "esp32-sim7600-01";
 
 // The MQTT topics for publishing and subscribing
 const char* mqtt_publish_topic = "esp32/telemetry";
 const char* mqtt_subscribe_topic = "esp32/commands";
 
 
 // --- 3. TLS CERTIFICATES ---
 // You must get these from your AWS IoT Core console.
 // Create a "Thing", create a certificate, and download these files.
 
 // Amazon's Root CA 1 certificate
 // Download from: https://www.amazontrust.com/repository/AmazonRootCA1.pem
 const char* aws_root_ca_pem = \
 "-----BEGIN CERTIFICATE-----\n" \
 "-----END CERTIFICATE-----\n";
 
 // Your device's certificate (from the file named xxxxx-certificate.pem.crt)
 const char* device_cert_pem = \
 "-----BEGIN CERTIFICATE-----\n" \
 "(Your device certificate here)\n" \
 "-----END CERTIFICATE-----\n";
 
 // Your device's private key (from the file named xxxxx-private.pem.key)
 const char* device_private_key_pem = \
 "-----BEGIN RSA PRIVATE KEY-----\n" \
 "(Your device private key here)\n" \
 "-----END RSA PRIVATE KEY-----\n";
 
 
 // --- 4. GLOBAL OBJECTS ---
 TinyGsm modem(MODEM_SERIAL);
 TinyGsmClient gsmClient(modem);
 MbedTLSClient tlsClient(gsmClient); // Wrap GSM client with TLS
 PubSubClient pubSubClient(tlsClient); // Use the secure client
 
 unsigned long last_publish_time = 0;
 
 
 // --- 5. FUNCTION DECLARATIONS ---
 void sync_time_with_modem();
 void mqtt_callback(char* topic, byte* payload, unsigned int length);
 void reconnect_mqtt();
 
 
 void setup() {
     Serial.begin(115200);
     delay(100);
 
     Serial.println("Initializing modem...");
     MODEM_SERIAL.begin(MODEM_BAUD, SERIAL_8N1, MODEM_RX, MODEM_TX);
     if (!modem.init()) {
         Serial.println("FATAL: Failed to initialize modem. Halting.");
         while (1);
     }
 
     Serial.print("Waiting for network...");
     if (!modem.waitForNetwork()) {
         Serial.println(" fail. Retrying...");
         delay(10000);
         ESP.restart();
     }
     Serial.println(" OK");
 
     Serial.print("Connecting to GPRS...");
     if (!modem.gprsConnect(apn, gprsUser, gprsPass)) {
         Serial.println(" fail. Retrying...");
         delay(10000);
         ESP.restart();
     }
     Serial.println(" OK");
 
     sync_time_with_modem();
 
     // Configure the TLS client with certificates
     Serial.println("Configuring TLS client...");
     tlsClient.setCACert(aws_root_ca_pem);
     tlsClient.setClientCert(device_cert_pem, device_private_key_pem);
 
     // Configure the MQTT client
     pubSubClient.setServer(aws_iot_endpoint, 8883);
     pubSubClient.setCallback(mqtt_callback);
 
     Serial.println("Setup complete.");
 }
 
 void loop() {
     if (!pubSubClient.connected()) {
         reconnect_mqtt();
     }
     pubSubClient.loop(); // Must be called regularly
 
     // Publish a message every 30 seconds
     if (millis() - last_publish_time > 30000) {
         last_publish_time = millis();
         char msg_buffer[128];
         snprintf(msg_buffer, sizeof(msg_buffer),
                  "{\"device_id\": \"%s\", \"uptime_sec\": %lu}",
                  mqtt_client_id, millis() / 1000);
 
         Serial.print("Publishing message: ");
         Serial.println(msg_buffer);
         pubSubClient.publish(mqtt_publish_topic, msg_buffer);
     }
 }
 
 /**
  * @brief Handles incoming MQTT messages safely.
  */
 void mqtt_callback(char* topic, byte* payload, unsigned int length) {
     Serial.print("Message arrived on topic: ");
     Serial.println(topic);
 
     // Create a temporary buffer to hold the payload and null-terminate it.
     // This prevents reading past the end of the payload into old buffer data.
     char message[length + 1];
     memcpy(message, payload, length);
     message[length] = '\0';
 
     Serial.print("Payload: ");
     Serial.println(message);
 }
 
 /**
  * @brief Connects/reconnects to the MQTT broker.
  */
 void reconnect_mqtt() {
     while (!pubSubClient.connected()) {
         Serial.print("Attempting MQTT connection to AWS IoT...");
         if (pubSubClient.connect(mqtt_client_id)) {
             Serial.println(" connected!");
             // Subscribe to the commands topic upon connection
             pubSubClient.subscribe(mqtt_subscribe_topic);
         } else {
             Serial.print(" failed, rc=");
             Serial.print(pubSubClient.state());
             Serial.println(". Retrying in 5 seconds...");
             delay(5000);
         }
     }
 }
 
 /**
  * @brief Gets the network time from the modem and sets the system clock.
  */
 void sync_time_with_modem() {
     Serial.print("Syncing system time with network...");
     int year, month, day, hour, min, sec;
     float timezone;
 
     if (modem.getNetworkTime(&year, &month, &day, &hour, &min, &sec, &timezone)) {
         struct tm timeinfo;
         timeinfo.tm_year = year - 1900;
         timeinfo.tm_mon = month - 1;
         timeinfo.tm_mday = day;
         timeinfo.tm_hour = hour;
         timeinfo.tm_min = min;
         timeinfo.tm_sec = sec;
         
         time_t now = mktime(&timeinfo);
 
         struct timeval tv = { .tv_sec = now };
         settimeofday(&tv, NULL);
 
         Serial.printf(" OK\nSystem time set to: %d-%02d-%02d %02d:%02d:%02d\n",
                       year, month, day, hour, min, sec);
     } else {
         Serial.println(" fail. Could not get network time. Retrying...");
         delay(5000);
         ESP.restart();
     }
 }
 