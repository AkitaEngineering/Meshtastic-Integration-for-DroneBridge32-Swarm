#include <Arduino.h>
#include <HardwareSerial.h>
#include <mavlink.h>
#include <stdint.h>
#if defined(ESP32) || defined(ARDUINO_ARCH_ESP32)
#include "esp_system.h" // esp_fill_random
#endif
#include <mbedtls/gcm.h>

// Configuration
#define MESHTASTIC_SERIAL Serial1
#define BAUD_RATE 115200
#define DRONE_ID 1
#define MAVLINK_SERIAL Serial
#define SYSTEM_ID 255
#define COMPONENT_ID 1
#define SIGNAL_LOSS_TIMEOUT 5000 // Milliseconds

// Wire-format for telemetry: 4 floats + 1 uint8_t = 17 bytes (packed)
// New telemetry plaintext: uint32_t seq | float latitude | float longitude | float altitude | float batteryVoltage | uint8_t droneID
#define TELEMETRY_PAYLOAD_LEN (sizeof(uint32_t) + 4 * sizeof(float) + 1)

// Symmetric key (example). Runtime key is loaded from NVS if available.
static const uint8_t kKey[] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
static const size_t kKeyLen = sizeof(kKey);
static uint8_t runtime_key[16];
static uint32_t telemetry_seq = 0;

#if defined(ESP32) || defined(ARDUINO_ARCH_ESP32)
#include <Preferences.h>
static Preferences prefs;
#endif

static void load_runtime_key_state_telemetry() {
#if defined(ESP32) || defined(ARDUINO_ARCH_ESP32)
  prefs.begin("db32", false);
  size_t got = prefs.getBytes("key", runtime_key, kKeyLen);
  if (got == kKeyLen) {
    Serial.println("Loaded AES key from NVS");
  } else {
    memcpy(runtime_key, kKey, kKeyLen);
    Serial.println("Using compiled default AES key");
  }
  telemetry_seq = prefs.getUInt("telemetry_seq", 0);
#else
  memcpy(runtime_key, kKey, kKeyLen);
#endif
}

static void persist_telemetry_seq(uint32_t seq) {
#if defined(ESP32) || defined(ARDUINO_ARCH_ESP32)
  prefs.putUInt("telemetry_seq", seq);
#endif
}

static bool aes_gcm_encrypt_runtime(const uint8_t* plaintext, size_t plen,
                            const uint8_t* nonce, size_t nonce_len,
                            uint8_t* ciphertext_out, uint8_t* tag_out, size_t tag_len) {
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, runtime_key, (int)(kKeyLen * 8));
  if (rc != 0) { mbedtls_gcm_free(&gcm); return false; }
  rc = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, (size_t)plen, nonce, nonce_len, NULL, 0, plaintext, ciphertext_out, tag_len, tag_out);
  mbedtls_gcm_free(&gcm);
  return (rc == 0);
}

// Fail Safes
unsigned long last_signal_time = 0;
bool signal_lost = false;
bool low_battery = false;

// Telemetry Data Structure
struct DroneTelemetry {
  float latitude;
  float longitude;
  float altitude;
  float batteryVoltage;
  uint8_t droneID;
};

void setup() {
  MESHTASTIC_SERIAL.begin(BAUD_RATE);
  MAVLINK_SERIAL.begin(57600);
  Serial.begin(115200);
  Serial.println("DroneBridge32 Meshtastic Integration - Telemetry (fixed)");
  load_runtime_key_state_telemetry();
}

void loop() {
  sendTelemetry();
  checkFailSafes();

  // provisioning via USB serial: SETKEY:hexkey
  if (Serial.available()) {
    String line = Serial.readStringUntil('\n');
    line.trim();
    if (line.startsWith("SETKEY:")) {
      String hex = line.substring(strlen("SETKEY:"));
      hex.trim();
      if (hex.length() == (int)(kKeyLen * 2)) {
        uint8_t newkey[kKeyLen];
        bool ok = true;
        for (size_t i = 0; i < kKeyLen; ++i) {
          char hh = hex.charAt(i*2);
          char hl = hex.charAt(i*2+1);
          int hi = (hh >= '0' && hh <= '9') ? hh - '0' : (hh >= 'a' && hh <= 'f') ? 10 + hh - 'a' : (hh >= 'A' && hh <= 'F') ? 10 + hh - 'A' : -1;
          int lo = (hl >= '0' && hl <= '9') ? hl - '0' : (hl >= 'a' && hl <= 'f') ? 10 + hl - 'a' : (hl >= 'A' && hl <= 'F') ? 10 + hl - 'A' : -1;
          if (hi < 0 || lo < 0) { ok = false; break; }
          newkey[i] = (uint8_t)((hi << 4) | lo);
        }
        if (ok) {
          memcpy(runtime_key, newkey, kKeyLen);
#if defined(ESP32) || defined(ARDUINO_ARCH_ESP32)
          prefs.putBytes("key", runtime_key, kKeyLen);
#endif
          Serial.println("Runtime AES key updated");
        } else {
          Serial.println("SETKEY: invalid hex");
        }
      } else {
        Serial.println("SETKEY: wrong length (expect 32 hex chars for AES-128)");
      }
    }
  }

  delay(50);
}

void sendTelemetry() {
  mavlink_message_t msg;
  mavlink_status_t status;
  uint8_t buf[MAVLINK_MAX_PACKET_LEN];

  while (MAVLINK_SERIAL.available() > 0) {
    uint8_t c = MAVLINK_SERIAL.read();
    if (mavlink_parse_char(MAVLINK_COMM_0, c, &msg, &status)) {
      if (msg.msgid == MAVLINK_MSG_ID_GLOBAL_POSITION_INT) {
        mavlink_global_position_int_t global_pos;
        mavlink_msg_global_position_int_decode(&msg, &global_pos);

        DroneTelemetry telemetryData;
        telemetryData.latitude = global_pos.lat / 10000000.0;
        telemetryData.longitude = global_pos.lon / 10000000.0;
        telemetryData.altitude = global_pos.alt / 1000.0;
        telemetryData.droneID = DRONE_ID;

        float voltage = getBatteryVoltage();
        if (voltage >= 0) {
          telemetryData.batteryVoltage = voltage;
          low_battery = (voltage < 11.0); // example low battery threshold
        } else {
          telemetryData.batteryVoltage = 0;
        }

        // Pack into wire-format buffer (packed, no compiler padding)
        // Pack plaintext: uint32_t seq | float lat | float lon | float alt | float battery | uint8_t droneID
        uint8_t buffer[TELEMETRY_PAYLOAD_LEN];
        size_t pos = 0;
        telemetry_seq++;
        memcpy(buffer + pos, &telemetry_seq, sizeof(telemetry_seq)); pos += sizeof(telemetry_seq);
        memcpy(buffer + pos, &telemetryData.latitude, sizeof(telemetryData.latitude)); pos += sizeof(telemetryData.latitude);
        memcpy(buffer + pos, &telemetryData.longitude, sizeof(telemetryData.longitude)); pos += sizeof(telemetryData.longitude);
        memcpy(buffer + pos, &telemetryData.altitude, sizeof(telemetryData.altitude)); pos += sizeof(telemetryData.altitude);
        memcpy(buffer + pos, &telemetryData.batteryVoltage, sizeof(telemetryData.batteryVoltage)); pos += sizeof(telemetryData.batteryVoltage);
        buffer[pos] = telemetryData.droneID; pos += sizeof(telemetryData.droneID);

        persist_telemetry_seq(telemetry_seq);

        const size_t nonce_len = 12;
        const size_t tag_len = 16;
        uint8_t nonce[nonce_len];
        fill_random_bytes(nonce, nonce_len);

        uint8_t ciphertext[TELEMETRY_PAYLOAD_LEN];
        uint8_t tag[tag_len];
        if (!aes_gcm_encrypt_runtime(buffer, TELEMETRY_PAYLOAD_LEN, nonce, nonce_len, ciphertext, tag, tag_len)) {
          Serial.println("AES-GCM encryption failed");
          return;
        }

        // wire: nonce | ciphertext | tag
        MESHTASTIC_SERIAL.write(nonce, nonce_len);
        MESHTASTIC_SERIAL.write(ciphertext, TELEMETRY_PAYLOAD_LEN);
        MESHTASTIC_SERIAL.write(tag, tag_len);
        last_signal_time = millis();
        signal_lost = false;

        // If we received a special sync request (handled elsewhere) the MCU will
        // reply via the same MESHTASTIC_SERIAL path with an encrypted ACK-like
        // payload. (ACK sending implemented in receiveControlCommand when needed.)

      }
    }
  }
}

float getBatteryVoltage() {
  mavlink_message_t msg;
  mavlink_status_t status;
  uint8_t buf[MAVLINK_MAX_PACKET_LEN];

  int timeout = 100;
  unsigned long startTime = millis();

  while ((millis() - startTime) < timeout) {
    if (MAVLINK_SERIAL.available() == 0) continue;
    uint8_t c = MAVLINK_SERIAL.read();
    if (mavlink_parse_char(MAVLINK_COMM_0, c, &msg, &status)) {
      if (msg.msgid == MAVLINK_MSG_ID_SYS_STATUS) {
        mavlink_sys_status_t sys_status;
        mavlink_msg_sys_status_decode(&msg, &sys_status);
        return sys_status.voltage_battery / 1000.0f;
      }
    }
  }
  return -1.0f;
}

void checkFailSafes() {
  if (millis() - last_signal_time > SIGNAL_LOSS_TIMEOUT && !signal_lost) {
    Serial.println("Signal loss detected. Initiating return to home.");
    sendMavlinkCommand(MAV_CMD_NAV_RETURN_TO_LAUNCH);
    signal_lost = true;
  }
  if (low_battery && !signal_lost) {
    Serial.println("Low battery detected. Initiating landing.");
    sendMavlinkCommand(MAV_CMD_NAV_LAND);
    low_battery = false;
  }
}

void sendMavlinkCommand(uint16_t command) {
  mavlink_message_t msg;
  uint8_t buf[MAVLINK_MAX_PACKET_LEN];
  mavlink_command_long_t cmd = {0};

  cmd.target_system = SYSTEM_ID;
  cmd.target_component = COMPONENT_ID;
  cmd.command = command;
  cmd.confirmation = 0;
  cmd.param1 = 0;
  cmd.param2 = 0;
  cmd.param3 = 0;
  cmd.param4 = 0;
  cmd.param5 = 0;
  cmd.param6 = 0;
  cmd.param7 = 0;

  mavlink_msg_command_long_encode(SYSTEM_ID, COMPONENT_ID, &msg, &cmd);
  uint16_t len = mavlink_msg_to_send_buffer(buf, &msg);
  MAVLINK_SERIAL.write(buf, len);
}

void serialErrorHandler(HardwareSerial* serialPort) {
  // Arduino core does not expose framing/parity/overrun clear APIs portably.
  // Check TX buffer availability and warn if constrained.
  if (serialPort->availableForWrite() == 0) {
    Serial.println("Warning: serial TX buffer full or write not available");
  }
}

void loop() {
  sendTelemetry();
  checkFailSafes();
  serialErrorHandler(&MAVLINK_SERIAL);
  serialErrorHandler(&MESHTASTIC_SERIAL);
  delay(50);
}
