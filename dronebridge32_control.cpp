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

// Wire-format sizes (explicit — do NOT rely on compiler padding)
// New wire-format for control plaintext: uint32_t seq | uint8_t droneID | int32_t command = 4 + 1 + 4 = 9 bytes
#define CONTROL_PAYLOAD_LEN (4 + 1 + 4)

// Symmetric key (example). Runtime key is loaded from NVS if available.
static const uint8_t kKey[] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
static const size_t kKeyLen = sizeof(kKey);
static uint8_t runtime_key[16];

#include "provisioning_pubkey.h"

#if defined(ESP32) || defined(ARDUINO_ARCH_ESP32)
#include <Preferences.h>
static Preferences prefs;
#endif

static uint32_t last_control_seq = 0; // persisted when updated (if supported)

static void load_runtime_key_and_state() {
#if defined(ESP32) || defined(ARDUINO_ARCH_ESP32)
  prefs.begin("db32", false);
  size_t got = prefs.getBytes("key", runtime_key, kKeyLen);
  if (got == kKeyLen) {
    Serial.println("Loaded AES key from NVS");
  } else {
    memcpy(runtime_key, kKey, kKeyLen);
    Serial.println("Using compiled default AES key");
  }
  last_control_seq = (uint32_t)prefs.getUInt("last_ctrl_seq", 0);
#else
  memcpy(runtime_key, kKey, kKeyLen);
#endif
}

static bool store_runtime_key(const uint8_t* key, size_t len) {
#if defined(ESP32) || defined(ARDUINO_ARCH_ESP32)
  prefs.putBytes("key", key, len);
  prefs.putUInt("last_ctrl_seq", last_control_seq);
  return true;
#else
  // Not persisted on non-ESP platforms in this example.
  (void)key; (void)len; return false;
#endif
}

static bool store_last_control_seq(uint32_t seq) {
  last_control_seq = seq;
#if defined(ESP32) || defined(ARDUINO_ARCH_ESP32)
  prefs.putUInt("last_ctrl_seq", seq);
  return true;
#else
  return false;
#endif
}

// AES-GCM decrypt helper (uses mbedTLS available on ESP32/Arduino cores)
static bool aes_gcm_decrypt_runtime(const uint8_t* nonce, size_t nonce_len,
                            const uint8_t* ciphertext, size_t ciphertext_len,
                            const uint8_t* tag, size_t tag_len,
                            uint8_t* out_plaintext) {
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, runtime_key, (int)(kKeyLen * 8));
  if (rc != 0) { mbedtls_gcm_free(&gcm); return false; }
  rc = mbedtls_gcm_auth_decrypt(&gcm, ciphertext_len, nonce, nonce_len, NULL, 0, tag, tag_len, ciphertext, out_plaintext);
  mbedtls_gcm_free(&gcm);
  return (rc == 0);
}

static void fill_random_bytes(uint8_t* buf, size_t len) {
#if defined(ESP32) || defined(ARDUINO_ARCH_ESP32)
  esp_fill_random(buf, len);
#else
  for (size_t i = 0; i < len; ++i) buf[i] = (uint8_t)random(0, 256);
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

void setup() {
  MESHTASTIC_SERIAL.begin(BAUD_RATE);
  MAVLINK_SERIAL.begin(57600);
  Serial.begin(115200);
  Serial.println("DroneBridge32 Meshtastic Integration - Control (fixed)");
}

void receiveControlCommand() {
  // expect wire format: nonce(12) | ciphertext(CONTROL_PAYLOAD_LEN) | tag(16)
  const size_t nonce_len = 12;
  const size_t tag_len = 16;
  const size_t wire_len = nonce_len + CONTROL_PAYLOAD_LEN + tag_len;
  if (MESHTASTIC_SERIAL.available() >= wire_len) {
    uint8_t wire[wire_len];
    MESHTASTIC_SERIAL.readBytes(wire, wire_len);

    uint8_t decrypted_buffer[CONTROL_PAYLOAD_LEN];
    if (!aes_gcm_decrypt_runtime(wire, nonce_len, wire + nonce_len, CONTROL_PAYLOAD_LEN, wire + nonce_len + CONTROL_PAYLOAD_LEN, tag_len, decrypted_buffer)) {
      Serial.println("AES-GCM decrypt failed");
      return;
    }

    // plaintext layout: uint32_t seq | uint8_t droneID | int32_t command
    uint32_t seq = 0;
    memcpy(&seq, decrypted_buffer, sizeof(seq));
    uint8_t droneID = decrypted_buffer[4];
    int32_t command = 0;
    memcpy(&command, &decrypted_buffer[5], sizeof(command));

    Serial.print("Received control seq="); Serial.print(seq);
    Serial.print(" droneID="); Serial.print(droneID);
    Serial.print(" cmd="); Serial.println(command);

    // replay protection: require strictly increasing sequence numbers
    if (seq <= last_control_seq) {
      Serial.println("Rejected control (replay or stale seq)");
      // send ACK with status=1 (rejected)
      uint32_t ack_seq = seq;
      uint8_t ackbuf[6];
      memcpy(ackbuf, &ack_seq, sizeof(ack_seq));
      ackbuf[4] = droneID;
      ackbuf[5] = 1; // rejected
      const size_t nonce_len = 12, tag_len = 16;
      uint8_t nonce[nonce_len]; fill_random_bytes(nonce, nonce_len);
      uint8_t ciphertext[sizeof(ackbuf)], tag[tag_len];
      if (aes_gcm_encrypt_runtime(ackbuf, sizeof(ackbuf), nonce, nonce_len, ciphertext, tag, tag_len)) {
        MESHTASTIC_SERIAL.write(nonce, nonce_len);
        MESHTASTIC_SERIAL.write(ciphertext, sizeof(ciphertext));
        MESHTASTIC_SERIAL.write(tag, tag_len);
      }
      return;
    }

    // Accept and persist sequence
    store_last_control_seq(seq);

    // Support special sync-request command: 0x7fffffff -> respond with last_control_seq
    if (command == 0x7FFFFFFF) {
      uint32_t ack_seq = last_control_seq;
      uint8_t ackbuf[6];
      memcpy(ackbuf, &ack_seq, sizeof(ack_seq));
      ackbuf[4] = droneID;
      ackbuf[5] = 2; // sync-response
      const size_t nonce_len = 12, tag_len = 16;
      uint8_t nonce[nonce_len]; fill_random_bytes(nonce, nonce_len);
      uint8_t ciphertext[sizeof(ackbuf)], tag[tag_len];
      if (aes_gcm_encrypt_runtime(ackbuf, sizeof(ackbuf), nonce, nonce_len, ciphertext, tag, tag_len)) {
        MESHTASTIC_SERIAL.write(nonce, nonce_len);
        MESHTASTIC_SERIAL.write(ciphertext, sizeof(ciphertext));
        MESHTASTIC_SERIAL.write(tag, tag_len);
      }
      return;
    }

    if (droneID == DRONE_ID) {
      if (command == 1) {
        sendMavlinkCommand(MAV_CMD_NAV_RETURN_TO_LAUNCH);
        Serial.println("-> Return to Launch");
      } else if (command == 2) {
        sendMavlinkCommand(MAV_CMD_NAV_LAND);
        Serial.println("-> Land");
      } else if (command == 3) {
        sendMavlinkCommand(MAV_CMD_NAV_LAND); // Emergency = land in this example
        Serial.println("-> Emergency Land");
      } else {
        Serial.println("-> Unknown command");
      }
      // send ACK (status=0)
      uint32_t ack_seq = seq;
      uint8_t ackbuf[6];
      memcpy(ackbuf, &ack_seq, sizeof(ack_seq));
      ackbuf[4] = droneID;
      ackbuf[5] = 0; // ok
      const size_t nonce_len = 12, tag_len = 16;
      uint8_t nonce[nonce_len]; fill_random_bytes(nonce, nonce_len);
      uint8_t ciphertext[sizeof(ackbuf)], tag[tag_len];
      if (aes_gcm_encrypt_runtime(ackbuf, sizeof(ackbuf), nonce, nonce_len, ciphertext, tag, tag_len)) {
        MESHTASTIC_SERIAL.write(nonce, nonce_len);
        MESHTASTIC_SERIAL.write(ciphertext, sizeof(ciphertext));
        MESHTASTIC_SERIAL.write(tag, tag_len);
      }
    }
  }

  // Simple provisioning via USB serial console: send a line `SETKEY:hexkey` to update runtime key
  if (Serial.available()) {
    String line = Serial.readStringUntil('\n');
    line.trim();
    if (line.startsWith("SETKEYSIG:")) {
      // format: SETKEYSIG:hexkey:dersighex
      int p1 = line.indexOf(':', 8); // after SETKEYSIG:
      if (p1 > 0) {
        String hex = line.substring(8, p1);
        String sighex = line.substring(p1 + 1);
        hex.trim(); sighex.trim();
        if (hex.length() == (int)(kKeyLen * 2) && sighex.length() > 0) {
          // convert hex to bytes
          uint8_t newkey[kKeyLen];
          bool ok = true;
          for (size_t i = 0; i < kKeyLen; ++i) {
            int hi = (int)strtol(hex.substring(i*2, i*2+1).c_str(), NULL, 16);
            int lo = (int)strtol(hex.substring(i*2+1, i*2+2).c_str(), NULL, 16);
            if (hi < 0 || lo < 0) { ok = false; break; }
            newkey[i] = (uint8_t)((hi << 4) | lo);
          }
          if (!ok) { Serial.println("SETKEYSIG: invalid hex"); }
          else {
            // convert signature hex
            size_t siglen = sighex.length() / 2;
            uint8_t sigbuf[256];
            if (siglen > sizeof(sigbuf)) { Serial.println("SETKEYSIG: signature too long"); }
            else {
              for (size_t i = 0; i < siglen; ++i) {
                int hi = (int)strtol(sighex.substring(i*2, i*2+1).c_str(), NULL, 16);
                int lo = (int)strtol(sighex.substring(i*2+1, i*2+2).c_str(), NULL, 16);
                sigbuf[i] = (uint8_t)((hi << 4) | lo);
              }
              // verify signature using compiled provisioning public key
              mbedtls_pk_context pk;
              mbedtls_pk_init(&pk);
              const char *pem = PROVISIONING_PUBKEY_PEM;
              int ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char*)pem, strlen(pem)+1);
              if (ret != 0) {
                Serial.println("SETKEYSIG: failed to parse provisioning pubkey");
              } else {
                // verify SHA256 over the key bytes (hex decoded)
                unsigned char hash[32];
                mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), newkey, kKeyLen, hash);
                ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), sigbuf, siglen);
                if (ret == 0) {
                  memcpy(runtime_key, newkey, kKeyLen);
                  store_runtime_key(runtime_key, kKeyLen);
                  Serial.println("SETKEYSIG: signature verified, key stored");
                } else {
                  Serial.println("SETKEYSIG: signature verification failed");
                }
              }
              mbedtls_pk_free(&pk);
            }
          }
        } else {
          Serial.println("SETKEYSIG: invalid lengths");
        }
      } else {
        Serial.println("SETKEYSIG: bad format");
      }
    } else if (line.startsWith("SETKEY:")) {
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
          store_runtime_key(runtime_key, kKeyLen);
          Serial.println("Runtime AES key updated and persisted");
        } else {
          Serial.println("SETKEY: invalid hex");
        }
      } else {
        Serial.println("SETKEY: wrong length (expect 32 hex chars for AES-128)");
      }
    }
  }
}

void sendMavlinkCommand(uint16_t command) {
  mavlink_message_t msg;
  uint8_t buf[MAVLINK_MAX_PACKET_LEN];
  mavlink_command_long_t cmd = {0};

n  cmd.target_system = SYSTEM_ID;
  cmd.target_component = COMPONENT_ID;
  cmd.command = command;
  cmd.confirmation = 0;

  for (int i = 1; i <= 7; ++i) ((float*)&cmd.param1)[i-1] = 0.0f; // zero params

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
  receiveControlCommand();
  serialErrorHandler(&MAVLINK_SERIAL);
  serialErrorHandler(&MESHTASTIC_SERIAL);
  delay(50);
}
