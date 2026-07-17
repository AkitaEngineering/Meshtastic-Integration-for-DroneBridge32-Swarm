#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/uart.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"

// Note: To compile, the MAVLink C headers must be available in your include path.
// If you don't have them in this repository yet, you will need to add them (e.g., in a `components/mavlink` folder).
#include "mavlink.h"
#include "../provisioning_pubkey.h"

static const char *TAG = "DB32_NODE";

// UART Configurations
#define CONSOLE_UART_NUM      UART_NUM_0
#define MESHTASTIC_UART_NUM   UART_NUM_1
#define MAVLINK_UART_NUM      UART_NUM_2

#define UART_RX_BUF_SIZE      1024
#define UART_TX_BUF_SIZE      1024

// Meshtastic UART Pins (Adjust for your specific ESP32 board)
#define MESH_TXD_PIN          (4)
#define MESH_RXD_PIN          (5)

// MAVLink UART Pins (Adjust for your specific ESP32 board)
#define MAV_TXD_PIN           (17)
#define MAV_RXD_PIN           (16)

#define DRONE_ID                  1
#define SWARM_BROADCAST_ID        255
#define GCS_SYSTEM_ID             255
#define GCS_COMPONENT_ID          1
#define FC_TARGET_SYSTEM_ID       1
#define FC_TARGET_COMPONENT_ID    1

#define COMMAND_RTL               1
#define COMMAND_LAND              2
#define COMMAND_EMERGENCY_LAND    3
#define COMMAND_SYNC_REQUEST      4

#define ACK_STATUS_ACCEPTED       1
#define ACK_STATUS_SYNC           2
#define ACK_STATUS_REJECTED       3

#define CONTROL_PAYLOAD_LEN 9
#define CONTROL_ACK_PAYLOAD_LEN 6
#define TELEMETRY_PAYLOAD_LEN 33
#define NONCE_LEN 12
#define TAG_LEN 16
#define KEY_HEX_LEN 32
#define MAX_SIGNATURE_LEN 128

static uint8_t runtime_key[16];
static const size_t kKeyLen = sizeof(runtime_key);
static bool runtime_key_configured = false;

#ifdef ALLOW_INSECURE_DEFAULT_KEY
static const uint8_t kDefaultKey[] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
};
#endif

static uint32_t last_control_seq = 0;
static uint32_t telemetry_seq = 0;

// Telemetry State
struct DroneTelemetry {
    float latitude;
    float longitude;
    float altitude;
    float batteryVoltage;
    float roll;
    float pitch;
    float yaw;
    uint8_t droneID;
};

static DroneTelemetry current_telemetry = {0, 0, 0, 0, 0, 0, 0, DRONE_ID};
static portMUX_TYPE telemetry_spinlock = portMUX_INITIALIZER_UNLOCKED;

// Helper: Fill random bytes
static void fill_random_bytes(uint8_t* buf, size_t len) {
    esp_fill_random(buf, len);
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static bool hex_to_bytes(const char* hex, uint8_t* out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) {
        return false;
    }

    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static bool verify_provisioning_signature(const uint8_t* key, const uint8_t* sig, size_t sig_len) {
    uint8_t hash[32];
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == NULL || mbedtls_md(md_info, key, kKeyLen, hash) != 0) {
        ESP_LOGE(TAG, "Failed to hash provisioning key.");
        return false;
    }

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    int rc = mbedtls_pk_parse_public_key(
        &pk,
        (const unsigned char*)PROVISIONING_PUBKEY_PEM,
        strlen(PROVISIONING_PUBKEY_PEM) + 1
    );
    if (rc != 0) {
        ESP_LOGE(TAG, "Provisioning public key parse failed: -0x%04x", (unsigned int)-rc);
        mbedtls_pk_free(&pk);
        return false;
    }

    rc = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig, sig_len);
    mbedtls_pk_free(&pk);
    return rc == 0;
}

// NVS Operations
static void load_state_from_nvs() {
    nvs_handle_t my_handle;
    esp_err_t err = nvs_open("storage", NVS_READWRITE, &my_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error (%s) opening NVS handle!", esp_err_to_name(err));
#ifdef ALLOW_INSECURE_DEFAULT_KEY
        memcpy(runtime_key, kDefaultKey, kKeyLen);
        runtime_key_configured = true;
#endif
        return;
    }

    size_t required_size = kKeyLen;
    err = nvs_get_blob(my_handle, "aes_key", runtime_key, &required_size);
    if (err != ESP_OK || required_size != kKeyLen) {
        ESP_LOGE(TAG, "AES Key not found in NVS. Provision with SETKEYSIG before use.");
#ifdef ALLOW_INSECURE_DEFAULT_KEY
        ESP_LOGW(TAG, "Using insecure compiled default key because ALLOW_INSECURE_DEFAULT_KEY is set.");
        memcpy(runtime_key, kDefaultKey, kKeyLen);
        runtime_key_configured = true;
#endif
    } else {
        ESP_LOGI(TAG, "AES Key loaded from NVS.");
        runtime_key_configured = true;
    }

    nvs_get_u32(my_handle, "ctrl_seq", &last_control_seq);
    nvs_get_u32(my_handle, "telem_seq", &telemetry_seq);

    nvs_close(my_handle);
}

static void save_key_to_nvs(const uint8_t* key, size_t len) {
    nvs_handle_t my_handle;
    if (nvs_open("storage", NVS_READWRITE, &my_handle) == ESP_OK) {
        nvs_set_blob(my_handle, "aes_key", key, len);
        nvs_commit(my_handle);
        nvs_close(my_handle);
        ESP_LOGI(TAG, "AES Key saved to NVS.");
    }
}

static void save_ctrl_seq_to_nvs(uint32_t seq) {
    nvs_handle_t my_handle;
    if (nvs_open("storage", NVS_READWRITE, &my_handle) == ESP_OK) {
        nvs_set_u32(my_handle, "ctrl_seq", seq);
        nvs_commit(my_handle);
        nvs_close(my_handle);
    }
}

static void save_telem_seq_to_nvs(uint32_t seq) {
    nvs_handle_t my_handle;
    if (nvs_open("storage", NVS_READWRITE, &my_handle) == ESP_OK) {
        nvs_set_u32(my_handle, "telem_seq", seq);
        nvs_commit(my_handle);
        nvs_close(my_handle);
    }
}

// AES-GCM Cryptography
static bool aes_gcm_decrypt(const uint8_t* nonce, const uint8_t* ciphertext, size_t clen, const uint8_t* tag, uint8_t* plaintext) {
    mbedtls_gcm_context gcm;
    if (!runtime_key_configured) {
        return false;
    }
    mbedtls_gcm_init(&gcm);
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, runtime_key, kKeyLen * 8) != 0) {
        mbedtls_gcm_free(&gcm);
        return false;
    }
    int rc = mbedtls_gcm_auth_decrypt(&gcm, clen, nonce, NONCE_LEN, NULL, 0, tag, TAG_LEN, ciphertext, plaintext);
    mbedtls_gcm_free(&gcm);
    return (rc == 0);
}

static bool aes_gcm_encrypt(const uint8_t* plaintext, size_t plen, const uint8_t* nonce, uint8_t* ciphertext, uint8_t* tag) {
    mbedtls_gcm_context gcm;
    if (!runtime_key_configured) {
        return false;
    }
    mbedtls_gcm_init(&gcm);
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, runtime_key, kKeyLen * 8) != 0) {
        mbedtls_gcm_free(&gcm);
        return false;
    }
    int rc = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plen, nonce, NONCE_LEN, NULL, 0, plaintext, ciphertext, TAG_LEN, tag);
    mbedtls_gcm_free(&gcm);
    return (rc == 0);
}

// MAVLink Output helper
static void send_mavlink_command(uint16_t command) {
    mavlink_message_t msg;
    uint8_t buf[MAVLINK_MAX_PACKET_LEN];
    mavlink_command_long_t cmd = {0};

    cmd.target_system = FC_TARGET_SYSTEM_ID;
    cmd.target_component = FC_TARGET_COMPONENT_ID;
    cmd.command = command;
    cmd.confirmation = 0;
    
    mavlink_msg_command_long_encode(GCS_SYSTEM_ID, GCS_COMPONENT_ID, &msg, &cmd);
    uint16_t len = mavlink_msg_to_send_buffer(buf, &msg);
    uart_write_bytes(MAVLINK_UART_NUM, (const char*)buf, len);
}

static void send_control_ack(uint32_t seq, uint8_t drone_id, uint8_t status) {
    uint8_t plaintext[CONTROL_ACK_PAYLOAD_LEN];
    size_t pos = 0;
    memcpy(plaintext + pos, &seq, sizeof(seq)); pos += sizeof(seq);
    plaintext[pos++] = drone_id;
    plaintext[pos] = status;

    uint8_t nonce[NONCE_LEN];
    uint8_t ciphertext[CONTROL_ACK_PAYLOAD_LEN];
    uint8_t tag[TAG_LEN];
    fill_random_bytes(nonce, NONCE_LEN);

    if (aes_gcm_encrypt(plaintext, CONTROL_ACK_PAYLOAD_LEN, nonce, ciphertext, tag)) {
        uart_write_bytes(MESHTASTIC_UART_NUM, (const char*)nonce, NONCE_LEN);
        uart_write_bytes(MESHTASTIC_UART_NUM, (const char*)ciphertext, CONTROL_ACK_PAYLOAD_LEN);
        uart_write_bytes(MESHTASTIC_UART_NUM, (const char*)tag, TAG_LEN);
    }
}

// Task: Read MAVLink from Flight Controller
static void task_mavlink_rx(void *arg) {
    uint8_t* data = (uint8_t*) malloc(UART_RX_BUF_SIZE);
    if (data == NULL) {
        ESP_LOGE(TAG, "Failed to allocate MAVLink RX buffer.");
        vTaskDelete(NULL);
        return;
    }
    mavlink_message_t msg = {};
    mavlink_status_t status = {};

    while (1) {
        int len = uart_read_bytes(MAVLINK_UART_NUM, data, UART_RX_BUF_SIZE, 20 / portTICK_PERIOD_MS);
        for (int i = 0; i < len; i++) {
            if (mavlink_parse_char(MAVLINK_COMM_0, data[i], &msg, &status)) {
                portENTER_CRITICAL(&telemetry_spinlock);
                if (msg.msgid == MAVLINK_MSG_ID_GLOBAL_POSITION_INT) {
                    mavlink_global_position_int_t global_pos;
                    mavlink_msg_global_position_int_decode(&msg, &global_pos);
                    current_telemetry.latitude = global_pos.lat / 10000000.0f;
                    current_telemetry.longitude = global_pos.lon / 10000000.0f;
                    current_telemetry.altitude = global_pos.alt / 1000.0f;
                } else if (msg.msgid == MAVLINK_MSG_ID_SYS_STATUS) {
                    mavlink_sys_status_t sys_status;
                    mavlink_msg_sys_status_decode(&msg, &sys_status);
                    current_telemetry.batteryVoltage = sys_status.voltage_battery / 1000.0f;
                } else if (msg.msgid == MAVLINK_MSG_ID_ATTITUDE) {
                    mavlink_attitude_t attitude;
                    mavlink_msg_attitude_decode(&msg, &attitude);
                    current_telemetry.roll = attitude.roll;
                    current_telemetry.pitch = attitude.pitch;
                    current_telemetry.yaw = attitude.yaw;
                }
                portEXIT_CRITICAL(&telemetry_spinlock);
            }
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

// Task: Read encrypted control commands from Meshtastic
static void task_meshtastic_rx(void *arg) {
    const size_t wire_len = NONCE_LEN + CONTROL_PAYLOAD_LEN + TAG_LEN;
    uint8_t* data = (uint8_t*) malloc(UART_RX_BUF_SIZE);
    if (data == NULL) {
        ESP_LOGE(TAG, "Failed to allocate Meshtastic RX buffer.");
        vTaskDelete(NULL);
        return;
    }

    while (1) {
        int len = uart_read_bytes(MESHTASTIC_UART_NUM, data, wire_len, portMAX_DELAY);
        if (len >= wire_len) {
            uint8_t nonce[NONCE_LEN];
            uint8_t ciphertext[CONTROL_PAYLOAD_LEN];
            uint8_t tag[TAG_LEN];
            
            memcpy(nonce, data, NONCE_LEN);
            memcpy(ciphertext, data + NONCE_LEN, CONTROL_PAYLOAD_LEN);
            memcpy(tag, data + NONCE_LEN + CONTROL_PAYLOAD_LEN, TAG_LEN);

            uint8_t plaintext[CONTROL_PAYLOAD_LEN];
            if (aes_gcm_decrypt(nonce, ciphertext, CONTROL_PAYLOAD_LEN, tag, plaintext)) {
                uint32_t seq;
                memcpy(&seq, plaintext, sizeof(seq));
                uint8_t drone_id = plaintext[4];
                int32_t command;
                memcpy(&command, &plaintext[5], sizeof(command));

                ESP_LOGI(TAG, "Command Received - Seq: %lu, Drone: %d, Cmd: %ld", (unsigned long)seq, drone_id, (long)command);

                if (drone_id != DRONE_ID && drone_id != SWARM_BROADCAST_ID) {
                    ESP_LOGI(TAG, "Command is for another drone; ignored without advancing replay counter.");
                    continue;
                }

                if (seq > last_control_seq) {
                    uint8_t ack_status = ACK_STATUS_ACCEPTED;

                    switch (command) {
                        case COMMAND_RTL:
                            ESP_LOGI(TAG, "Executing RTL");
                            send_mavlink_command(MAV_CMD_NAV_RETURN_TO_LAUNCH);
                            break;
                        case COMMAND_LAND:
                        case COMMAND_EMERGENCY_LAND:
                            ESP_LOGI(TAG, "Executing Land");
                            send_mavlink_command(MAV_CMD_NAV_LAND);
                            break;
                        case COMMAND_SYNC_REQUEST:
                            ESP_LOGI(TAG, "Control sync requested");
                            ack_status = ACK_STATUS_SYNC;
                            break;
                        default:
                            ESP_LOGW(TAG, "Unsupported command rejected: %ld", (long)command);
                            ack_status = ACK_STATUS_REJECTED;
                            break;
                    }

                    last_control_seq = seq;
                    save_ctrl_seq_to_nvs(seq);
                    send_control_ack(seq, DRONE_ID, ack_status);
                } else {
                    ESP_LOGW(TAG, "Stale/Replay control command rejected. Seq: %lu", (unsigned long)seq);
                    send_control_ack(seq, DRONE_ID, ACK_STATUS_REJECTED);
                }
            } else {
                ESP_LOGE(TAG, "Failed to decrypt incoming control packet.");
            }
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

// Task: Send encrypted telemetry to Meshtastic
static void task_telemetry_tx(void *arg) {
    while (1) {
        uint8_t plaintext[TELEMETRY_PAYLOAD_LEN];
        size_t pos = 0;
        
        telemetry_seq++;
        save_telem_seq_to_nvs(telemetry_seq);

        portENTER_CRITICAL(&telemetry_spinlock);
        memcpy(plaintext + pos, &telemetry_seq, sizeof(telemetry_seq)); pos += sizeof(uint32_t);
        memcpy(plaintext + pos, &current_telemetry.latitude, sizeof(float)); pos += sizeof(float);
        memcpy(plaintext + pos, &current_telemetry.longitude, sizeof(float)); pos += sizeof(float);
        memcpy(plaintext + pos, &current_telemetry.altitude, sizeof(float)); pos += sizeof(float);
        memcpy(plaintext + pos, &current_telemetry.batteryVoltage, sizeof(float)); pos += sizeof(float);
        memcpy(plaintext + pos, &current_telemetry.roll, sizeof(float)); pos += sizeof(float);
        memcpy(plaintext + pos, &current_telemetry.pitch, sizeof(float)); pos += sizeof(float);
        memcpy(plaintext + pos, &current_telemetry.yaw, sizeof(float)); pos += sizeof(float);
        plaintext[pos] = current_telemetry.droneID;
        portEXIT_CRITICAL(&telemetry_spinlock);

        uint8_t nonce[NONCE_LEN];
        fill_random_bytes(nonce, NONCE_LEN);
        
        uint8_t ciphertext[TELEMETRY_PAYLOAD_LEN];
        uint8_t tag[TAG_LEN];

        if (aes_gcm_encrypt(plaintext, TELEMETRY_PAYLOAD_LEN, nonce, ciphertext, tag)) {
            uart_write_bytes(MESHTASTIC_UART_NUM, (const char*)nonce, NONCE_LEN);
            uart_write_bytes(MESHTASTIC_UART_NUM, (const char*)ciphertext, TELEMETRY_PAYLOAD_LEN);
            uart_write_bytes(MESHTASTIC_UART_NUM, (const char*)tag, TAG_LEN);
            ESP_LOGI(TAG, "Telemetry Sent. Seq: %lu", (unsigned long)telemetry_seq);
        } else {
            ESP_LOGE(TAG, "Telemetry encryption failed.");
        }

        // Delay 5 seconds between telemetry broadcasts
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

// Task: Read USB Console for Provisioning
static void task_provisioning(void *arg) {
    uint8_t* data = (uint8_t*) malloc(UART_RX_BUF_SIZE + 1);
    if (data == NULL) {
        ESP_LOGE(TAG, "Failed to allocate provisioning buffer.");
        vTaskDelete(NULL);
        return;
    }
    while (1) {
        int len = uart_read_bytes(CONSOLE_UART_NUM, data, UART_RX_BUF_SIZE, 100 / portTICK_PERIOD_MS);
        if (len > 0) {
            data[len] = 0; // null terminate
            char* signed_ptr = strstr((char*)data, "SETKEYSIG:");
            if (signed_ptr != NULL) {
                char key_hex[KEY_HEX_LEN + 1];
                char sig_hex[MAX_SIGNATURE_LEN * 2 + 1];
                int matched = sscanf(
                    signed_ptr,
                    "SETKEYSIG:%32[0-9a-fA-F]:%256[0-9a-fA-F]",
                    key_hex,
                    sig_hex
                );
                if (matched == 2) {
                    uint8_t newkey[16];
                    uint8_t sig[MAX_SIGNATURE_LEN];
                    size_t sig_len = strlen(sig_hex) / 2;
                    if ((strlen(sig_hex) % 2) != 0 || sig_len > MAX_SIGNATURE_LEN ||
                        !hex_to_bytes(key_hex, newkey, sizeof(newkey)) ||
                        !hex_to_bytes(sig_hex, sig, sig_len)) {
                        ESP_LOGE(TAG, "Invalid SETKEYSIG hex payload.");
                    } else if (verify_provisioning_signature(newkey, sig, sig_len)) {
                        memcpy(runtime_key, newkey, 16);
                        runtime_key_configured = true;
                        save_key_to_nvs(runtime_key, 16);
                        ESP_LOGI(TAG, "Signed AES key provisioned.");
                    } else {
                        ESP_LOGE(TAG, "SETKEYSIG signature verification failed.");
                    }
                } else {
                    ESP_LOGE(TAG, "Invalid SETKEYSIG format. Expected SETKEYSIG:<32hex>:<der_sig_hex>.");
                }
            }

#ifdef ALLOW_INSECURE_SETKEY
            char* ptr = strstr((char*)data, "SETKEY:");
            if (ptr != NULL) {
                char hex[33];
                if (sscanf(ptr, "SETKEY:%32s", hex) == 1 && strlen(hex) == 32) {
                    uint8_t newkey[16];
                    if (hex_to_bytes(hex, newkey, sizeof(newkey))) {
                        memcpy(runtime_key, newkey, 16);
                        runtime_key_configured = true;
                        save_key_to_nvs(runtime_key, 16);
                    } else {
                        ESP_LOGE(TAG, "Invalid SETKEY hex.");
                    }
                } else {
                    ESP_LOGE(TAG, "Invalid SETKEY format. Expected 32 hex chars.");
                }
            }
#endif
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }
}

extern "C" void app_main(void) {
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    load_state_from_nvs();

    // Configure UART0 (Console)
    uart_config_t uart_config_console = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    uart_driver_install(CONSOLE_UART_NUM, UART_RX_BUF_SIZE, UART_TX_BUF_SIZE, 0, NULL, 0);
    uart_param_config(CONSOLE_UART_NUM, &uart_config_console);

    // Configure UART1 (Meshtastic)
    uart_config_t uart_config_mesh = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    uart_driver_install(MESHTASTIC_UART_NUM, UART_RX_BUF_SIZE, UART_TX_BUF_SIZE, 0, NULL, 0);
    uart_param_config(MESHTASTIC_UART_NUM, &uart_config_mesh);
    uart_set_pin(MESHTASTIC_UART_NUM, MESH_TXD_PIN, MESH_RXD_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    // Configure UART2 (MAVLink)
    uart_config_t uart_config_mav = {
        .baud_rate = 57600,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    uart_driver_install(MAVLINK_UART_NUM, UART_RX_BUF_SIZE, UART_TX_BUF_SIZE, 0, NULL, 0);
    uart_param_config(MAVLINK_UART_NUM, &uart_config_mav);
    uart_set_pin(MAVLINK_UART_NUM, MAV_TXD_PIN, MAV_RXD_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    ESP_LOGI(TAG, "UART drivers installed. Starting FreeRTOS Tasks...");

    // Start Tasks
    xTaskCreate(task_mavlink_rx, "mavlink_rx", 4096, NULL, 5, NULL);
    xTaskCreate(task_meshtastic_rx, "mesh_rx", 4096, NULL, 5, NULL);
    xTaskCreate(task_telemetry_tx, "telem_tx", 4096, NULL, 4, NULL);
    xTaskCreate(task_provisioning, "provisioning", 2048, NULL, 3, NULL);
}
