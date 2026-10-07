/**
 * Passive I2C sniffer used by ESP32 Bit Pirate.
 *
 * On ESP32-S3 the implementation timestamps SDA/SCL edges with the MCPWM
 * capture peripheral and decodes the protocol later from the ordered edge
 * stream. The sniffer never drives either bus line.
 */
#pragma once

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

void i2c_sniffer_begin(uint8_t scl, uint8_t sda);
void i2c_sniffer_set_address_filter(bool enabled, uint8_t address);
bool i2c_sniffer_setup();
void i2c_sniffer_stop();
void i2c_sniffer_release();
bool i2c_sniffer_available();
char i2c_sniffer_read();
void i2c_sniffer_reset_buffer();

#ifdef __cplusplus
}
#endif
