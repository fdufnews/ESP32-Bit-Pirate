#pragma once
#include <cstdint>

class II2cSnifferService {
public:
    virtual ~II2cSnifferService() = default;
    // Reserve capture/decode RAM on the first sniff; release on exit.
    virtual bool prepare() { return true; } // default keeps existing test fakes compatible
    virtual void begin(uint8_t scl, uint8_t sda) = 0;
    virtual void setAddressFilter(bool enabled, uint8_t address) = 0;
    virtual bool setup() = 0;
    virtual const char* backendName() const = 0;
    virtual const char* lastError() const = 0;
    virtual void stop() = 0;
    virtual void release() = 0;
    virtual bool available() = 0;
    virtual char read() = 0;
    virtual void resetBuffer() = 0;
};
