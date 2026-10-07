/**
 * Passive I2C sniffer for ESP32 Bit Pirate.
 *
 * The original implementation decoded I2C directly from two Arduino GPIO
 * interrupt handlers. That is fundamentally racy: a SDA interrupt can be
 * serviced after SCL has already changed, so a normal data transition can be
 * mistaken for START/STOP and the byte stream becomes desynchronised.
 *
 * On ESP32-S3 we instead use the MCPWM capture peripheral. SCL and SDA edges
 * are timestamped by the same hardware capture timer. ISR callbacks only put
 * the latched timestamp + edge into lock-free rings. The actual I2C protocol
 * is decoded later, in timestamp order, from main context.
 *
 * This keeps the sniffer passive and makes protocol decisions from the bus
 * chronology rather than from ISR execution order.
 */

#include "i2c_sniffer.h"

#include <Arduino.h>
#include <cstdlib>
#include "driver/gpio.h"
#include "driver/mcpwm_cap.h"
#include "esp_err.h"
#include "esp_heap_caps.h"
#include "soc/soc_caps.h"

static uint8_t sniffer_scl_pin = 1;
static uint8_t sniffer_sda_pin = 2;

// ---------------------------------------------------------------------------
// Hardware capture
// ---------------------------------------------------------------------------

// We only need a common monotonically increasing hardware timestamp. Use the
// target's native capture-timer resolution instead of forcing the MCPWM group
// clock. On ESP32-S3 this is the APB capture clock; no prescaler changes are
// required and existing MCPWM timing in the selected group is left untouched.
static constexpr int CAPTURE_INTR_PRIORITY = 3;

static mcpwm_cap_timer_handle_t captureTimer = nullptr;
static mcpwm_cap_channel_handle_t sclCaptureChannel = nullptr;
static mcpwm_cap_channel_handle_t sdaCaptureChannel = nullptr;
static bool captureTimerEnabled = false;
static bool captureTimerStarted = false;
static bool sclCaptureEnabled = false;
static bool sdaCaptureEnabled = false;

// Raw capture event encoding (single shared stream):
// bit 31    : SDA event = 1, SCL event = 0
// bit 30    : positive edge = 1, negative edge = 0
// bits 29:0 : lower 30 bits of the common MCPWM capture timestamp
//
// A single ISR ring is important here. Two independent per-line rings are not
// sufficient even with hardware timestamps: one channel callback can be
// serviced later than the other, and consuming the currently non-empty ring
// can therefore decode a newer edge before an older callback has arrived.
//
// Main context drains this shared arrival ring into a small timestamp-ordered
// heap and only releases events after a short reorder window. Capture itself
// is never delayed; only text decoding/display is held back by a few hundred
// microseconds.
static constexpr uint32_t RAW_LINE_SDA  = 0x80000000UL;
static constexpr uint32_t RAW_EDGE_POS  = 0x40000000UL;
static constexpr uint32_t RAW_TIME_MASK = 0x3FFFFFFFUL;
static constexpr uint32_t RAW_HALF_RANGE = 0x20000000UL;

#define RAW_RING_ORDER 12
#define RAW_RING_SIZE  (1u << RAW_RING_ORDER)  // 4096 combined edges (16 KiB)
#define RAW_RING_MASK  (RAW_RING_SIZE - 1u)

static volatile uint32_t* rawRing = nullptr;
static volatile uint16_t rawW = 0;
static volatile uint16_t rawR = 0;
static volatile bool rawOverflow = false;

// Reordering window. 200 us is tiny compared with terminal output latency but
// comfortably larger than normal cross-channel ISR service skew. At 400 kHz
// this is only about 80 I2C bit periods. If callbacks are delayed beyond this
// window the raw ring still protects capture; if either queue overflows we
// explicitly resynchronise instead of fabricating bytes.
static constexpr uint32_t REORDER_HOLDBACK_US = 200;
static constexpr uint32_t REORDER_IDLE_FLUSH_US = 500;
#define REORDER_HEAP_ORDER 10
#define REORDER_HEAP_SIZE (1u << REORDER_HEAP_ORDER) // 1024 events
static uint32_t* reorderHeap = nullptr;
static uint16_t reorderCount = 0;
static bool reorderOverflow = false;
static bool haveNewestTimestamp = false;
static uint32_t newestTimestamp = 0;
static uint32_t reorderHoldbackTicks = 1;
static uint32_t captureResolutionHz = 0;
static uint32_t lastRawActivityUs = 0;

static inline uint32_t IRAM_ATTR pack_raw_event(bool isSda,
                                                const mcpwm_capture_event_data_t* edata) {
    return (edata->cap_value & RAW_TIME_MASK) |
           (isSda ? RAW_LINE_SDA : 0u) |
           ((edata->cap_edge == MCPWM_CAP_EDGE_POS) ? RAW_EDGE_POS : 0u);
}

static inline void IRAM_ATTR raw_push(uint32_t value) {
    if (rawRing == nullptr) {
        return;
    }

    const uint16_t write = rawW;
    const uint16_t next = (uint16_t)((write + 1u) & RAW_RING_MASK);
    if (next == rawR) {
        rawOverflow = true;
        return;
    }

    rawRing[write] = value;
    rawW = next;
}

static bool IRAM_ATTR on_scl_capture(mcpwm_cap_channel_handle_t,
                                     const mcpwm_capture_event_data_t* edata,
                                     void*) {
    raw_push(pack_raw_event(false, edata));
    return false;
}

static bool IRAM_ATTR on_sda_capture(mcpwm_cap_channel_handle_t,
                                     const mcpwm_capture_event_data_t* edata,
                                     void*) {
    raw_push(pack_raw_event(true, edata));
    return false;
}

static inline uint32_t raw_time(uint32_t raw) {
    return raw & RAW_TIME_MASK;
}

static inline bool raw_is_sda(uint32_t raw) {
    return (raw & RAW_LINE_SDA) != 0;
}

static inline bool raw_is_positive(uint32_t raw) {
    return (raw & RAW_EDGE_POS) != 0;
}

// Modulo-2^30 timestamp comparison. All events held for ordering are only a
// few hundred microseconds apart, far below the 2^29 half-range.
static inline bool timestamp_before(uint32_t a, uint32_t b) {
    if (a == b) {
        return false;
    }
    return (((a - b) & RAW_TIME_MASK) & RAW_HALF_RANGE) != 0;
}

static inline bool timestamp_after(uint32_t a, uint32_t b) {
    return timestamp_before(b, a);
}

static inline uint32_t timestamp_distance(uint32_t newer, uint32_t older) {
    return (newer - older) & RAW_TIME_MASK;
}

// If two physical transitions quantise to the same capture tick, use I2C-safe
// tie breaking:
//   1) SCL falling first: SDA may legally change immediately after SCL falls.
//   2) SDA transition next.
//   3) SCL rising last: SDA must already be stable when data is sampled.
static inline uint8_t raw_tie_rank(uint32_t raw) {
    if (!raw_is_sda(raw) && !raw_is_positive(raw)) {
        return 0;
    }
    if (raw_is_sda(raw)) {
        return 1;
    }
    return 2;
}

static inline bool raw_event_before(uint32_t a, uint32_t b) {
    const uint32_t ta = raw_time(a);
    const uint32_t tb = raw_time(b);
    if (ta != tb) {
        return timestamp_before(ta, tb);
    }
    return raw_tie_rank(a) < raw_tie_rank(b);
}

static bool reorder_push(uint32_t raw) {
    if (reorderHeap == nullptr || reorderCount >= REORDER_HEAP_SIZE) {
        reorderOverflow = true;
        return false;
    }

    uint16_t i = reorderCount++;
    while (i > 0) {
        const uint16_t parent = (uint16_t)((i - 1u) >> 1u);
        if (!raw_event_before(raw, reorderHeap[parent])) {
            break;
        }
        reorderHeap[i] = reorderHeap[parent];
        i = parent;
    }
    reorderHeap[i] = raw;
    return true;
}

static uint32_t reorder_pop() {
    const uint32_t out = reorderHeap[0];
    const uint32_t tail = reorderHeap[--reorderCount];

    if (reorderCount == 0) {
        return out;
    }

    uint16_t i = 0;
    while (true) {
        const uint16_t left = (uint16_t)(i * 2u + 1u);
        if (left >= reorderCount) {
            break;
        }
        const uint16_t right = (uint16_t)(left + 1u);
        uint16_t child = left;
        if (right < reorderCount && raw_event_before(reorderHeap[right], reorderHeap[left])) {
            child = right;
        }
        if (!raw_event_before(reorderHeap[child], tail)) {
            break;
        }
        reorderHeap[i] = reorderHeap[child];
        i = child;
    }
    reorderHeap[i] = tail;
    return out;
}

// ---------------------------------------------------------------------------
// Decoded event ring (main-context producer -> text formatter consumer)
// ---------------------------------------------------------------------------

#define TAG_START    0x1
#define TAG_STOP     0x2
#define TAG_DATA     0x3
#define TAG_ADDR     0x4
#define TAG_ACK      0x5
#define TAG_OVERFLOW 0x6

static inline uint16_t PACK_EVENT(uint16_t tag, uint16_t value) {
    return (uint16_t)((tag << 12) | (value & 0x0FFF));
}
static inline uint8_t EVENT_TAG(uint16_t ev) {
    return (uint8_t)((ev >> 12) & 0x0F);
}
static inline uint16_t EVENT_VAL(uint16_t ev) {
    return (uint16_t)(ev & 0x0FFF);
}

#define EVENT_RING_ORDER 11
#define EVENT_RING_SIZE  (1u << EVENT_RING_ORDER)
#define EVENT_RING_MASK  (EVENT_RING_SIZE - 1u)
static uint16_t* eventRing = nullptr;
static uint16_t eventW = 0;
static uint16_t eventR = 0;
static bool eventOverflow = false;

static inline void push_event(uint16_t ev) {
    if (eventRing == nullptr) {
        return;
    }

    const uint16_t next = (uint16_t)((eventW + 1u) & EVENT_RING_MASK);
    if (next == eventR) {
        eventOverflow = true;
        return;
    }

    eventRing[eventW] = ev;
    eventW = next;
}

// ---------------------------------------------------------------------------
// Output character ring
// ---------------------------------------------------------------------------

#define CHAR_RING_ORDER 13
#define CHAR_RING_SIZE  (1u << CHAR_RING_ORDER)
#define CHAR_RING_MASK  (CHAR_RING_SIZE - 1u)
static char* charRing = nullptr;
static uint16_t charW = 0;
static uint16_t charR = 0;
static bool charOverflow = false;

static inline void char_push(char c) {
    if (charRing == nullptr) {
        return;
    }

    const uint16_t next = (uint16_t)((charW + 1u) & CHAR_RING_MASK);
    if (next == charR) {
        // Do not move charR here: overwriting the oldest bytes produces the
        // misleading truncated lines seen with the previous implementation.
        charOverflow = true;
        return;
    }

    charRing[charW] = c;
    charW = next;
}

static void text_push_str(const char* s) {
    while (*s) {
        char_push(*s++);
    }
}

static void text_push_hex8(uint8_t value) {
    static const char HEX_DIGITS[] = "0123456789ABCDEF";
    char_push('0');
    char_push('x');
    char_push(HEX_DIGITS[(value >> 4) & 0x0F]);
    char_push(HEX_DIGITS[value & 0x0F]);
}

// ---------------------------------------------------------------------------
// I2C decoder state (main context only)
// ---------------------------------------------------------------------------

static bool decoderInTransaction = false;
static uint8_t decoderScl = 1;
static uint8_t decoderSda = 1;
static uint8_t decoderBitCount = 0;
static uint8_t decoderByte = 0;
static uint16_t decoderByteCount = 0;
static bool decoderExpectingAck = false;

static bool addressFilterEnabled = false;
static uint8_t addressFilter = 0;
static bool frameAccepted = true;

static void reset_decoder_state(bool samplePins) {
    decoderInTransaction = false;
    decoderBitCount = 0;
    decoderByte = 0;
    decoderByteCount = 0;
    decoderExpectingAck = false;
    frameAccepted = !addressFilterEnabled;

    if (samplePins) {
        decoderScl = (uint8_t)(gpio_get_level((gpio_num_t)sniffer_scl_pin) != 0);
        decoderSda = (uint8_t)(gpio_get_level((gpio_num_t)sniffer_sda_pin) != 0);
    } else {
        decoderScl = 1;
        decoderSda = 1;
    }
}

static void decoder_start() {
    // START and repeated START both begin a fresh address phase.
    if (!addressFilterEnabled) {
        push_event(PACK_EVENT(TAG_START, 0));
    }

    decoderInTransaction = true;
    decoderBitCount = 0;
    decoderByte = 0;
    decoderByteCount = 0;
    decoderExpectingAck = false;
    frameAccepted = !addressFilterEnabled;
}

static void decoder_stop() {
    if (!decoderInTransaction) {
        return;
    }

    if (frameAccepted) {
        push_event(PACK_EVENT(TAG_STOP, 0));
    }

    decoderInTransaction = false;
    decoderBitCount = 0;
    decoderByte = 0;
    decoderByteCount = 0;
    decoderExpectingAck = false;
    frameAccepted = !addressFilterEnabled;
}

static void decoder_sample_sda_on_scl_rise() {
    if (!decoderInTransaction) {
        return;
    }

    if (decoderExpectingAck) {
        if (frameAccepted) {
            push_event(PACK_EVENT(TAG_ACK, decoderSda ? 1u : 0u));
        }
        decoderExpectingAck = false;
        decoderBitCount = 0;
        decoderByte = 0;
        return;
    }

    decoderByte = (uint8_t)((decoderByte << 1) | (decoderSda & 0x01u));
    decoderBitCount++;

    if (decoderBitCount != 8) {
        return;
    }

    if (decoderByteCount == 0) {
        const uint8_t addr = (uint8_t)((decoderByte >> 1) & 0x7F);
        frameAccepted = !addressFilterEnabled || (addr == addressFilter);

        if (frameAccepted) {
            // With a filter enabled, defer START until the address byte proves
            // this phase belongs to the requested device.
            if (addressFilterEnabled) {
                push_event(PACK_EVENT(TAG_START, 0));
            }
            push_event(PACK_EVENT(TAG_ADDR, decoderByte));
        }
    } else if (frameAccepted) {
        push_event(PACK_EVENT(TAG_DATA, decoderByte));
    }

    decoderByteCount++;
    decoderExpectingAck = true;
}

static void process_scl_edge(uint32_t raw) {
    const bool positive = raw_is_positive(raw);
    decoderScl = positive ? 1 : 0;

    if (positive) {
        decoder_sample_sda_on_scl_rise();
    }
}

static void process_sda_edge(uint32_t raw) {
    const bool positive = raw_is_positive(raw);
    decoderSda = positive ? 1 : 0;

    // In I2C, SDA changing while SCL is HIGH is protocol control, not data:
    //   high -> low = START / repeated START
    //   low  -> high = STOP
    // Because SCL/SDA are processed in hardware timestamp order, decoderScl
    // is the level that actually existed at the SDA edge time.
    if (decoderScl == 0) {
        return;
    }

    if (positive) {
        decoder_stop();
    } else {
        decoder_start();
    }
}

static void process_raw_event(uint32_t raw) {
    if (raw_is_sda(raw)) {
        process_sda_edge(raw);
    } else {
        process_scl_edge(raw);
    }
}

static void handle_capture_overflow() {
    // Once an edge is lost we can no longer trust byte alignment. Flush raw
    // arrival + reorder state and wait for the next genuine START rather than
    // inventing addresses/data from a shifted stream.
    noInterrupts();
    rawR = rawW;
    rawOverflow = false;
    interrupts();

    reorderCount = 0;
    reorderOverflow = false;
    haveNewestTimestamp = false;
    reset_decoder_state(true);
    push_event(PACK_EVENT(TAG_OVERFLOW, 0));
}

static void pump_raw_to_events() {
    if (rawRing == nullptr || reorderHeap == nullptr) {
        return;
    }

    if (rawOverflow || reorderOverflow) {
        handle_capture_overflow();
        return;
    }

    // First move callback-arrival order into a timestamp ordered heap. This is
    // intentionally separate from decoding: callbacks from the two MCPWM
    // channels are not guaranteed to execute in physical edge order.
    static constexpr uint16_t MAX_RAW_PER_PUMP = 4096;
    uint16_t drained = 0;
    bool sawRaw = false;

    while (drained < MAX_RAW_PER_PUMP && rawR != rawW) {
        const uint32_t raw = rawRing[rawR];
        rawR = (uint16_t)((rawR + 1u) & RAW_RING_MASK);

        if (!reorder_push(raw)) {
            handle_capture_overflow();
            return;
        }

        const uint32_t ts = raw_time(raw);
        if (!haveNewestTimestamp || timestamp_after(ts, newestTimestamp)) {
            newestTimestamp = ts;
            haveNewestTimestamp = true;
        }

        sawRaw = true;
        drained++;
    }

    if (sawRaw) {
        lastRawActivityUs = micros();
    }

    // Decode only events sufficiently older than the newest hardware timestamp.
    // That holdback is what lets a late callback from the other channel arrive
    // and be inserted ahead of an already-seen newer edge.
    static constexpr uint16_t MAX_DECODE_PER_PUMP = 4096;
    uint16_t decoded = 0;
    const bool idleFlush = (rawR == rawW) && reorderCount != 0 &&
                           ((uint32_t)(micros() - lastRawActivityUs) >= REORDER_IDLE_FLUSH_US);

    while (decoded < MAX_DECODE_PER_PUMP && reorderCount != 0) {
        const uint32_t earliest = reorderHeap[0];
        bool safeToRelease = idleFlush;

        if (!safeToRelease && haveNewestTimestamp) {
            const uint32_t age = timestamp_distance(newestTimestamp, raw_time(earliest));
            safeToRelease = age < RAW_HALF_RANGE && age >= reorderHoldbackTicks;
        }

        if (!safeToRelease) {
            break;
        }

        process_raw_event(reorder_pop());
        decoded++;
    }

    if (rawOverflow || reorderOverflow) {
        handle_capture_overflow();
        return;
    }

    // Do not carry a timestamp epoch across a long idle period. The packed
    // hardware timestamp intentionally keeps only 30 bits, so a fresh burst
    // should establish a fresh newest-timestamp reference once all pending
    // events have been released.
    if (reorderCount == 0 && rawR == rawW) {
        haveNewestTimestamp = false;
    }
}

// ---------------------------------------------------------------------------
// Event -> text formatting (main context)
// ---------------------------------------------------------------------------

static void pump_events_to_text() {
    static constexpr uint16_t MAX_EVENTS_PER_PUMP = 256;
    uint16_t processed = 0;

    while (processed < MAX_EVENTS_PER_PUMP && eventR != eventW) {
        const uint16_t ev = eventRing[eventR];
        eventR = (uint16_t)((eventR + 1u) & EVENT_RING_MASK);

        switch (EVENT_TAG(ev)) {
            case TAG_START:
                text_push_str("[S] ");
                break;

            case TAG_STOP:
                text_push_str("[P]");
                char_push('\n');
                break;

            case TAG_ADDR: {
                const uint8_t b = (uint8_t)EVENT_VAL(ev);
                text_push_str("ADDR ");
                text_push_hex8((uint8_t)((b >> 1) & 0x7F));
                char_push(' ');
                char_push((b & 0x01u) ? 'R' : 'W');
                char_push(' ');
                break;
            }

            case TAG_DATA:
                text_push_hex8((uint8_t)EVENT_VAL(ev));
                char_push(' ');
                break;

            case TAG_ACK:
                text_push_str(EVENT_VAL(ev) == 0 ? "<ACK> " : "<NACK> ");
                break;

            case TAG_OVERFLOW:
                text_push_str("[!] CAPTURE OVERFLOW - resync at next START");
                char_push('\n');
                break;

            default:
                break;
        }

        processed++;
    }

    if (eventOverflow) {
        eventOverflow = false;
        text_push_str("[!] DECODE BUFFER OVERFLOW");
        char_push('\n');
    }
}

// ---------------------------------------------------------------------------
// Allocation / MCPWM lifecycle
// ---------------------------------------------------------------------------

static bool ensure_buffers_allocated() {
    if (rawRing != nullptr && reorderHeap != nullptr &&
        eventRing != nullptr && charRing != nullptr) {
        return true;
    }

    if (rawRing == nullptr) {
        rawRing = static_cast<volatile uint32_t*>(
            heap_caps_malloc(RAW_RING_SIZE * sizeof(uint32_t), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
    }
    if (reorderHeap == nullptr) {
        reorderHeap = static_cast<uint32_t*>(
            heap_caps_malloc(REORDER_HEAP_SIZE * sizeof(uint32_t), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
    }
    if (eventRing == nullptr) {
        eventRing = static_cast<uint16_t*>(
            heap_caps_malloc(EVENT_RING_SIZE * sizeof(uint16_t), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
    }
    if (charRing == nullptr) {
        charRing = static_cast<char*>(
            heap_caps_malloc(CHAR_RING_SIZE * sizeof(char), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
    }

    if (rawRing == nullptr || reorderHeap == nullptr ||
        eventRing == nullptr || charRing == nullptr) {
        return false;
    }

    return true;
}

static void reset_buffers_and_decoder() {
    noInterrupts();
    rawW = rawR = 0;
    rawOverflow = false;
    interrupts();

    reorderCount = 0;
    reorderOverflow = false;
    haveNewestTimestamp = false;
    newestTimestamp = 0;
    lastRawActivityUs = micros();

    eventW = eventR = 0;
    charW = charR = 0;
    eventOverflow = false;
    charOverflow = false;
    reset_decoder_state(true);
}

static void destroy_capture_hardware() {
    if (captureTimerStarted && captureTimer != nullptr) {
        mcpwm_capture_timer_stop(captureTimer);
        captureTimerStarted = false;
    }

    if (sclCaptureEnabled && sclCaptureChannel != nullptr) {
        mcpwm_capture_channel_disable(sclCaptureChannel);
        sclCaptureEnabled = false;
    }
    if (sdaCaptureEnabled && sdaCaptureChannel != nullptr) {
        mcpwm_capture_channel_disable(sdaCaptureChannel);
        sdaCaptureEnabled = false;
    }

    if (captureTimerEnabled && captureTimer != nullptr) {
        mcpwm_capture_timer_disable(captureTimer);
        captureTimerEnabled = false;
    }

    if (sclCaptureChannel != nullptr) {
        mcpwm_del_capture_channel(sclCaptureChannel);
        sclCaptureChannel = nullptr;
    }
    if (sdaCaptureChannel != nullptr) {
        mcpwm_del_capture_channel(sdaCaptureChannel);
        sdaCaptureChannel = nullptr;
    }
    if (captureTimer != nullptr) {
        mcpwm_del_capture_timer(captureTimer);
        captureTimer = nullptr;
    }
}

static bool setup_capture_hardware() {
    destroy_capture_hardware();

    // MCPWM capture timer is a per-group resource. Try every available group so
    // sniffing can coexist with another feature that may have reserved one.
    esp_err_t err = ESP_ERR_NOT_FOUND;
    for (int group = 0; group < SOC_MCPWM_GROUPS; ++group) {
        mcpwm_capture_timer_config_t timerConfig = {};
        timerConfig.group_id = group;
        timerConfig.clk_src = MCPWM_CAPTURE_CLK_SRC_DEFAULT;
        timerConfig.resolution_hz = 0; // native/default hardware resolution

        err = mcpwm_new_capture_timer(&timerConfig, &captureTimer);
        if (err == ESP_OK) {
            break;
        }
        captureTimer = nullptr;
    }

    if (captureTimer == nullptr || err != ESP_OK) {
        return false;
    }

    if (mcpwm_capture_timer_get_resolution(captureTimer, &captureResolutionHz) != ESP_OK ||
        captureResolutionHz == 0) {
        destroy_capture_hardware();
        return false;
    }

    const uint64_t holdback =
        (static_cast<uint64_t>(captureResolutionHz) * REORDER_HOLDBACK_US + 999999ULL) / 1000000ULL;
    reorderHoldbackTicks = (uint32_t)(holdback == 0 ? 1 : holdback);

    mcpwm_capture_channel_config_t sclConfig = {};
    sclConfig.gpio_num = sniffer_scl_pin;
    sclConfig.intr_priority = CAPTURE_INTR_PRIORITY;
    sclConfig.prescale = 1;
    sclConfig.flags.pos_edge = true;
    sclConfig.flags.neg_edge = true;
    sclConfig.flags.pull_up = false;
    sclConfig.flags.pull_down = false;

    mcpwm_capture_channel_config_t sdaConfig = sclConfig;
    sdaConfig.gpio_num = sniffer_sda_pin;

    if (mcpwm_new_capture_channel(captureTimer, &sclConfig, &sclCaptureChannel) != ESP_OK ||
        mcpwm_new_capture_channel(captureTimer, &sdaConfig, &sdaCaptureChannel) != ESP_OK) {
        destroy_capture_hardware();
        return false;
    }

    mcpwm_capture_event_callbacks_t sclCallbacks = {};
    sclCallbacks.on_cap = on_scl_capture;
    mcpwm_capture_event_callbacks_t sdaCallbacks = {};
    sdaCallbacks.on_cap = on_sda_capture;

    if (mcpwm_capture_channel_register_event_callbacks(sclCaptureChannel, &sclCallbacks, nullptr) != ESP_OK ||
        mcpwm_capture_channel_register_event_callbacks(sdaCaptureChannel, &sdaCallbacks, nullptr) != ESP_OK) {
        destroy_capture_hardware();
        return false;
    }

    if (mcpwm_capture_timer_enable(captureTimer) != ESP_OK) {
        destroy_capture_hardware();
        return false;
    }
    captureTimerEnabled = true;

    if (mcpwm_capture_channel_enable(sclCaptureChannel) != ESP_OK) {
        destroy_capture_hardware();
        return false;
    }
    sclCaptureEnabled = true;

    if (mcpwm_capture_channel_enable(sdaCaptureChannel) != ESP_OK) {
        destroy_capture_hardware();
        return false;
    }
    sdaCaptureEnabled = true;

    // Sample line levels immediately before starting the common capture clock.
    // Starting in the middle of a transfer is harmless: decoder ignores SCL
    // samples until the next actual START edge appears in the timestamp stream.
    reset_decoder_state(true);

    if (mcpwm_capture_timer_start(captureTimer) != ESP_OK) {
        destroy_capture_hardware();
        return false;
    }
    captureTimerStarted = true;

    return true;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void i2c_sniffer_begin(uint8_t scl, uint8_t sda) {
    sniffer_scl_pin = scl;
    sniffer_sda_pin = sda;
}

void i2c_sniffer_set_address_filter(bool enabled, uint8_t address) {
    addressFilterEnabled = enabled;
    addressFilter = (uint8_t)(address & 0x7F);
    frameAccepted = !enabled;
}

bool i2c_sniffer_setup() {
    if (!ensure_buffers_allocated()) {
        i2c_sniffer_release();
        return false;
    }

    // Passive monitor: do not add internal pull-ups to a live I2C bus. The bus
    // must already have the pull-ups required by I2C itself.
    pinMode(sniffer_scl_pin, INPUT);
    pinMode(sniffer_sda_pin, INPUT);

    reset_buffers_and_decoder();

    if (!setup_capture_hardware()) {
        return false;
    }

    return true;
}

void i2c_sniffer_stop() {
    destroy_capture_hardware();
    reset_decoder_state(true);
}

void i2c_sniffer_release() {
    i2c_sniffer_stop();

    noInterrupts();
    rawW = rawR = 0;
    rawOverflow = false;
    interrupts();

    reorderCount = 0;
    reorderOverflow = false;
    haveNewestTimestamp = false;
    eventW = eventR = 0;
    charW = charR = 0;

    volatile uint32_t* oldRaw = rawRing;
    uint32_t* oldReorder = reorderHeap;
    uint16_t* oldEvents = eventRing;
    char* oldChars = charRing;

    rawRing = nullptr;
    reorderHeap = nullptr;
    eventRing = nullptr;
    charRing = nullptr;

    heap_caps_free(const_cast<uint32_t*>(oldRaw));
    heap_caps_free(oldReorder);
    heap_caps_free(oldEvents);
    heap_caps_free(oldChars);
}

bool i2c_sniffer_available() {
    if (rawRing == nullptr || reorderHeap == nullptr ||
        eventRing == nullptr || charRing == nullptr) {
        return false;
    }

    // Always drain raw capture first, even if text is already buffered. This is
    // the priority path: preserving bus chronology matters more than formatting.
    pump_raw_to_events();

    if (charR == charW) {
        pump_events_to_text();
    }

    if (charOverflow && charR == charW) {
        charOverflow = false;
        text_push_str("[!] OUTPUT BUFFER OVERFLOW");
        char_push('\n');
    }

    return charR != charW;
}

char i2c_sniffer_read() {
    if (!i2c_sniffer_available()) {
        return '\0';
    }

    const char out = charRing[charR];
    charR = (uint16_t)((charR + 1u) & CHAR_RING_MASK);
    return out;
}

void i2c_sniffer_reset_buffer() {
    if (rawRing == nullptr || reorderHeap == nullptr ||
        eventRing == nullptr || charRing == nullptr) {
        return;
    }

    reset_buffers_and_decoder();
}
