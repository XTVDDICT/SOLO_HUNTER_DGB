#include "SoloHunterSha256.h"

#if defined(CONFIG_IDF_TARGET_ESP32)

#include <sha/sha_parallel_engine.h>
#include <esp_private/esp_crypto_lock_internal.h>
#include <hal/sha_ll.h>
#include <soc/dport_access.h>
#include <soc/dport_reg.h>
#include <soc/hwcrypto_reg.h>
#include <mbedtls/sha256.h>
#include <esp_chip_info.h>
#include <atomic>

// Match ESP-IDF's DPORT read workaround, protecting only the two bus reads,
// never the mining batch. a8 is the result; psReg must be a spare register.
#if SOC_DPORT_WORKAROUND && !defined(CONFIG_ESP_SYSTEM_SINGLE_CORE_MODE)
#define HELIOS_SHA_READ(base, offset, psReg) \
      "rsil " psReg ", " XTSTR(SOC_DPORT_WORKAROUND_DIS_INTERRUPT_LVL) "\n" \
      "movi a8, 0x3ff40078\n" \
      "l32i.n a8, a8, 0\n" \
      "l32i.n a8, " base ", " offset "\n" \
      "wsr.ps " psReg "\n" \
      "rsync\n"
#else
#define HELIOS_SHA_READ(base, offset, psReg) \
      "l32i.n a8, " base ", " offset "\n"
#endif

// Numeric labels are local to the next/previous matching occurrence in GAS.
// Bound each SAFE-mode wait independently; a12 is reserved for the countdown.
#define HELIOS_SHA_WAIT_IDLE \
      "movi.n   a12, 1\n" \
      "slli     a12, a12, 12\n" \
      "90:\n" \
      HELIOS_SHA_READ("a5", "12", "a11") \
      "beqz.n   a8, 91f\n" \
      "addi.n   a12, a12, -1\n" \
      "bnez.n   a12, 90b\n" \
      "j        16f\n" \
      "91:\n"

namespace {

bool hardwareLocked = false;
bool timedPipeline = false;
std::atomic<bool> nativeDportReads{false};
std::atomic<bool> referenceNativePipeline{false};
std::atomic<const char*> referenceValidation{"NOT TESTED"};
std::atomic<uint32_t> detectedChipRevision{0};
bool nativeReadsRejected = false;
std::atomic<const char*> lastFault{"NONE"};
std::atomic<const char*> lastFallback{"NONE"};
std::atomic<const char*> lastSelfTestFailure{"NONE"};
std::atomic<uint32_t> recoveryCount{0};
SoloHunterSha256Failure firstFailure;
std::atomic<bool> failureCaptured{false};
constexpr uint32_t SHA_IDLE_SPIN_LIMIT = 4096;
constexpr uint8_t FAST_SELF_TEST_ATTEMPTS = 3;

struct PipelineArgs {
  volatile uint32_t* shaBase;
  const uint32_t* header;
  uint32_t nonce;
  uint32_t limit;
  uint32_t filterMask;
  uint32_t hashes;
  uint32_t found;
};

static_assert(sizeof(PipelineArgs) == 28, "ESP32 pipeline arguments changed");

void resetShaPeripheral() {
  // AES/TLS shares these clock/reset registers. Use the same RCC lock as
  // ESP-IDF, and never assert SECUREBOOT reset (it also affects other crypto).
  SHA_RCC_ATOMIC() {
    sha_ll_enable_bus_clock(true);
    sha_ll_reset_register();
  }
}

bool waitForShaIdle() {
  for (uint32_t spin = 0; spin < SHA_IDLE_SPIN_LIMIT; ++spin) {
    if (DPORT_REG_READ(SHA_TEXT_BASE + 156) == 0) return true;
  }
  return false;
}

bool prepareShaPeripheral() {
  // The engine reservations keep SHA clocked. Rewriting the shared control
  // registers each batch can race the other core's AES clock/reset updates.
  if (waitForShaIdle()) return true;

  // A stuck BUSY bit must never trap the high-priority mining task until the
  // watchdog reboots the device. Reset only the SHA peripheral and retry.
  resetShaPeripheral();
  return waitForShaIdle();
}

bool tryLockShaHardware() {
  if (!esp_sha_try_lock_engine(SHA1)) return false;
  if (!esp_sha_try_lock_engine(SHA2_256)) {
    esp_sha_unlock_engine(SHA1);
    return false;
  }
  // SHA-384 and SHA-512 share the third physical engine on classic ESP32.
  if (!esp_sha_try_lock_engine(SHA2_384)) {
    esp_sha_unlock_engine(SHA2_256);
    esp_sha_unlock_engine(SHA1);
    return false;
  }
  return true;
}

void unlockShaHardware() {
  esp_sha_unlock_engine(SHA2_384);
  esp_sha_unlock_engine(SHA2_256);
  esp_sha_unlock_engine(SHA1);
}

void readDigest(uint8_t output[32]) {
  // ESP-IDF keeps the complete interrupt-masked read in IRAM. Do not mask
  // interrupts around our flash-resident caller or its byte conversions.
  uint32_t words[8];
  esp_dport_access_read_buffer(words, SHA_TEXT_BASE, 8);
  for (size_t i = 0; i < 8; ++i) {
    const uint32_t word = __builtin_bswap32(words[i]);
    memcpy(output + i * sizeof(word), &word, sizeof(word));
  }
}

__attribute__((noinline)) IRAM_ATTR void runPollingPipeline(PipelineArgs& args) {
  // Register scheduling follows the pipelined hardware-SHA technique used by
  // BitsyMiner (Justin Williams, GPL-3.0-or-later). Prepare SHA_TEXT while the
  // engine is busy, then synchronize before issuing the next command.
  __asm__ __volatile__(
      "l32i     a3,  %[args], 0\n"
      "l32i     a4,  %[args], 4\n"
      "l32i     a2,  %[args], 8\n"
      "l32i     a7,  %[args], 12\n"
      "l32i     a9,  %[args], 16\n"
      "movi     a5,  144\n"
      "add.n    a5,  a5, a3\n"
      "movi.n   a6,  0\n"
      "movi.n   a10, 1\n"

      "10:\n"
      // Load block one and start the first compression.
      "l32i.n   a8,  a4, 0\n"
      "s32i.n   a8,  a3, 0\n"
      "l32i.n   a8,  a4, 4\n"
      "s32i.n   a8,  a3, 4\n"
      "l32i.n   a8,  a4, 8\n"
      "s32i.n   a8,  a3, 8\n"
      "l32i.n   a8,  a4, 12\n"
      "s32i.n   a8,  a3, 12\n"
      "l32i.n   a8,  a4, 16\n"
      "s32i.n   a8,  a3, 16\n"
      "l32i.n   a8,  a4, 20\n"
      "s32i.n   a8,  a3, 20\n"
      "l32i.n   a8,  a4, 24\n"
      "s32i.n   a8,  a3, 24\n"
      "l32i.n   a8,  a4, 28\n"
      "s32i.n   a8,  a3, 28\n"
      "l32i.n   a8,  a4, 32\n"
      "s32i.n   a8,  a3, 32\n"
      "l32i.n   a8,  a4, 36\n"
      "s32i.n   a8,  a3, 36\n"
      "l32i.n   a8,  a4, 40\n"
      "s32i.n   a8,  a3, 40\n"
      "l32i.n   a8,  a4, 44\n"
      "s32i.n   a8,  a3, 44\n"
      "l32i.n   a8,  a4, 48\n"
      "s32i.n   a8,  a3, 48\n"
      "l32i.n   a8,  a4, 52\n"
      "s32i.n   a8,  a3, 52\n"
      "l32i.n   a8,  a4, 56\n"
      "s32i.n   a8,  a3, 56\n"
      "l32i.n   a8,  a4, 60\n"
      "s32i.n   a8,  a3, 60\n"
      "s32i.n   a10, a5, 0\n"
      "memw\n"

      // SAFE mode does not overwrite TEXT until compression has finished.
      HELIOS_SHA_WAIT_IDLE
      "l32i     a8,  a4, 64\n"
      "s32i.n   a8,  a3, 0\n"
      "l32i     a8,  a4, 68\n"
      "s32i.n   a8,  a3, 4\n"
      "l32i     a8,  a4, 72\n"
      "s32i.n   a8,  a3, 8\n"
      "s32i.n   a2,  a3, 12\n"
      "movi.n   a8,  1\n"
      "slli     a8,  a8, 31\n"
      "s32i.n   a8,  a3, 16\n"
      "movi.n   a8,  0\n"
      "s32i.n   a8,  a3, 20\n"
      "s32i.n   a8,  a3, 24\n"
      "s32i.n   a8,  a3, 28\n"
      "s32i.n   a8,  a3, 32\n"
      "s32i.n   a8,  a3, 36\n"
      "s32i.n   a8,  a3, 40\n"
      "s32i.n   a8,  a3, 44\n"
      "s32i.n   a8,  a3, 48\n"
      "s32i.n   a8,  a3, 52\n"
      "s32i.n   a8,  a3, 56\n"
      "movi     a8,  640\n"
      "s32i.n   a8,  a3, 60\n"

      "s32i.n   a10, a5, 4\n"
      "memw\n"

      HELIOS_SHA_WAIT_IDLE
      "s32i.n   a10, a5, 8\n"
      "memw\n"
      HELIOS_SHA_WAIT_IDLE

      // SHA_LOAD replaced words 0-7 with the first digest. Words 9-14
      // are already zero from the tail block, so only padding changes.
      "movi.n   a8,  1\n"
      "slli     a8,  a8, 31\n"
      "s32i.n   a8,  a3, 32\n"
      "movi     a8,  256\n"
      "s32i.n   a8,  a3, 60\n"
      "s32i.n   a10, a5, 0\n"
      "memw\n"

      // Account for this nonce while the second SHA is running.
      "addi.n   a6,  a6, 1\n"
      "addi.n   a2,  a2, 1\n"
      "addi.n   a7,  a7, -1\n"

      HELIOS_SHA_WAIT_IDLE
      "s32i.n   a10, a5, 8\n"
      "memw\n"
      HELIOS_SHA_WAIT_IDLE

      // Only return hashes that can still meet the current pool target.
      HELIOS_SHA_READ("a3", "28", "a11")
      "and      a8,  a8, a9\n"
      "beqz.n   a8,  17f\n"
      "beqz.n   a7,  18f\n"
      "j        10b\n"

      "16:\n"
      "movi.n   a8,  2\n"
      "s32i.n   a8,  %[args], 24\n"
      "j        19f\n"
      "17:\n"
      "movi.n   a8,  1\n"
      "s32i.n   a8,  %[args], 24\n"
      "j        19f\n"
      "18:\n"
      "movi.n   a8,  0\n"
      "s32i.n   a8,  %[args], 24\n"
      "19:\n"
      "s32i.n   a2,  %[args], 8\n"
      "s32i.n   a6,  %[args], 20\n"
      "memw\n"
      :
      : [args] "r"(&args)
      : "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10",
        "a11", "a12", "memory");
}

// Keep the recovered native loop in flash, matching the saved fast ELF.
// This alignment is a performance ABI: unrelated assets and UI code must not
// be allowed to move the hot loop to a slower instruction-cache position.
// It never masks interrupts; guarded DPORT reads remain in the IRAM loop.
__attribute__((noinline, aligned(32))) void runReferenceNativePipeline(PipelineArgs& args) {
  // At the standard 240/80 MHz clocks, fixed command spacing removes polling
  // and nonessential MEMW stalls. START commands retain an ordering fence
  // because SHA_TEXT is overwritten while their compression is in flight.
  // A multi-nonce self-test gates this path on every individual chip.
  // The measured 920 kH/s image begins useful assembly at cache-line offset
  // 17. The compiler's five-byte entry plus these twelve bytes preserves that
  // exact offset while the function itself remains locked to 32-byte alignment.
  __asm__ __volatile__(
      "nop.n\n"
      "nop.n\n"
      "nop.n\n"
      "nop.n\n"
      "nop.n\n"
      "nop.n\n"
      "l32i     a3,  %[args], 0\n"
      "l32i     a4,  %[args], 4\n"
      "l32i     a2,  %[args], 8\n"
      "l32i     a7,  %[args], 12\n"
      "l32i     a9,  %[args], 16\n"
      "movi     a5,  144\n"
      "add.n    a5,  a5, a3\n"
      "movi.n   a10, 1\n"
      "movi.n   a11, 1\n"
      "slli     a11, a11, 31\n"
      "movi     a12, 640\n"
      "movi     a13, 256\n"
      "movi.n   a14, 0\n"

      // Prime the pipeline with the fixed first 64 bytes.
      "l32i.n   a8,  a4, 0\n"
      "s32i.n   a8,  a3, 0\n"
      "l32i.n   a8,  a4, 4\n"
      "s32i.n   a8,  a3, 4\n"
      "l32i.n   a8,  a4, 8\n"
      "s32i.n   a8,  a3, 8\n"
      "l32i.n   a8,  a4, 12\n"
      "s32i.n   a8,  a3, 12\n"
      "l32i.n   a8,  a4, 16\n"
      "s32i.n   a8,  a3, 16\n"
      "l32i.n   a8,  a4, 20\n"
      "s32i.n   a8,  a3, 20\n"
      "l32i.n   a8,  a4, 24\n"
      "s32i.n   a8,  a3, 24\n"
      "l32i.n   a8,  a4, 28\n"
      "s32i.n   a8,  a3, 28\n"
      "l32i.n   a8,  a4, 32\n"
      "s32i.n   a8,  a3, 32\n"
      "l32i.n   a8,  a4, 36\n"
      "s32i.n   a8,  a3, 36\n"
      "l32i.n   a8,  a4, 40\n"
      "s32i.n   a8,  a3, 40\n"
      "l32i.n   a8,  a4, 44\n"
      "s32i.n   a8,  a3, 44\n"
      "l32i.n   a8,  a4, 48\n"
      "s32i.n   a8,  a3, 48\n"
      "l32i.n   a8,  a4, 52\n"
      "s32i.n   a8,  a3, 52\n"
      "l32i.n   a8,  a4, 56\n"
      "s32i.n   a8,  a3, 56\n"
      "l32i.n   a8,  a4, 60\n"
      "s32i.n   a8,  a3, 60\n"
      "s32i.n   a10, a5, 0\n"
      "memw\n"
      // Give SHA time to latch TEXT before the tail overwrites it. Without
      // this window the timed self-test falls back to the polling engine.
      ".rept 12\n"
      "nop.n\n"
      ".endr\n"

      "20:\n"
      // Stage the nonce-bearing tail during the first compression.
      "l32i     a8,  a4, 64\n"
      "s32i.n   a8,  a3, 0\n"
      "l32i     a8,  a4, 68\n"
      "s32i.n   a8,  a3, 4\n"
      "l32i     a8,  a4, 72\n"
      "s32i.n   a8,  a3, 8\n"
      "s32i.n   a2,  a3, 12\n"
      "s32i.n   a11, a3, 16\n"
      "s32i.n   a14, a3, 20\n"
      "s32i.n   a14, a3, 24\n"
      "s32i.n   a14, a3, 28\n"
      "s32i.n   a14, a3, 32\n"
      "s32i.n   a14, a3, 36\n"
      "s32i.n   a14, a3, 40\n"
      "s32i.n   a14, a3, 44\n"
      "s32i.n   a14, a3, 48\n"
      "s32i.n   a14, a3, 52\n"
      "s32i.n   a14, a3, 56\n"
      "s32i.n   a12, a3, 60\n"
      ".rept 16\n"
      "nop.n\n"
      ".endr\n"
      "s32i.n   a10, a5, 4\n"

      // Allow the tail compression to finish before loading its digest.
      ".rept 64\n"
      "nop.n\n"
      ".endr\n"

      "s32i.n   a10, a5, 8\n"
      ".rept 12\n"
      "nop.n\n"
      ".endr\n"

      // Words 0-7 now hold the first digest; finish its padded block.
      "s32i.n   a11, a3, 32\n"
      "s32i.n   a13, a3, 60\n"
      "s32i.n   a10, a5, 0\n"
      "memw\n"

      "addi.n   a2,  a2, 1\n"
      ".rept 48\n"
      "nop.n\n"
      ".endr\n"

      // Stage the upper half of the next fixed block while SHA is busy.
      "l32i.n   a8,  a4, 32\n"
      "s32i.n   a8,  a3, 32\n"
      "l32i.n   a8,  a4, 36\n"
      "s32i.n   a8,  a3, 36\n"
      "l32i.n   a8,  a4, 40\n"
      "s32i.n   a8,  a3, 40\n"
      "l32i.n   a8,  a4, 44\n"
      "s32i.n   a8,  a3, 44\n"
      "l32i.n   a8,  a4, 48\n"
      "s32i.n   a8,  a3, 48\n"
      "l32i.n   a8,  a4, 52\n"
      "s32i.n   a8,  a3, 52\n"
      "l32i.n   a8,  a4, 56\n"
      "s32i.n   a8,  a3, 56\n"
      "l32i.n   a8,  a4, 60\n"
      "s32i.n   a8,  a3, 60\n"
      "s32i.n   a10, a5, 8\n"
      ".rept 16\n"
      "nop.n\n"
      ".endr\n"

      "l16ui    a8,  a3, 28\n"
      "and      a8,  a8, a9\n"
      "beqz.n   a8,  22f\n"
      "beq      a2,  a7, 23f\n"

      // Complete the next fixed block and immediately restart the pipeline.
      "l32i.n   a8,  a4, 0\n"
      "s32i.n   a8,  a3, 0\n"
      "l32i.n   a8,  a4, 4\n"
      "s32i.n   a8,  a3, 4\n"
      "l32i.n   a8,  a4, 8\n"
      "s32i.n   a8,  a3, 8\n"
      "l32i.n   a8,  a4, 12\n"
      "s32i.n   a8,  a3, 12\n"
      "l32i.n   a8,  a4, 16\n"
      "s32i.n   a8,  a3, 16\n"
      "l32i.n   a8,  a4, 20\n"
      "s32i.n   a8,  a3, 20\n"
      "l32i.n   a8,  a4, 24\n"
      "s32i.n   a8,  a3, 24\n"
      "l32i.n   a8,  a4, 28\n"
      "s32i.n   a8,  a3, 28\n"
      "s32i.n   a10, a5, 0\n"
      "memw\n"
      ".rept 12\n"
      "nop.n\n"
      ".endr\n"
      "j        20b\n"

      "22:\n"
      "movi.n   a8,  1\n"
      "s32i.n   a8,  %[args], 24\n"
      "j        24f\n"
      "23:\n"
      "movi.n   a8,  0\n"
      "s32i.n   a8,  %[args], 24\n"
      "24:\n"
      "s32i.n   a2,  %[args], 8\n"
      "memw\n"
      :
      : [args] "r"(&args)
      : "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10",
        "a11", "a12", "a13", "a14", "memory");
}

template <bool GuardedRead>
__attribute__((noinline)) IRAM_ATTR void runTimedPipeline(PipelineArgs& args) {
  // Retain the reference build's fixed command spacing and START fences.
  // noinline keeps the assembly in IRAM instead of a flash-resident caller.
  // A multi-nonce self-test gates this path on every individual chip.
  __asm__ __volatile__(
      "l32i     a3,  %[args], 0\n"
      "l32i     a4,  %[args], 4\n"
      "l32i     a2,  %[args], 8\n"
      "l32i     a7,  %[args], 12\n"
      "l32i     a9,  %[args], 16\n"
      "movi     a5,  144\n"
      "add.n    a5,  a5, a3\n"
      "movi.n   a10, 1\n"
      "movi.n   a11, 1\n"
      "slli     a11, a11, 31\n"
      "movi     a12, 640\n"
      "movi     a13, 256\n"
      "movi.n   a14, 0\n"

      // Prime the pipeline with the fixed first 64 bytes.
      "l32i.n   a8,  a4, 0\n"
      "s32i.n   a8,  a3, 0\n"
      "l32i.n   a8,  a4, 4\n"
      "s32i.n   a8,  a3, 4\n"
      "l32i.n   a8,  a4, 8\n"
      "s32i.n   a8,  a3, 8\n"
      "l32i.n   a8,  a4, 12\n"
      "s32i.n   a8,  a3, 12\n"
      "l32i.n   a8,  a4, 16\n"
      "s32i.n   a8,  a3, 16\n"
      "l32i.n   a8,  a4, 20\n"
      "s32i.n   a8,  a3, 20\n"
      "l32i.n   a8,  a4, 24\n"
      "s32i.n   a8,  a3, 24\n"
      "l32i.n   a8,  a4, 28\n"
      "s32i.n   a8,  a3, 28\n"
      "l32i.n   a8,  a4, 32\n"
      "s32i.n   a8,  a3, 32\n"
      "l32i.n   a8,  a4, 36\n"
      "s32i.n   a8,  a3, 36\n"
      "l32i.n   a8,  a4, 40\n"
      "s32i.n   a8,  a3, 40\n"
      "l32i.n   a8,  a4, 44\n"
      "s32i.n   a8,  a3, 44\n"
      "l32i.n   a8,  a4, 48\n"
      "s32i.n   a8,  a3, 48\n"
      "l32i.n   a8,  a4, 52\n"
      "s32i.n   a8,  a3, 52\n"
      "l32i.n   a8,  a4, 56\n"
      "s32i.n   a8,  a3, 56\n"
      "l32i.n   a8,  a4, 60\n"
      "s32i.n   a8,  a3, 60\n"
      "s32i.n   a10, a5, 0\n"
      "memw\n"
      // Retain the validated command spacing before TEXT is reused.
      ".rept 12\n"
      "nop.n\n"
      ".endr\n"

      "20:\n"
      // Stage the nonce-bearing tail during the first compression.
      "l32i     a8,  a4, 64\n"
      "s32i.n   a8,  a3, 0\n"
      "l32i     a8,  a4, 68\n"
      "s32i.n   a8,  a3, 4\n"
      "l32i     a8,  a4, 72\n"
      "s32i.n   a8,  a3, 8\n"
      "s32i.n   a2,  a3, 12\n"
      "s32i.n   a11, a3, 16\n"
      "s32i.n   a14, a3, 20\n"
      "s32i.n   a14, a3, 24\n"
      "s32i.n   a14, a3, 28\n"
      "s32i.n   a14, a3, 32\n"
      "s32i.n   a14, a3, 36\n"
      "s32i.n   a14, a3, 40\n"
      "s32i.n   a14, a3, 44\n"
      "s32i.n   a14, a3, 48\n"
      "s32i.n   a14, a3, 52\n"
      "s32i.n   a14, a3, 56\n"
      "s32i.n   a12, a3, 60\n"
      ".rept 16\n"
      "nop.n\n"
      ".endr\n"
      "s32i.n   a10, a5, 4\n"

      // Allow the tail compression to finish before loading its digest.
      ".rept 64\n"
      "nop.n\n"
      ".endr\n"

      "s32i.n   a10, a5, 8\n"
      ".rept 12\n"
      "nop.n\n"
      ".endr\n"

      // Words 0-7 now hold the first digest; finish its padded block.
      "s32i.n   a11, a3, 32\n"
      "s32i.n   a13, a3, 60\n"
      "s32i.n   a10, a5, 0\n"
      "memw\n"

      "addi.n   a2,  a2, 1\n"
      ".rept 48\n"
      "nop.n\n"
      ".endr\n"

      // Stage the upper half of the next fixed block while SHA is busy.
      "l32i.n   a8,  a4, 32\n"
      "s32i.n   a8,  a3, 32\n"
      "l32i.n   a8,  a4, 36\n"
      "s32i.n   a8,  a3, 36\n"
      "l32i.n   a8,  a4, 40\n"
      "s32i.n   a8,  a3, 40\n"
      "l32i.n   a8,  a4, 44\n"
      "s32i.n   a8,  a3, 44\n"
      "l32i.n   a8,  a4, 48\n"
      "s32i.n   a8,  a3, 48\n"
      "l32i.n   a8,  a4, 52\n"
      "s32i.n   a8,  a3, 52\n"
      "l32i.n   a8,  a4, 56\n"
      "s32i.n   a8,  a3, 56\n"
      "l32i.n   a8,  a4, 60\n"
      "s32i.n   a8,  a3, 60\n"
      "s32i.n   a10, a5, 8\n"
      ".rept 16\n"
      "nop.n\n"
      ".endr\n"

      // CPU-3.10 is fixed in revision 3.0. Select the specialization once
      // per batch, not a branch per nonce; retain the original LOAD delay.
      ".if %[guardedRead]\n"
      HELIOS_SHA_READ("a3", "28", "a6")
      ".else\n"
      "l32i.n   a8,  a3, 28\n"
      ".endif\n"
      "and      a8,  a8, a9\n"
      "beqz.n   a8,  22f\n"
      "beq      a2,  a7, 23f\n"

      // Complete the next fixed block and immediately restart the pipeline.
      "l32i.n   a8,  a4, 0\n"
      "s32i.n   a8,  a3, 0\n"
      "l32i.n   a8,  a4, 4\n"
      "s32i.n   a8,  a3, 4\n"
      "l32i.n   a8,  a4, 8\n"
      "s32i.n   a8,  a3, 8\n"
      "l32i.n   a8,  a4, 12\n"
      "s32i.n   a8,  a3, 12\n"
      "l32i.n   a8,  a4, 16\n"
      "s32i.n   a8,  a3, 16\n"
      "l32i.n   a8,  a4, 20\n"
      "s32i.n   a8,  a3, 20\n"
      "l32i.n   a8,  a4, 24\n"
      "s32i.n   a8,  a3, 24\n"
      "l32i.n   a8,  a4, 28\n"
      "s32i.n   a8,  a3, 28\n"
      "s32i.n   a10, a5, 0\n"
      "memw\n"
      ".rept 12\n"
      "nop.n\n"
      ".endr\n"
      "j        20b\n"

      "22:\n"
      "movi.n   a8,  1\n"
      "s32i.n   a8,  %[args], 24\n"
      "j        24f\n"
      "23:\n"
      "movi.n   a8,  0\n"
      "s32i.n   a8,  %[args], 24\n"
      "24:\n"
      "s32i.n   a2,  %[args], 8\n"
      "memw\n"
      :
      : [args] "r"(&args), [guardedRead] "i"(GuardedRead ? 1 : 0)
      : "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10",
        "a11", "a12", "a13", "a14", "memory");
}

bool mineLocked(const uint32_t headerSwapped[20],
                uint32_t& nextNonceSwapped, uint16_t leadingZeroMask,
                uint32_t maxHashes, SoloHunterSha256Result& result,
                bool readFinalDigest = false) {
  if (maxHashes == 0) return false;

  PipelineArgs args;
  args.shaBase = reinterpret_cast<volatile uint32_t*>(SHA_TEXT_BASE);
  args.header = headerSwapped;
  args.nonce = nextNonceSwapped;
  args.limit = maxHashes;
  args.filterMask = leadingZeroMask;
  args.hashes = 0;
  args.found = 0;
  const uint32_t startingNonce = args.nonce;

  if (!prepareShaPeripheral()) return false;
  if (timedPipeline) {
    // The timed loop compares directly against an exclusive end nonce. This
    // removes both a counter increment and a countdown instruction per hash.
    args.limit = args.nonce + maxHashes;
    if (nativeDportReads.load()) {
      if (referenceNativePipeline.load()) {
        runReferenceNativePipeline(args);
      } else {
        runTimedPipeline<false>(args);
      }
    } else {
      runTimedPipeline<true>(args);
    }
    args.hashes = args.nonce - startingNonce;
  } else {
    runPollingPipeline(args);
  }
  if (args.found == 2) {
    lastFault.store("POLLING BUSY TIMEOUT");
    resetShaPeripheral();
    return false;
  }
  nextNonceSwapped = args.nonce;
  result.hashes = args.hashes;
  result.candidate = args.found != 0;
  if (result.candidate || readFinalDigest) {
    // Fixed-cycle filtering is the hot path, but a full digest snapshot must
    // wait for LOAD to finish. This runs only at a candidate/test boundary.
    if (!waitForShaIdle()) {
      lastFault.store("DIGEST READ BUSY TIMEOUT");
      return false;
    }
    result.nonce = __builtin_bswap32(nextNonceSwapped - 1);
    readDigest(result.hash);
  }
  return true;
}

bool genesisSelfTest() {
  static const uint8_t genesisHeader[80] = {
      0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0xa3, 0xed, 0xfd,
      0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76,
      0x8f, 0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32,
      0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a, 0x29, 0xab,
      0x5f, 0x49, 0xff, 0xff, 0x00, 0x1d, 0x1d, 0xac, 0x2b, 0x7c};
  static const uint8_t expectedHash[32] = {
      0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6,
      0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65,
      0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00,
      0x00, 0x00};

  uint32_t swappedHeader[20];
  for (size_t i = 0; i < 20; ++i) {
    uint32_t word;
    memcpy(&word, genesisHeader + i * 4, sizeof(word));
    swappedHeader[i] = __builtin_bswap32(word);
  }

  constexpr uint32_t SELF_TEST_HASHES = 513;
  uint32_t nonce =
      __builtin_bswap32(0x7c2bac1d) - (SELF_TEST_HASHES - 1);
  SoloHunterSha256Result result;
  if (!mineLocked(swappedHeader, nonce, 0xFFFF, SELF_TEST_HASHES, result)) {
    return false;
  }
  return result.candidate && result.hashes == SELF_TEST_HASHES &&
         result.nonce == 0x7c2bac1d &&
         memcmp(result.hash, expectedHash, sizeof(expectedHash)) == 0;
}

bool softwareReferenceSha256(const uint8_t* input, size_t length,
                             uint8_t output[32]) {
  mbedtls_sha256_context context;
  mbedtls_sha256_init(&context);
  int result = mbedtls_sha256_starts(&context, 0);
#if defined(MBEDTLS_SHA256_ALT)
#if SOC_SHA_SUPPORT_PARALLEL_ENG
  // This diagnostic must not depend on the peripheral it is checking.
  context.mode = ESP_MBEDTLS_SHA256_SOFTWARE;
#else
  mbedtls_sha256_free(&context);
  return false;
#endif
#endif
  if (result == 0) result = mbedtls_sha256_update(&context, input, length);
  if (result == 0) result = mbedtls_sha256_finish(&context, output);
  mbedtls_sha256_free(&context);
  return result == 0;
}

void captureVariedFailure(const char* reason, uint32_t seed,
                         uint32_t before, uint32_t next,
                         const uint32_t words[20], const uint8_t header[80],
                         const SoloHunterSha256Result& result,
                         const uint8_t expected[32]) {
  if (failureCaptured.load(std::memory_order_acquire)) return;
  SoloHunterSha256Failure record;
  record.reason = reason;
  record.timing = !timedPipeline ? "POLLING" :
      (nativeDportReads.load() ?
          (referenceNativePipeline.load() ? "REFERENCE_NATIVE_DPORT"
                                          : "NATIVE_DPORT")
          : "GUARDED_DPORT");
  record.uptimeMs = millis();
  record.seed = seed;
  record.startNonceSwapped = before;
  record.nextNonceSwapped = next;
  record.nonce = result.nonce;
  record.hashes = result.hashes;
  record.candidate = result.candidate;
  memcpy(record.referenceHeader, header, sizeof(record.referenceHeader));
  for (size_t i = 0; i < 20; ++i) {
    const uint32_t word = __builtin_bswap32(words[i]);
    memcpy(record.hardwareHeader + i * sizeof(word), &word, sizeof(word));
  }
  for (size_t i = 0; i < 4; ++i) {
    record.hardwareHeader[76 + i] =
        static_cast<uint8_t>(result.nonce >> (i * 8));
  }
  memcpy(record.hardwareHash, result.hash, sizeof(record.hardwareHash));
  memcpy(record.referenceHash, expected, sizeof(record.referenceHash));
  record.rereadValid = waitForShaIdle();
  if (record.rereadValid) readDigest(record.rereadHash);
  uint8_t first[32];
  record.softwareReferenceOk =
      softwareReferenceSha256(header, 80, first) &&
      softwareReferenceSha256(first, sizeof(first), record.softwareHash);
  // One mining-thread writer; publish once, then keep the record immutable.
  firstFailure = record;
  failureCaptured.store(true, std::memory_order_release);
}

bool failVariedSelfTest(const char* reason) {
  lastSelfTestFailure.store(reason);
  return false;
}

bool variedHeaderSelfTest() {
  // Check full digests after long, uninterrupted runs with nonzero headers,
  // including nonce wraparound. All SHA engines are reserved here, so the
  // mbedTLS reference falls back to software rather than testing against itself.
  for (uint32_t seed = 0; seed < 8; ++seed) {
    uint8_t header[80];
    uint32_t words[20];
    uint32_t pattern = 0x9E3779B9U ^ seed;
    for (size_t i = 0; i < sizeof(header); ++i) {
      pattern ^= pattern << 13;
      pattern ^= pattern >> 17;
      pattern ^= pattern << 5;
      header[i] = static_cast<uint8_t>(pattern);
    }
    for (size_t i = 0; i < 20; ++i) {
      uint32_t word;
      memcpy(&word, header + i * 4, sizeof(word));
      words[i] = __builtin_bswap32(word);
    }
    uint32_t next = seed == 0 ? 0xFFFFF800U : pattern;
    uint32_t remaining = 4096;
    while (remaining != 0) {
      const uint32_t before = next;
      SoloHunterSha256Result result;
      if (!mineLocked(words, next, 0xFFFF, remaining, result, true)) {
        return failVariedSelfTest("VARIED PIPELINE ERROR");
      }
      if (result.hashes == 0 || result.hashes > remaining ||
          next != before + result.hashes ||
          result.nonce != __builtin_bswap32(next - 1)) {
        return failVariedSelfTest("VARIED NONCE ACCOUNTING");
      }
      for (size_t i = 0; i < 4; ++i) {
        header[76 + i] = static_cast<uint8_t>(result.nonce >> (i * 8));
      }
      uint8_t first[32];
      uint8_t expected[32];
      if (mbedtls_sha256(header, sizeof(header), first, 0) != 0 ||
          mbedtls_sha256(first, sizeof(first), expected, 0) != 0) {
        return failVariedSelfTest("VARIED REFERENCE ERROR");
      }
      if (memcmp(result.hash, expected, sizeof(expected)) != 0) {
        captureVariedFailure("VARIED DIGEST MISMATCH", seed, before, next,
                            words, header, result, expected);
        return failVariedSelfTest("VARIED DIGEST MISMATCH");
      }
      if (result.candidate != (expected[30] == 0 && expected[31] == 0)) {
        captureVariedFailure("VARIED FILTER MISMATCH", seed, before, next,
                            words, header, result, expected);
        return failVariedSelfTest("VARIED FILTER MISMATCH");
      }
      remaining -= result.hashes;
    }
  }
  return true;
}

bool hardwareSelfTest() {
  if (!genesisSelfTest()) {
    lastSelfTestFailure.store("GENESIS");
    return false;
  }
  if (!variedHeaderSelfTest()) {
    return false;
  }
  return true;
}

void recordFallback(const char* reason) {
  lastFault.store(reason);
  lastFallback.store(reason);
}

bool revalidateCurrentPipeline() {
  for (uint8_t attempt = 0; attempt < FAST_SELF_TEST_ATTEMPTS; ++attempt) {
    resetShaPeripheral();
    if (hardwareSelfTest()) {
      lastSelfTestFailure.store("NONE");
      return true;
    }
    if (attempt + 1 < FAST_SELF_TEST_ATTEMPTS) {
      vTaskDelay(pdMS_TO_TICKS(1));
    }
  }
  return false;
}

bool selectValidatedFastPipeline() {
  referenceNativePipeline.store(nativeDportReads.load());
  if (referenceNativePipeline.load()) {
    if (revalidateCurrentPipeline()) {
      referenceValidation.store("PASSED");
      return true;
    }
    referenceValidation.store(lastSelfTestFailure.load());
    referenceNativePipeline.store(false);
  } else {
    referenceValidation.store("NOT ELIGIBLE");
  }
  // A failed reference test retains the known FAST loop, not SAFE mode.
  return revalidateCurrentPipeline();
}

}  // namespace

bool soloHunterSha256GetFailure(SoloHunterSha256Failure& output) {
  if (!failureCaptured.load(std::memory_order_acquire)) return false;
  output = firstFailure;
  return true;
}

bool soloHunterSha256Begin() {
  if (hardwareLocked) return true;
  esp_chip_info_t chip = {};
  esp_chip_info(&chip);
  detectedChipRevision.store(chip.revision);
  if (!tryLockShaHardware()) return false;
  timedPipeline = getCpuFrequencyMhz() == 240 &&
                  getApbFrequency() == 80000000;
  // Generic Arduino builds target old ESP32s, so their compile-time DPORT
  // workaround remains enabled even on v3 silicon. Revision uses MXX units.
  // https://docs.espressif.com/projects/esp-chip-errata/en/latest/esp32/03-errata-description/esp32/cpu-read-error-of-dual-core-cpu.html
  nativeDportReads.store(timedPipeline && chip.model == CHIP_ESP32 &&
                        chip.revision >= 300 && !nativeReadsRejected);
  if (!timedPipeline) recordFallback("CLOCKS NOT 240/80 MHZ");
  referenceNativePipeline.store(false);
  const bool ok = timedPipeline ? selectValidatedFastPipeline()
                                : hardwareSelfTest();
  if (ok) {
    // Keep SHA reserved for mining so concurrent TLS uses software SHA.
    hardwareLocked = true;
    lastFallback.store("NONE");
  } else {
    recordFallback(timedPipeline ? "FAST STARTUP RETRIES EXHAUSTED"
                                 : "SAFE STARTUP SELF-TEST FAILED");
    unlockShaHardware();
  }
  return ok;
}

bool soloHunterSha256Mine(const uint32_t headerSwapped[20],
                           uint32_t& nextNonceSwapped,
                           uint16_t leadingZeroMask, uint32_t maxHashes,
                           SoloHunterSha256Result& result) {
  if (!hardwareLocked) return false;
  return mineLocked(headerSwapped, nextNonceSwapped, leadingZeroMask,
                    maxHashes, result);
}

bool soloHunterSha256FastPathActive() {
  return hardwareLocked && timedPipeline;
}

bool soloHunterSha256Recover() {
  recoveryCount.fetch_add(1);
  lastFault.store("CANDIDATE HASH MISMATCH");
  if (!hardwareLocked) return soloHunterSha256Begin();

  // A transient mismatch must not permanently demote a proven FAST device.
  // Reset and fully validate the same pipeline several times. If it remains
  // invalid, release hardware temporarily; the miner retries FAST later.
  bool ok = timedPipeline ? revalidateCurrentPipeline()
                          : (resetShaPeripheral(), hardwareSelfTest());
  if (!ok && referenceNativePipeline.load()) {
    referenceValidation.store(lastSelfTestFailure.load());
    referenceNativePipeline.store(false);
    ok = revalidateCurrentPipeline();
  }
  if (ok) {
    lastFallback.store("NONE");
    return true;
  }

  recordFallback(timedPipeline ? "FAST RECOVERY RETRIES EXHAUSTED"
                               : "SAFE RECOVERY SELF-TEST FAILED");
  hardwareLocked = false;
  unlockShaHardware();
  return false;
}

const char* soloHunterSha256LastFault() {
  return lastFault.load();
}

const char* soloHunterSha256LastFallback() {
  return lastFallback.load();
}

const char* soloHunterSha256LastSelfTestFailure() {
  return lastSelfTestFailure.load();
}

const char* soloHunterSha256Timing() {
  if (!hardwareLocked) return "SOFTWARE";
  if (!timedPipeline) return "POLLING";
  if (!nativeDportReads.load()) return "GUARDED_DPORT";
  return referenceNativePipeline.load() ? "REFERENCE_NATIVE_DPORT"
                                        : "NATIVE_DPORT";
}

const char* soloHunterSha256ReferenceValidation() {
  return referenceValidation.load();
}

uint32_t soloHunterSha256ChipRevision() {
  return detectedChipRevision.load();
}

uint32_t soloHunterSha256RecoveryCount() {
  return recoveryCount.load();
}

#undef HELIOS_SHA_READ
#undef HELIOS_SHA_WAIT_IDLE

#else

bool soloHunterSha256GetFailure(SoloHunterSha256Failure&) {
  return false;
}

bool soloHunterSha256Begin() {
  return false;
}

bool soloHunterSha256Mine(const uint32_t[20], uint32_t&, uint16_t, uint32_t,
                          SoloHunterSha256Result&) {
  return false;
}

bool soloHunterSha256FastPathActive() {
  return false;
}

bool soloHunterSha256Recover() {
  return false;
}

const char* soloHunterSha256LastFault() {
  return "HARDWARE SHA UNSUPPORTED";
}

const char* soloHunterSha256LastFallback() {
  return "HARDWARE SHA UNSUPPORTED";
}

const char* soloHunterSha256LastSelfTestFailure() {
  return "NONE";
}

const char* soloHunterSha256Timing() {
  return "SOFTWARE";
}

uint32_t soloHunterSha256ChipRevision() {
  return 0;
}

uint32_t soloHunterSha256RecoveryCount() {
  return 0;
}

const char* soloHunterSha256ReferenceValidation() {
  return "NOT ELIGIBLE";
}

#endif
