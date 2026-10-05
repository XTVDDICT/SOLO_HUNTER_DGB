#include "SoloHunterMiner.h"
#include "SoloHunterSha256.h"

#include <ArduinoJson.h>
#include <Client.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <WiFiClientSecure.h>
#include <math.h>
#include <mbedtls/sha256.h>
#include <new>

namespace {

constexpr size_t MAX_MERKLE_BRANCHES = 32;
constexpr size_t MAX_STRATUM_LINE = 12288;
constexpr uint32_t HASH_BATCH_SIZE = 256;
constexpr uint32_t AUXILIARY_HASH_BATCH_SIZE = 1024;
constexpr uint8_t AUXILIARY_BATCHES_BEFORE_DELAY = 16;
constexpr uint32_t HARDWARE_HASH_BATCH_SIZE = 65536;
constexpr uint8_t HARDWARE_BATCHES_BEFORE_DELAY = 16;
// Run the software helper below all UI/network work and block it every batch.
// Its nonce range is disjoint from the hardware engine, so these are real
// additional attempts rather than duplicated hashrate.
constexpr bool ENABLE_AUXILIARY_MINING = true;
constexpr uint32_t CONNECT_RETRY_MS = 5000;
constexpr uint32_t HANDSHAKE_TIMEOUT_MS = 15000;
constexpr uint32_t NO_JOB_TIMEOUT_MS = 10UL * 60UL * 1000UL;
constexpr uint32_t POOL_SILENCE_TIMEOUT_MS = 30UL * 60UL * 1000UL;
constexpr uint32_t HASHRATE_WINDOW_MS = 1000;
constexpr uint32_t HARDWARE_RETRY_MS = 5000;
constexpr float HASHRATE_SMOOTHING = 0.20f;
constexpr double SUGGESTED_DIFFICULTY = 0.001;
constexpr double DIFF_ONE_TARGET =
    26959535291011309493156476344723991336010898738574164086137773096960.0;
constexpr uint32_t SHA256_INITIAL_STATE[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
DRAM_ATTR const uint32_t SHA256_ROUND_CONSTANTS[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

struct PoolEndpoint {
  String host;
  uint16_t port = 3333;
  bool tls = false;
};

struct StratumJob {
  bool valid = false;
  String jobId;
  String prevHash;
  String coinbase1;
  String coinbase2;
  String version;
  String nbits;
  String ntime;
  String merkleBranches[MAX_MERKLE_BRANCHES];
  size_t merkleBranchCount = 0;
  String extranonce2;
  uint8_t header[80] = {0};
  uint32_t nextNonce = 0;
};

struct PendingShare {
  bool used = false;
  uint32_t id = 0;
  double difficulty = 0.0;
};

struct MiningSession {
  bool connected = false;
  bool subscribed = false;
  bool authorized = false;
  uint32_t subscribeId = 1;
  uint32_t authorizeId = 2;
  uint32_t nextRequestId = 10;
  uint32_t connectedAt = 0;
  uint32_t lastPoolMessageAt = 0;
  uint32_t lastJobAt = 0;
  uint64_t extranonce2Counter = 0;
  String extranonce1;
  uint8_t extranonce2Size = 0;
  double poolDifficulty = 1.0;
  uint8_t shareTarget[32] = {0};
  uint8_t blockTarget[32] = {0};
  uint8_t bestHash[32] = {0};
  String rxLine;
  StratumJob job;
  PendingShare pending[12];
  uint32_t midstate[8] = {0};
  uint32_t hashSchedule[64] = {0};
  bool midstateReady = false;
  uint32_t hardwareHeader[20] = {0};
  uint32_t hardwareNonceSwapped = 0;
  bool hardwareReady = false;
  uint32_t auxiliaryGeneration = 0;
};

struct AuxiliaryMiningWork {
  bool valid = false;
  uint32_t generation = 0;
  uint32_t nextNonceSwapped = 0;
  uint32_t midstate[8] = {0};
  uint8_t headerTail[16] = {0};
  uint8_t shareTarget[32] = {0};
  uint8_t blockTarget[32] = {0};
};

struct AuxiliaryMiningBatch {
  uint32_t generation = 0;
  uint32_t firstNonceSwapped = 0;
  uint32_t midstate[8] = {0};
  uint8_t headerTail[16] = {0};
  uint8_t shareTarget[32] = {0};
  uint8_t blockTarget[32] = {0};
};

struct AuxiliaryCandidate {
  uint32_t generation = 0;
  uint32_t nonce = 0;
  uint8_t hash[32] = {0};
};

SemaphoreHandle_t stateMutex = nullptr;
TaskHandle_t minerTaskHandle = nullptr;
TaskHandle_t auxiliaryMinerTaskHandle = nullptr;
QueueHandle_t auxiliaryCandidateQueue = nullptr;
portMUX_TYPE auxiliaryWorkMux = portMUX_INITIALIZER_UNLOCKED;
AuxiliaryMiningWork auxiliaryWork;
uint32_t auxiliaryHashesPending = 0;
SoloHunterMiningConfig activeConfig;
SoloHunterMiningStats activeStats;
volatile uint32_t configRevision = 0;
uint32_t statsStartedAt = 0;

void lockState() {
  if (stateMutex != nullptr) xSemaphoreTake(stateMutex, portMAX_DELAY);
}

void unlockState() {
  if (stateMutex != nullptr) xSemaphoreGive(stateMutex);
}

void setStatus(const String& status) {
  lockState();
  activeStats.status = status;
  unlockState();
}

void setHashTelemetry(float hashrateKh, float primaryHashrateKh,
                      float auxiliaryHashrateKh, uint64_t totalHashes,
                      bool hardwareSha) {
  lockState();
  activeStats.hashrateKh = hashrateKh;
  activeStats.primaryHashrateKh = primaryHashrateKh;
  activeStats.auxiliaryHashrateKh = auxiliaryHashrateKh;
  activeStats.totalHashes = totalHashes;
  activeStats.hardwareSha = hardwareSha;
  unlockState();
}

void setHashrate(float hashrateKh) {
  lockState();
  activeStats.hashrateKh = hashrateKh;
  if (hashrateKh <= 0.0f) {
    activeStats.primaryHashrateKh = 0.0f;
    activeStats.auxiliaryHashrateKh = 0.0f;
  }
  unlockState();
}

void setPoolDifficulty(double difficulty) {
  lockState();
  activeStats.poolDifficulty = difficulty;
  unlockState();
}

void recordBestDifficulty(double difficulty) {
  lockState();
  if (difficulty > activeStats.bestDifficulty) activeStats.bestDifficulty = difficulty;
  unlockState();
}

void recordShareResult(bool accepted) {
  lockState();
  if (accepted) {
    activeStats.acceptedShares++;
  } else {
    activeStats.rejectedShares++;
  }
  unlockState();
}

void recordSubmittedShare(uint32_t pendingShares) {
  lockState();
  activeStats.submittedShares++;
  activeStats.pendingShares = pendingShares;
  unlockState();
}

void recordBlockFound() {
  lockState();
  activeStats.blocksFound++;
  unlockState();
}

void recordPoolReconnect() {
  lockState();
  activeStats.poolReconnects++;
  unlockState();
}

void setPendingShares(uint32_t pendingShares) {
  lockState();
  activeStats.pendingShares = pendingShares;
  unlockState();
}

void setHardwareSha(bool hardwareSha) {
  lockState();
  activeStats.hardwareSha = hardwareSha;
  unlockState();
}

void resetRunStats(bool hardwareSha) {
  lockState();
  activeStats.hashrateKh = 0.0f;
  activeStats.primaryHashrateKh = 0.0f;
  activeStats.auxiliaryHashrateKh = 0.0f;
  activeStats.totalHashes = 0;
  activeStats.submittedShares = 0;
  activeStats.pendingShares = 0;
  activeStats.acceptedShares = 0;
  activeStats.rejectedShares = 0;
  activeStats.blocksFound = 0;
  activeStats.uptimeSeconds = 0;
  activeStats.bestDifficulty = 0.0;
  activeStats.poolDifficulty = 0.0;
  activeStats.hardwareSha = hardwareSha;
  activeStats.status = activeConfig.enabled ? "STARTING" : "OFF";
  statsStartedAt = activeConfig.enabled ? millis() : 0;
  unlockState();
}

SoloHunterMiningConfig copyConfig(uint32_t& revision) {
  lockState();
  SoloHunterMiningConfig copy = activeConfig;
  revision = configRevision;
  unlockState();
  return copy;
}

uint32_t currentConfigRevision() {
  // Aligned 32-bit reads are atomic on ESP32. The full configuration is still
  // copied under the mutex only after this inexpensive change check fires.
  return configRevision;
}

String lowerCopy(String value) {
  value.toLowerCase();
  return value;
}

bool allDigits(const String& value) {
  if (value.isEmpty()) return false;
  for (size_t i = 0; i < value.length(); ++i) {
    if (!isDigit(value[i])) return false;
  }
  return true;
}

PoolEndpoint parseEndpoint(const SoloHunterMiningConfig& config) {
  PoolEndpoint endpoint;
  endpoint.host = config.poolHost;
  endpoint.host.trim();
  endpoint.port = config.poolPort > 0 ? config.poolPort : 3333;

  String lower = lowerCopy(endpoint.host);
  const char* schemes[] = {"stratum+ssl://", "stratum+tls://", "ssl://", "tls://",
                           "stratum+tcp://", "tcp://"};
  for (size_t i = 0; i < sizeof(schemes) / sizeof(schemes[0]); ++i) {
    String scheme = schemes[i];
    if (!lower.startsWith(scheme)) continue;
    endpoint.tls = (scheme.indexOf("ssl") >= 0 || scheme.indexOf("tls") >= 0);
    endpoint.host.remove(0, scheme.length());
    break;
  }

  int slash = endpoint.host.indexOf('/');
  if (slash >= 0) endpoint.host = endpoint.host.substring(0, slash);

  int colon = endpoint.host.lastIndexOf(':');
  if (colon > 0 && endpoint.host.indexOf(':') == colon) {
    String portText = endpoint.host.substring(colon + 1);
    if (allDigits(portText)) {
      long parsedPort = portText.toInt();
      if (parsedPort > 0 && parsedPort <= 65535) endpoint.port = (uint16_t)parsedPort;
      endpoint.host = endpoint.host.substring(0, colon);
    }
  }

  endpoint.host.trim();
  return endpoint;
}

String workerLogin(const SoloHunterMiningConfig& config) {
  String login = config.username;
  login.trim();
  String worker = config.worker;
  worker.trim();
  if (worker.isEmpty()) return login;
  if (worker.startsWith(".")) return login + worker;
  return login + "." + worker;
}

uint8_t hexNibble(char ch) {
  if (ch >= '0' && ch <= '9') return (uint8_t)(ch - '0');
  if (ch >= 'a' && ch <= 'f') return (uint8_t)(ch - 'a' + 10);
  if (ch >= 'A' && ch <= 'F') return (uint8_t)(ch - 'A' + 10);
  return 0xFF;
}

bool hexToBytes(const String& hex, uint8_t* output, size_t outputSize) {
  if (hex.length() != outputSize * 2) return false;
  for (size_t i = 0; i < outputSize; ++i) {
    uint8_t high = hexNibble(hex[i * 2]);
    uint8_t low = hexNibble(hex[i * 2 + 1]);
    if (high == 0xFF || low == 0xFF) return false;
    output[i] = (uint8_t)((high << 4) | low);
  }
  return true;
}

bool hexToAllocatedBytes(const String& hex, uint8_t*& output, size_t& outputSize) {
  if (hex.isEmpty() || (hex.length() & 1U) != 0) return false;
  outputSize = hex.length() / 2;
  output = new (std::nothrow) uint8_t[outputSize];
  if (output == nullptr) return false;
  if (!hexToBytes(hex, output, outputSize)) {
    delete[] output;
    output = nullptr;
    outputSize = 0;
    return false;
  }
  return true;
}

void reverseBytes(uint8_t* data, size_t length) {
  for (size_t i = 0; i < length / 2; ++i) {
    uint8_t temp = data[i];
    data[i] = data[length - 1 - i];
    data[length - 1 - i] = temp;
  }
}

void swapEndianWords(uint8_t* data, size_t length) {
  for (size_t offset = 0; offset + 4 <= length; offset += 4) {
    reverseBytes(data + offset, 4);
  }
}

uint32_t loadBigEndian32(const uint8_t* data) {
  return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
         ((uint32_t)data[2] << 8) | (uint32_t)data[3];
}

void storeBigEndian32(uint8_t* output, uint32_t value) {
  output[0] = (uint8_t)(value >> 24);
  output[1] = (uint8_t)(value >> 16);
  output[2] = (uint8_t)(value >> 8);
  output[3] = (uint8_t)value;
}

template <uint8_t Count>
__attribute__((always_inline)) inline uint32_t rotateRight32(uint32_t value) {
#if defined(__XTENSA__)
  uint32_t result;
  __asm__ __volatile__("ssai %1\n\tsrc %0, %2, %2"
                       : "=r"(result)
                       : "i"(Count), "r"(value));
  return result;
#else
  constexpr uint8_t count = Count;
  return (value >> count) | (value << (32 - count));
#endif
}

void sha256Initialize(uint32_t state[8]) {
  memcpy(state, SHA256_INITIAL_STATE, sizeof(SHA256_INITIAL_STATE));
}

IRAM_ATTR __attribute__((optimize("O3"))) void sha256CompressPrepared(
    uint32_t state[8], uint32_t schedule[64]) {
#pragma GCC unroll 48
  for (size_t i = 16; i < 64; ++i) {
    uint32_t s0 = rotateRight32<7>(schedule[i - 15]) ^
                  rotateRight32<18>(schedule[i - 15]) ^
                  (schedule[i - 15] >> 3);
    uint32_t s1 = rotateRight32<17>(schedule[i - 2]) ^
                  rotateRight32<19>(schedule[i - 2]) ^
                  (schedule[i - 2] >> 10);
    schedule[i] =
        schedule[i - 16] + s0 + schedule[i - 7] + s1;
  }

  uint32_t a = state[0];
  uint32_t b = state[1];
  uint32_t c = state[2];
  uint32_t d = state[3];
  uint32_t e = state[4];
  uint32_t f = state[5];
  uint32_t g = state[6];
  uint32_t h = state[7];

#pragma GCC unroll 64
  for (size_t i = 0; i < 64; ++i) {
    uint32_t sum1 = rotateRight32<6>(e) ^ rotateRight32<11>(e) ^
                    rotateRight32<25>(e);
    uint32_t choose = g ^ (e & (f ^ g));
    uint32_t temp1 =
        h + sum1 + choose + SHA256_ROUND_CONSTANTS[i] + schedule[i];
    uint32_t sum0 = rotateRight32<2>(a) ^ rotateRight32<13>(a) ^
                    rotateRight32<22>(a);
    uint32_t majority = (a & b) | (c & (a | b));
    uint32_t temp2 = sum0 + majority;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

void sha256CompressBlock(uint32_t state[8], const uint8_t block[64],
                         uint32_t schedule[64]) {
  for (size_t i = 0; i < 16; ++i) {
    schedule[i] = loadBigEndian32(block + i * 4);
  }
  sha256CompressPrepared(state, schedule);
}

__attribute__((optimize("O3"))) void sha256d80WordsFromMidstate(
    const uint32_t midstate[8], const uint32_t headerTailWords[4],
    uint32_t outputWords[8], uint32_t schedule[64]) {
  uint32_t firstHash[8];
  memcpy(firstHash, midstate, sizeof(firstHash));
  memcpy(schedule, headerTailWords, 4 * sizeof(uint32_t));
  schedule[4] = 0x80000000;
  memset(schedule + 5, 0, 10 * sizeof(uint32_t));
  schedule[15] = 80 * 8;
  sha256CompressPrepared(firstHash, schedule);

  sha256Initialize(outputWords);
  memcpy(schedule, firstHash, sizeof(firstHash));
  schedule[8] = 0x80000000;
  memset(schedule + 9, 0, 6 * sizeof(uint32_t));
  schedule[15] = 32 * 8;
  sha256CompressPrepared(outputWords, schedule);
}

__attribute__((optimize("O3"))) void sha256d80FromMidstate(
    const uint32_t midstate[8], const uint8_t headerTail[16],
    uint8_t output[32], uint32_t schedule[64]) {
  uint32_t headerTailWords[4];
  uint32_t outputWords[8];
  for (size_t i = 0; i < 4; ++i) {
    headerTailWords[i] = loadBigEndian32(headerTail + i * 4);
  }
  sha256d80WordsFromMidstate(midstate, headerTailWords, outputWords,
                             schedule);

  for (size_t i = 0; i < 8; ++i) {
    storeBigEndian32(output + i * 4, outputWords[i]);
  }
}

void sha256d80(const uint8_t header[80], uint8_t output[32],
               uint32_t schedule[64]) {
  uint32_t midstate[8];
  sha256Initialize(midstate);
  sha256CompressBlock(midstate, header, schedule);
  sha256d80FromMidstate(midstate, header + 64, output, schedule);
}

bool sha256d(const uint8_t* data, size_t length, uint8_t output[32]) {
  uint8_t firstHash[32];
  mbedtls_sha256_context context;
  mbedtls_sha256_init(&context);
  bool ok = mbedtls_sha256_starts(&context, 0) == 0 &&
            mbedtls_sha256_update(&context, data, length) == 0 &&
            mbedtls_sha256_finish(&context, firstHash) == 0 &&
            mbedtls_sha256_starts(&context, 0) == 0 &&
            mbedtls_sha256_update(&context, firstHash, sizeof(firstHash)) == 0 &&
            mbedtls_sha256_finish(&context, output) == 0;
  mbedtls_sha256_free(&context);
  return ok;
}

String makeExtranonce2(uint64_t counter, uint8_t byteCount) {
  size_t hexLength = (size_t)byteCount * 2;
  String value;
  value.reserve(hexLength);
  for (size_t i = 0; i < hexLength; ++i) value += '0';
  for (size_t i = 0; i < hexLength && counter != 0; ++i) {
    uint8_t nibble = (uint8_t)(counter & 0x0F);
    value.setCharAt(hexLength - 1 - i, nibble < 10 ? char('0' + nibble) : char('a' + nibble - 10));
    counter >>= 4;
  }
  return value;
}

void targetFromDifficulty(double difficulty, uint8_t target[32]) {
  if (!isfinite(difficulty) || difficulty <= 0.0) difficulty = 1.0;
  double value = DIFF_ONE_TARGET / difficulty;
  const double uint256Limit = 1.1579208923731619542e77;
  if (!isfinite(value) || value >= uint256Limit) {
    memset(target, 0xFF, 32);
    return;
  }

  value *= 0.999999999999;
  for (size_t i = 0; i < 32; ++i) {
    target[i] = (uint8_t)fmod(value, 256.0);
    value = floor(value / 256.0);
  }
}

bool targetFromHex(const String& targetHex, uint8_t target[32]) {
  uint8_t bigEndian[32];
  if (!hexToBytes(targetHex, bigEndian, sizeof(bigEndian))) return false;
  for (size_t i = 0; i < sizeof(bigEndian); ++i) {
    target[i] = bigEndian[sizeof(bigEndian) - 1 - i];
  }
  return true;
}

bool targetFromCompact(uint32_t compact, uint8_t target[32]) {
  uint8_t size = compact >> 24;
  if (size < 3 || size > 32 || !(compact & 0x007FFFFFU) ||
      (compact & 0x00800000U)) {
    return false;
  }
  memset(target, 0, 32);
  uint8_t offset = size - 3;
  target[offset] = (uint8_t)compact;
  target[offset + 1] = (uint8_t)(compact >> 8);
  target[offset + 2] = (uint8_t)(compact >> 16);
  return true;
}

bool hashMeetsTarget(const uint8_t hash[32], const uint8_t target[32]) {
  for (int i = 31; i >= 0; --i) {
    if (hash[i] < target[i]) return true;
    if (hash[i] > target[i]) return false;
  }
  return true;
}

bool hashIsBetter(const uint8_t hash[32], const uint8_t bestHash[32]) {
  for (int i = 31; i >= 0; --i) {
    if (hash[i] < bestHash[i]) return true;
    if (hash[i] > bestHash[i]) return false;
  }
  return false;
}

double difficultyFromHash(const uint8_t hash[32]) {
  double value = 0.0;
  for (int i = 31; i >= 0; --i) value = value * 256.0 + hash[i];
  if (value <= 0.0) return INFINITY;
  return DIFF_ONE_TARGET / value;
}

bool miningMathSelfTest() {
  static const char* GENESIS_HEADER =
      "01000000"
      "0000000000000000000000000000000000000000000000000000000000000000"
      "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
      "29ab5f49ffff001d1dac2b7c";
  static const char* GENESIS_RAW_HASH =
      "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000";

  uint8_t header[80];
  uint8_t hash[32];
  uint8_t optimizedHash[32];
  uint8_t expected[32];
  uint8_t difficultyOneTarget[32];
  uint32_t schedule[64];
  if (!hexToBytes(String(GENESIS_HEADER), header, sizeof(header)) ||
      !hexToBytes(String(GENESIS_RAW_HASH), expected, sizeof(expected)) ||
      !sha256d(header, sizeof(header), hash) ||
      memcmp(hash, expected, sizeof(hash)) != 0) {
    return false;
  }
  sha256d80(header, optimizedHash, schedule);
  if (memcmp(optimizedHash, expected, sizeof(optimizedHash)) != 0) return false;
  targetFromDifficulty(1.0, difficultyOneTarget);
  return hashMeetsTarget(optimizedHash, difficultyOneTarget);
}

bool prepareMidstate(MiningSession& session) {
  sha256Initialize(session.midstate);
  sha256CompressBlock(session.midstate, session.job.header,
                      session.hashSchedule);
  for (size_t i = 0; i < 20; ++i) {
    uint32_t word;
    memcpy(&word, session.job.header + i * 4, sizeof(word));
    session.hardwareHeader[i] = __builtin_bswap32(word);
  }
  session.hardwareNonceSwapped =
      __builtin_bswap32(session.job.nextNonce);
  session.hardwareReady = true;
  session.midstateReady = true;
  return true;
}

uint16_t hardwareLeadingZeroMask(const uint8_t target[32]) {
  uint16_t targetHigh =
      (uint16_t)(((uint16_t)target[31] << 8) | target[30]);
  uint8_t leadingZeros =
      targetHigh == 0 ? 16 : (uint8_t)(__builtin_clz((uint32_t)targetHigh) - 16);
  uint16_t highMask =
      leadingZeros == 0 ? 0 : (uint16_t)(0xFFFFU << (16 - leadingZeros));
  return __builtin_bswap16(highMask);
}

bool hashHeaderNonce(MiningSession& session, uint32_t nonce, uint8_t output[32]) {
  if (!session.midstateReady) return false;
  session.job.header[76] = (uint8_t)(nonce);
  session.job.header[77] = (uint8_t)(nonce >> 8);
  session.job.header[78] = (uint8_t)(nonce >> 16);
  session.job.header[79] = (uint8_t)(nonce >> 24);
  sha256d80FromMidstate(session.midstate, session.job.header + 64, output,
                        session.hashSchedule);
  return true;
}

void clearAuxiliaryWork() {
  portENTER_CRITICAL(&auxiliaryWorkMux);
  auxiliaryWork.valid = false;
  if (++auxiliaryWork.generation == 0) ++auxiliaryWork.generation;
  portEXIT_CRITICAL(&auxiliaryWorkMux);
}

uint32_t publishAuxiliaryWork(const MiningSession& session) {
  portENTER_CRITICAL(&auxiliaryWorkMux);
  if (++auxiliaryWork.generation == 0) ++auxiliaryWork.generation;
  auxiliaryWork.nextNonceSwapped =
      session.hardwareNonceSwapped ^ 0x80000000U;
  memcpy(auxiliaryWork.midstate, session.midstate,
         sizeof(auxiliaryWork.midstate));
  memcpy(auxiliaryWork.headerTail, session.job.header + 64,
         sizeof(auxiliaryWork.headerTail));
  memcpy(auxiliaryWork.shareTarget, session.shareTarget,
         sizeof(auxiliaryWork.shareTarget));
  memcpy(auxiliaryWork.blockTarget, session.blockTarget,
         sizeof(auxiliaryWork.blockTarget));
  auxiliaryWork.valid = session.job.valid && session.midstateReady;
  uint32_t generation = auxiliaryWork.generation;
  portEXIT_CRITICAL(&auxiliaryWorkMux);
  return generation;
}

void refreshAuxiliaryTargets(const MiningSession& session) {
  portENTER_CRITICAL(&auxiliaryWorkMux);
  if (auxiliaryWork.valid &&
      auxiliaryWork.generation == session.auxiliaryGeneration) {
    memcpy(auxiliaryWork.shareTarget, session.shareTarget,
           sizeof(auxiliaryWork.shareTarget));
    memcpy(auxiliaryWork.blockTarget, session.blockTarget,
           sizeof(auxiliaryWork.blockTarget));
  }
  portEXIT_CRITICAL(&auxiliaryWorkMux);
}

bool reserveAuxiliaryBatch(AuxiliaryMiningBatch& batch) {
  portENTER_CRITICAL(&auxiliaryWorkMux);
  bool available = auxiliaryWork.valid;
  if (available) {
    batch.generation = auxiliaryWork.generation;
    batch.firstNonceSwapped = auxiliaryWork.nextNonceSwapped;
    auxiliaryWork.nextNonceSwapped += AUXILIARY_HASH_BATCH_SIZE;
    memcpy(batch.midstate, auxiliaryWork.midstate, sizeof(batch.midstate));
    memcpy(batch.headerTail, auxiliaryWork.headerTail,
           sizeof(batch.headerTail));
    memcpy(batch.shareTarget, auxiliaryWork.shareTarget,
           sizeof(batch.shareTarget));
    memcpy(batch.blockTarget, auxiliaryWork.blockTarget,
           sizeof(batch.blockTarget));
  }
  portEXIT_CRITICAL(&auxiliaryWorkMux);
  return available;
}

void recordAuxiliaryHashes(uint32_t hashes) {
  portENTER_CRITICAL(&auxiliaryWorkMux);
  auxiliaryHashesPending += hashes;
  portEXIT_CRITICAL(&auxiliaryWorkMux);
}

uint32_t drainAuxiliaryHashes() {
  portENTER_CRITICAL(&auxiliaryWorkMux);
  uint32_t hashes = auxiliaryHashesPending;
  auxiliaryHashesPending = 0;
  portEXIT_CRITICAL(&auxiliaryWorkMux);
  return hashes;
}

void auxiliaryMiningTask(void*) {
  uint32_t schedule[64];
  uint32_t headerTailWords[4];
  uint32_t hashWords[8];
  uint8_t hash[32];
  uint8_t batchesBeforeDelay = 0;

  for (;;) {
    AuxiliaryMiningBatch batch;
    if (!reserveAuxiliaryBatch(batch)) {
      vTaskDelay(pdMS_TO_TICKS(20));
      continue;
    }

    for (size_t i = 0; i < 4; ++i) {
      headerTailWords[i] = loadBigEndian32(batch.headerTail + i * 4);
    }
    const uint16_t candidateMask =
        hardwareLeadingZeroMask(batch.shareTarget) &
        hardwareLeadingZeroMask(batch.blockTarget);
    uint32_t nonceSwapped = batch.firstNonceSwapped;
    for (uint32_t i = 0; i < AUXILIARY_HASH_BATCH_SIZE; ++i) {
      const uint32_t thisNonceSwapped = nonceSwapped++;
      headerTailWords[3] = thisNonceSwapped;
      sha256d80WordsFromMidstate(batch.midstate, headerTailWords, hashWords,
                                 schedule);

      const uint16_t highWord =
          __builtin_bswap16((uint16_t)hashWords[7]);
      if ((highWord & candidateMask) != 0) continue;

      for (size_t word = 0; word < 8; ++word) {
        storeBigEndian32(hash + word * 4, hashWords[word]);
      }

      if (hashMeetsTarget(hash, batch.shareTarget) ||
          hashMeetsTarget(hash, batch.blockTarget)) {
        AuxiliaryCandidate candidate;
        candidate.generation = batch.generation;
        candidate.nonce = __builtin_bswap32(thisNonceSwapped);
        memcpy(candidate.hash, hash, sizeof(candidate.hash));
        xQueueSend(auxiliaryCandidateQueue, &candidate, 0);
      }
    }
    recordAuxiliaryHashes(AUXILIARY_HASH_BATCH_SIZE);
    if (++batchesBeforeDelay >= AUXILIARY_BATCHES_BEFORE_DELAY) {
      batchesBeforeDelay = 0;
      vTaskDelay(pdMS_TO_TICKS(1));
    } else {
      // The core-0 idle task has the same priority and gets watchdog time here.
      taskYIELD();
    }
  }
}

bool buildJobHeader(MiningSession& session) {
  StratumJob& job = session.job;
  if (session.extranonce1.isEmpty() || session.extranonce2Size == 0 ||
      session.extranonce2Size > 16) {
    return false;
  }

  job.extranonce2 = makeExtranonce2(++session.extranonce2Counter, session.extranonce2Size);
  String coinbaseHex = job.coinbase1 + session.extranonce1 + job.extranonce2 + job.coinbase2;
  uint8_t* coinbase = nullptr;
  size_t coinbaseSize = 0;
  if (!hexToAllocatedBytes(coinbaseHex, coinbase, coinbaseSize)) return false;

  uint8_t merkleRoot[32];
  bool ok = sha256d(coinbase, coinbaseSize, merkleRoot);
  delete[] coinbase;
  if (!ok) return false;

  uint8_t merklePair[64];
  for (size_t i = 0; i < job.merkleBranchCount; ++i) {
    memcpy(merklePair, merkleRoot, 32);
    if (!hexToBytes(job.merkleBranches[i], merklePair + 32, 32)) return false;
    if (!sha256d(merklePair, sizeof(merklePair), merkleRoot)) return false;
  }

  uint8_t versionBytes[4];
  uint8_t previousBytes[32];
  uint8_t ntimeBytes[4];
  uint8_t nbitsBytes[4];
  if (!hexToBytes(job.version, versionBytes, sizeof(versionBytes)) ||
      !hexToBytes(job.prevHash, previousBytes, sizeof(previousBytes)) ||
      !hexToBytes(job.ntime, ntimeBytes, sizeof(ntimeBytes)) ||
      !hexToBytes(job.nbits, nbitsBytes, sizeof(nbitsBytes))) {
    return false;
  }

  uint32_t compact = ((uint32_t)nbitsBytes[0] << 24) |
                     ((uint32_t)nbitsBytes[1] << 16) |
                     ((uint32_t)nbitsBytes[2] << 8) | nbitsBytes[3];
  if (!targetFromCompact(compact, session.blockTarget)) return false;
  reverseBytes(versionBytes, sizeof(versionBytes));
  swapEndianWords(previousBytes, sizeof(previousBytes));
  reverseBytes(ntimeBytes, sizeof(ntimeBytes));
  reverseBytes(nbitsBytes, sizeof(nbitsBytes));

  memcpy(job.header, versionBytes, sizeof(versionBytes));
  memcpy(job.header + 4, previousBytes, sizeof(previousBytes));
  memcpy(job.header + 36, merkleRoot, sizeof(merkleRoot));
  memcpy(job.header + 68, ntimeBytes, sizeof(ntimeBytes));
  memcpy(job.header + 72, nbitsBytes, sizeof(nbitsBytes));
  memset(job.header + 76, 0, 4);
  job.nextNonce = esp_random();
  job.valid = prepareMidstate(session);
  return job.valid;
}

bool sendDocument(Client& client, JsonDocument& document) {
  if (serializeJson(document, client) == 0) return false;
  return client.print('\n') == 1;
}

bool sendSubscribe(Client& client, MiningSession& session) {
  JsonDocument request;
  request["id"] = session.subscribeId;
  request["method"] = "mining.subscribe";
  request["params"].to<JsonArray>().add("SOLO_HUNTER/1.0.6");
  return sendDocument(client, request);
}

bool sendAuthorize(Client& client, MiningSession& session,
                   const SoloHunterMiningConfig& config) {
  JsonDocument request;
  request["id"] = session.authorizeId;
  request["method"] = "mining.authorize";
  JsonArray params = request["params"].to<JsonArray>();
  params.add(workerLogin(config));
  params.add(config.password.isEmpty() ? "x" : config.password);
  return sendDocument(client, request);
}

bool sendSuggestedDifficulty(Client& client) {
  JsonDocument request;
  request["id"] = 3;
  request["method"] = "mining.suggest_difficulty";
  request["params"].to<JsonArray>().add(SUGGESTED_DIFFICULTY);
  return sendDocument(client, request);
}

void rememberPending(MiningSession& session, uint32_t id, double difficulty) {
  size_t slot = 0;
  uint32_t oldestId = UINT32_MAX;
  for (size_t i = 0; i < sizeof(session.pending) / sizeof(session.pending[0]); ++i) {
    if (!session.pending[i].used) {
      slot = i;
      oldestId = 0;
      break;
    }
    if (session.pending[i].id < oldestId) {
      oldestId = session.pending[i].id;
      slot = i;
    }
  }
  session.pending[slot].used = true;
  session.pending[slot].id = id;
  session.pending[slot].difficulty = difficulty;
}

uint32_t countPending(const MiningSession& session) {
  uint32_t count = 0;
  for (size_t i = 0; i < sizeof(session.pending) / sizeof(session.pending[0]); ++i) {
    if (session.pending[i].used) count++;
  }
  return count;
}

PendingShare* findPending(MiningSession& session, uint32_t id) {
  for (size_t i = 0; i < sizeof(session.pending) / sizeof(session.pending[0]); ++i) {
    if (session.pending[i].used && session.pending[i].id == id) return &session.pending[i];
  }
  return nullptr;
}

bool sendShare(Client& client, MiningSession& session,
               const SoloHunterMiningConfig& config, uint32_t nonce,
               double difficulty) {
  uint32_t requestId = session.nextRequestId++;
  if (session.nextRequestId < 10) session.nextRequestId = 10;

  char nonceHex[9];
  snprintf(nonceHex, sizeof(nonceHex), "%08lx", (unsigned long)nonce);

  JsonDocument request;
  request["id"] = requestId;
  request["method"] = "mining.submit";
  JsonArray params = request["params"].to<JsonArray>();
  params.add(workerLogin(config));
  params.add(session.job.jobId);
  params.add(session.job.extranonce2);
  params.add(session.job.ntime);
  params.add(nonceHex);
  if (!sendDocument(client, request)) return false;
  rememberPending(session, requestId, difficulty);
  recordSubmittedShare(countPending(session));
  return true;
}

void clearSession(MiningSession& session) {
  clearAuxiliaryWork();
  session.connected = false;
  session.subscribed = false;
  session.authorized = false;
  session.connectedAt = 0;
  session.lastPoolMessageAt = 0;
  session.lastJobAt = 0;
  session.extranonce1 = "";
  session.extranonce2Size = 0;
  session.poolDifficulty = 1.0;
  session.job = StratumJob();
  session.rxLine = "";
  session.midstateReady = false;
  session.hardwareReady = false;
  session.auxiliaryGeneration = 0;
  memset(session.shareTarget, 0xFF, sizeof(session.shareTarget));
  memset(session.pending, 0, sizeof(session.pending));
}

bool parseNotify(JsonArrayConst params, MiningSession& session) {
  if (params.size() < 9) return false;

  StratumJob nextJob;
  nextJob.jobId = String(params[0] | "");
  nextJob.prevHash = String(params[1] | "");
  nextJob.coinbase1 = String(params[2] | "");
  nextJob.coinbase2 = String(params[3] | "");
  JsonArrayConst branches = params[4].as<JsonArrayConst>();
  if (branches.size() > MAX_MERKLE_BRANCHES) return false;
  nextJob.merkleBranchCount = branches.size();
  for (size_t i = 0; i < nextJob.merkleBranchCount; ++i) {
    nextJob.merkleBranches[i] = String(branches[i] | "");
  }
  nextJob.version = String(params[5] | "");
  nextJob.nbits = String(params[6] | "");
  nextJob.ntime = String(params[7] | "");

  session.job = nextJob;
  if (!buildJobHeader(session)) {
    session.job.valid = false;
    return false;
  }

  session.lastJobAt = millis();
  session.auxiliaryGeneration = publishAuxiliaryWork(session);
  setStatus("HASHING");
  return true;
}

bool parseSubscription(JsonVariantConst result, MiningSession& session) {
  JsonArrayConst values = result.as<JsonArrayConst>();
  if (values.size() < 3) return false;
  session.extranonce1 = String(values[1] | "");
  int extraSize = values[2] | 0;
  if (session.extranonce1.isEmpty() || extraSize <= 0 || extraSize > 16) return false;
  session.extranonce2Size = (uint8_t)extraSize;
  session.subscribed = true;
  return true;
}

bool responseAccepted(JsonDocument& document) {
  if (!document["error"].isNull()) return false;
  JsonVariant result = document["result"];
  if (result.is<bool>()) return result.as<bool>();
  return !result.isNull();
}

bool processLine(const String& line, Client& client, MiningSession& session,
                 const SoloHunterMiningConfig& config) {
  JsonDocument document;
  DeserializationError error = deserializeJson(document, line);
  if (error) return true;

  session.lastPoolMessageAt = millis();
  const char* method = document["method"].as<const char*>();
  if (method != nullptr) {
    JsonArrayConst params = document["params"].as<JsonArrayConst>();
    if (strcmp(method, "mining.set_difficulty") == 0) {
      double difficulty = params.size() > 0 ? params[0].as<double>() : 0.0;
      if (isfinite(difficulty) && difficulty > 0.0) {
        session.poolDifficulty = difficulty;
        targetFromDifficulty(difficulty, session.shareTarget);
        setPoolDifficulty(difficulty);
        refreshAuxiliaryTargets(session);
      }
      return true;
    }
    if (strcmp(method, "mining.set_target") == 0) {
      String targetHex = params.size() > 0 ? String(params[0] | "") : "";
      if (targetFromHex(targetHex, session.shareTarget)) {
        session.poolDifficulty = difficultyFromHash(session.shareTarget);
        setPoolDifficulty(session.poolDifficulty);
        refreshAuxiliaryTargets(session);
      }
      return true;
    }
    if (strcmp(method, "mining.set_extranonce") == 0) {
      if (params.size() >= 2) {
        String extranonce1 = String(params[0] | "");
        int extraSize = params[1] | 0;
        if (!extranonce1.isEmpty() && extraSize > 0 && extraSize <= 16) {
          session.extranonce1 = extranonce1;
          session.extranonce2Size = (uint8_t)extraSize;
          session.job.valid = false;
          session.midstateReady = false;
        }
      }
      return true;
    }
    if (strcmp(method, "mining.notify") == 0) {
      if (!parseNotify(params, session)) setStatus("BAD JOB");
      return true;
    }
    return true;
  }

  if (document["id"].isNull()) return true;
  uint32_t responseId = document["id"].as<uint32_t>();
  if (responseId == session.subscribeId && !session.subscribed) {
    if (!responseAccepted(document) ||
        !parseSubscription(document["result"], session)) {
      setStatus("SUBSCRIBE ERR");
      return false;
    }
    setStatus("AUTHORIZING");
    if (!sendAuthorize(client, session, config)) return false;
    return true;
  }

  if (responseId == session.authorizeId && !session.authorized) {
    if (!responseAccepted(document)) {
      setStatus("AUTH DENIED");
      return false;
    }
    session.authorized = true;
    if (!sendSuggestedDifficulty(client)) return false;
    setStatus(session.job.valid ? "HASHING" : "WAITING JOB");
    return true;
  }

  PendingShare* pending = findPending(session, responseId);
  if (pending != nullptr) {
    bool accepted = responseAccepted(document);
    recordShareResult(accepted);
    if (accepted) recordBestDifficulty(pending->difficulty);
    pending->used = false;
    setPendingShares(countPending(session));
  }
  return true;
}

bool readPoolMessages(Client& client, MiningSession& session,
                      const SoloHunterMiningConfig& config) {
  while (client.connected() && client.available() > 0) {
    char ch = (char)client.read();
    if (ch == '\r') continue;
    if (ch == '\n') {
      if (!session.rxLine.isEmpty()) {
        if (!processLine(session.rxLine, client, session, config)) {
          session.rxLine = "";
          return false;
        }
        session.rxLine = "";
      }
      continue;
    }
    if (session.rxLine.length() >= MAX_STRATUM_LINE) {
      setStatus("JOB TOO LARGE");
      return false;
    }
    session.rxLine += ch;
  }
  return client.connected();
}

void stopClient(Client*& client, WiFiClient& tcpClient, WiFiClientSecure& tlsClient,
                MiningSession& session) {
  if (session.connected) recordPoolReconnect();
  if (client != nullptr) client->stop();
  tcpClient.stop();
  tlsClient.stop();
  client = nullptr;
  clearSession(session);
  setHashrate(0.0f);
  setPendingShares(0);
}

bool connectPool(Client*& client, WiFiClient& tcpClient, WiFiClientSecure& tlsClient,
                 const PoolEndpoint& endpoint, MiningSession& session) {
  setStatus(endpoint.tls ? "TLS CONNECT" : "CONNECTING");
  if (endpoint.tls) {
    tlsClient.setInsecure();
    tlsClient.setTimeout(2000);
    client = &tlsClient;
  } else {
    tcpClient.setTimeout(2000);
    client = &tcpClient;
  }

  if (!client->connect(endpoint.host.c_str(), endpoint.port)) {
    client = nullptr;
    setStatus("POOL RETRY");
    return false;
  }

  clearSession(session);
  session.connected = true;
  session.connectedAt = millis();
  session.lastPoolMessageAt = session.connectedAt;
  session.rxLine.reserve(4096);
  targetFromDifficulty(session.poolDifficulty, session.shareTarget);
  setStatus("SUBSCRIBING");
  if (!sendSubscribe(*client, session)) {
    setStatus("SUBSCRIBE ERR");
    client->stop();
    client = nullptr;
    return false;
  }
  return true;
}

bool processAuxiliaryCandidates(Client& client, MiningSession& session,
                                const SoloHunterMiningConfig& config,
                                bool& bestChanged) {
  if (auxiliaryCandidateQueue == nullptr) return true;

  AuxiliaryCandidate candidate;
  while (xQueueReceive(auxiliaryCandidateQueue, &candidate, 0) == pdTRUE) {
    if (candidate.generation != session.auxiliaryGeneration) continue;
    if (hashIsBetter(candidate.hash, session.bestHash)) {
      memcpy(session.bestHash, candidate.hash, sizeof(session.bestHash));
      bestChanged = true;
    }
    if (hashMeetsTarget(candidate.hash, session.blockTarget)) {
      recordBlockFound();
    }
    if (hashMeetsTarget(candidate.hash, session.shareTarget)) {
      double shareDifficulty = difficultyFromHash(candidate.hash);
      if (!sendShare(client, session, config, candidate.nonce,
                     shareDifficulty)) {
        return false;
      }
    }
  }
  return true;
}

void miningTask(void*) {
  WiFiClient tcpClient;
  WiFiClientSecure tlsClient;
  Client* client = nullptr;
  MiningSession session;
  memset(session.bestHash, 0xFF, sizeof(session.bestHash));
  clearSession(session);
  if (!miningMathSelfTest()) {
    setStatus("SELF TEST FAIL");
    minerTaskHandle = nullptr;
    vTaskDelete(nullptr);
    return;
  }
  bool hardwareShaAvailable = soloHunterSha256Begin();

  uint32_t appliedRevision = UINT32_MAX;
  uint32_t reconnectAt = 0;
  uint32_t hardwareRetryAt = 0;
  uint32_t hashrateStartedAt = millis();
  uint32_t hashesInWindow = 0;
  uint32_t primaryHashesInWindow = 0;
  uint32_t auxiliaryHashesInWindow = 0;
  float smoothedHashrateKh = 0.0f;
  float smoothedPrimaryHashrateKh = 0.0f;
  float smoothedAuxiliaryHashrateKh = 0.0f;
  uint64_t totalHashes = 0;
  uint8_t hardwareBatchesBeforeDelay = 0;
  SoloHunterMiningConfig config;
  PoolEndpoint endpoint;

  for (;;) {
    uint32_t latestRevision = currentConfigRevision();
    if (latestRevision != appliedRevision) {
      config = copyConfig(latestRevision);
      endpoint = parseEndpoint(config);
      stopClient(client, tcpClient, tlsClient, session);
      memset(session.bestHash, 0xFF, sizeof(session.bestHash));
      appliedRevision = latestRevision;
      reconnectAt = 0;
      hardwareRetryAt = 0;
      hashesInWindow = 0;
      primaryHashesInWindow = 0;
      auxiliaryHashesInWindow = 0;
      smoothedHashrateKh = 0.0f;
      smoothedPrimaryHashrateKh = 0.0f;
      smoothedAuxiliaryHashrateKh = 0.0f;
      totalHashes = 0;
      hardwareBatchesBeforeDelay = 0;
      hashrateStartedAt = millis();
      resetRunStats(hardwareShaAvailable);
    }

    if (!config.enabled) {
      setStatus("OFF");
      vTaskDelay(pdMS_TO_TICKS(500));
      continue;
    }

    if (endpoint.host.isEmpty() || config.username.isEmpty()) {
      setStatus("CONFIG REQUIRED");
      vTaskDelay(pdMS_TO_TICKS(1000));
      continue;
    }

    if (WiFi.status() != WL_CONNECTED) {
      stopClient(client, tcpClient, tlsClient, session);
      setStatus("WAITING WIFI");
      vTaskDelay(pdMS_TO_TICKS(1000));
      continue;
    }

    uint32_t now = millis();
    if (client == nullptr || !client->connected()) {
      stopClient(client, tcpClient, tlsClient, session);
      if ((int32_t)(now - reconnectAt) < 0) {
        vTaskDelay(pdMS_TO_TICKS(100));
        continue;
      }
      if (!connectPool(client, tcpClient, tlsClient, endpoint, session)) {
        reconnectAt = millis() + CONNECT_RETRY_MS;
        vTaskDelay(pdMS_TO_TICKS(250));
        continue;
      }
    }

    if (!readPoolMessages(*client, session, config)) {
      stopClient(client, tcpClient, tlsClient, session);
      reconnectAt = millis() + CONNECT_RETRY_MS;
      continue;
    }

    now = millis();
    if (!session.authorized &&
        (uint32_t)(now - session.connectedAt) > HANDSHAKE_TIMEOUT_MS) {
      setStatus("POOL TIMEOUT");
      stopClient(client, tcpClient, tlsClient, session);
      reconnectAt = millis() + CONNECT_RETRY_MS;
      continue;
    }
    // A valid Stratum job remains usable until the pool replaces it. Quiet
    // pools can legitimately keep one job for many minutes, so only tear down
    // a connection that has delivered no messages at all for a long period.
    if (session.job.valid && session.lastPoolMessageAt != 0 &&
        (uint32_t)(now - session.lastPoolMessageAt) >
            POOL_SILENCE_TIMEOUT_MS) {
      setStatus("POOL SILENT");
      stopClient(client, tcpClient, tlsClient, session);
      reconnectAt = millis() + CONNECT_RETRY_MS;
      continue;
    }
    if (session.authorized && !session.job.valid &&
        (uint32_t)(now - session.connectedAt) > NO_JOB_TIMEOUT_MS) {
      setStatus("NO JOB");
      stopClient(client, tcpClient, tlsClient, session);
      reconnectAt = millis() + CONNECT_RETRY_MS;
      continue;
    }

    if (!(session.authorized && session.job.valid && session.midstateReady)) {
      vTaskDelay(pdMS_TO_TICKS(5));
      continue;
    }

    uint32_t auxiliaryHashes = drainAuxiliaryHashes();
    hashesInWindow += auxiliaryHashes;
    auxiliaryHashesInWindow += auxiliaryHashes;
    totalHashes += auxiliaryHashes;

    if (!hardwareShaAvailable &&
        (int32_t)(now - hardwareRetryAt) >= 0) {
      if (soloHunterSha256Begin()) {
        hardwareShaAvailable = true;
        prepareMidstate(session);
        setHardwareSha(true);
        setStatus("HASHING");
      } else {
        hardwareRetryAt = now + HARDWARE_RETRY_MS;
      }
    }

    bool bestChanged = false;
    if (!processAuxiliaryCandidates(*client, session, config, bestChanged)) {
      stopClient(client, tcpClient, tlsClient, session);
      reconnectAt = millis() + CONNECT_RETRY_MS;
      continue;
    }
    uint8_t hash[32];
    bool usedHardware = false;
    if (hardwareShaAvailable && session.hardwareReady) {
      SoloHunterSha256Result result;
      usedHardware = soloHunterSha256Mine(
          session.hardwareHeader, session.hardwareNonceSwapped,
          hardwareLeadingZeroMask(session.shareTarget) &
              hardwareLeadingZeroMask(session.blockTarget),
          HARDWARE_HASH_BATCH_SIZE, result);

      if (usedHardware) {
        hashesInWindow += result.hashes;
        primaryHashesInWindow += result.hashes;
        totalHashes += result.hashes;
        if (result.candidate) {
            uint8_t verifiedHash[32];
            if (!hashHeaderNonce(session, result.nonce, verifiedHash) ||
                memcmp(result.hash, verifiedHash, sizeof(verifiedHash)) != 0) {
              session.job.nextNonce =
                  __builtin_bswap32(session.hardwareNonceSwapped);
              if (soloHunterSha256Recover()) {
                hardwareShaAvailable = true;
                prepareMidstate(session);
                setHardwareSha(true);
                setStatus("HASHING");
              } else {
                hardwareShaAvailable = false;
                session.hardwareReady = false;
                setHardwareSha(false);
                hardwareRetryAt = millis() + HARDWARE_RETRY_MS;
                setStatus("SHA RETRY");
              }
            } else {
              memcpy(hash, verifiedHash, sizeof(hash));
              if (hashIsBetter(hash, session.bestHash)) {
                memcpy(session.bestHash, hash, sizeof(session.bestHash));
                bestChanged = true;
              }
              if (hashMeetsTarget(hash, session.blockTarget)) {
                recordBlockFound();
              }
              if (hashMeetsTarget(hash, session.shareTarget)) {
                double shareDifficulty = difficultyFromHash(hash);
                if (!sendShare(*client, session, config, result.nonce,
                               shareDifficulty)) {
                  stopClient(client, tcpClient, tlsClient, session);
                  reconnectAt = millis() + CONNECT_RETRY_MS;
                }
              }
            }
        }
      }
    }

    if (!usedHardware) {
      for (uint32_t i = 0; i < HASH_BATCH_SIZE; ++i) {
        uint32_t nonce = session.job.nextNonce++;
        if (!hashHeaderNonce(session, nonce, hash)) {
          setStatus("SHA ERROR");
          session.job.valid = false;
          break;
        }
        hashesInWindow++;
        primaryHashesInWindow++;
        totalHashes++;
        if (hashIsBetter(hash, session.bestHash)) {
          memcpy(session.bestHash, hash, sizeof(session.bestHash));
          bestChanged = true;
        }
        if (hashMeetsTarget(hash, session.blockTarget)) {
          recordBlockFound();
        }
        if (hashMeetsTarget(hash, session.shareTarget)) {
          double shareDifficulty = difficultyFromHash(hash);
          if (!sendShare(*client, session, config, nonce, shareDifficulty)) {
            stopClient(client, tcpClient, tlsClient, session);
            reconnectAt = millis() + CONNECT_RETRY_MS;
            break;
          }
        }
      }
    }

    if (bestChanged) recordBestDifficulty(difficultyFromHash(session.bestHash));

    now = millis();
    uint32_t elapsed = now - hashrateStartedAt;
    if (elapsed >= HASHRATE_WINDOW_MS) {
      float sampleHashrateKh =
          elapsed > 0 ? (float)hashesInWindow / (float)elapsed : 0.0f;
      float samplePrimaryHashrateKh =
          elapsed > 0 ? (float)primaryHashesInWindow / (float)elapsed : 0.0f;
      float sampleAuxiliaryHashrateKh =
          elapsed > 0 ? (float)auxiliaryHashesInWindow / (float)elapsed : 0.0f;
      if (smoothedHashrateKh <= 0.0f) {
        smoothedHashrateKh = sampleHashrateKh;
        smoothedPrimaryHashrateKh = samplePrimaryHashrateKh;
        smoothedAuxiliaryHashrateKh = sampleAuxiliaryHashrateKh;
      } else {
        smoothedHashrateKh +=
            (sampleHashrateKh - smoothedHashrateKh) * HASHRATE_SMOOTHING;
        smoothedPrimaryHashrateKh +=
            (samplePrimaryHashrateKh - smoothedPrimaryHashrateKh) *
            HASHRATE_SMOOTHING;
        smoothedAuxiliaryHashrateKh +=
            (sampleAuxiliaryHashrateKh - smoothedAuxiliaryHashrateKh) *
            HASHRATE_SMOOTHING;
      }
      setHashTelemetry(smoothedHashrateKh, smoothedPrimaryHashrateKh,
                       smoothedAuxiliaryHashrateKh, totalHashes,
                       hardwareShaAvailable);
      hashesInWindow = 0;
      primaryHashesInWindow = 0;
      auxiliaryHashesInWindow = 0;
      hashrateStartedAt = now;
    }

    if (usedHardware) {
      if (++hardwareBatchesBeforeDelay >= HARDWARE_BATCHES_BEFORE_DELAY) {
        hardwareBatchesBeforeDelay = 0;
        // Let the core-1 idle task service its watchdog. At 16 full hardware
        // batches this costs roughly one tick per second, not one per hash.
        vTaskDelay(pdMS_TO_TICKS(1));
      } else {
        taskYIELD();
      }
    } else {
      hardwareBatchesBeforeDelay = 0;
      vTaskDelay(pdMS_TO_TICKS(1));
    }
  }
}

}  // namespace

void soloHunterMinerBegin(const SoloHunterMiningConfig& config) {
  if (stateMutex == nullptr) stateMutex = xSemaphoreCreateMutex();
  if (auxiliaryCandidateQueue == nullptr) {
    auxiliaryCandidateQueue = xQueueCreate(8, sizeof(AuxiliaryCandidate));
  }
  soloHunterMinerConfigure(config);
  if (ENABLE_AUXILIARY_MINING && auxiliaryMinerTaskHandle == nullptr &&
      auxiliaryCandidateQueue != nullptr) {
    BaseType_t created = xTaskCreatePinnedToCore(
        auxiliaryMiningTask, "solo-miner0", 6144, nullptr, 0,
        &auxiliaryMinerTaskHandle, 0);
    if (created != pdPASS) auxiliaryMinerTaskHandle = nullptr;
  }
  if (minerTaskHandle == nullptr) {
    BaseType_t created =
        xTaskCreatePinnedToCore(miningTask, "solo-miner1", 16384, nullptr, 2,
                                &minerTaskHandle, 1);
    if (created != pdPASS) {
      minerTaskHandle = nullptr;
      setStatus("TASK ERROR");
    }
  }
}

void soloHunterMinerConfigure(const SoloHunterMiningConfig& config) {
  if (stateMutex == nullptr) stateMutex = xSemaphoreCreateMutex();
  SoloHunterMiningConfig normalized = config;
  normalized.poolHost.trim();
  normalized.username.trim();
  normalized.worker.trim();
  normalized.password.trim();
  if (normalized.poolPort == 0) normalized.poolPort = 3333;
  if (normalized.password.isEmpty()) normalized.password = "x";

  lockState();
  bool changed = activeConfig.enabled != normalized.enabled ||
                 activeConfig.poolHost != normalized.poolHost ||
                 activeConfig.poolPort != normalized.poolPort ||
                 activeConfig.username != normalized.username ||
                 activeConfig.worker != normalized.worker ||
                 activeConfig.password != normalized.password;
  if (changed) {
    activeConfig = normalized;
    configRevision++;
  }
  unlockState();
}

SoloHunterMiningStats soloHunterMinerGetStats(bool includeStack) {
  lockState();
  SoloHunterMiningStats copy = activeStats;
  copy.uptimeSeconds =
      statsStartedAt > 0 ? (uint32_t)((millis() - statsStartedAt) / 1000U) : 0;
  unlockState();
  if (includeStack) {
    copy.primaryStackFreeBytes =
        minerTaskHandle
            ? static_cast<uint32_t>(
                  uxTaskGetStackHighWaterMark(minerTaskHandle))
            : 0;
    copy.auxiliaryStackFreeBytes =
        auxiliaryMinerTaskHandle
            ? static_cast<uint32_t>(
                  uxTaskGetStackHighWaterMark(auxiliaryMinerTaskHandle))
            : 0;
  }
  return copy;
}
