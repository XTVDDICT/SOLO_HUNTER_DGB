#pragma once

#include <Arduino.h>

struct SoloHunterSha256Result {
  uint32_t hashes = 0;
  bool candidate = false;
  uint32_t nonce = 0;
  uint8_t hash[32] = {0};
};

struct SoloHunterSha256Failure {
  const char* reason = "NONE";
  const char* timing = "NONE";
  uint32_t uptimeMs = 0;
  uint32_t seed = 0;
  uint32_t startNonceSwapped = 0;
  uint32_t nextNonceSwapped = 0;
  uint32_t nonce = 0;
  uint32_t hashes = 0;
  bool candidate = false;
  bool softwareReferenceOk = false;
  bool rereadValid = false;
  uint8_t hardwareHeader[80] = {0};
  uint8_t referenceHeader[80] = {0};
  uint8_t hardwareHash[32] = {0};
  uint8_t referenceHash[32] = {0};
  uint8_t softwareHash[32] = {0};
  uint8_t rereadHash[32] = {0};
};

bool soloHunterSha256GetFailure(SoloHunterSha256Failure& output);
bool soloHunterSha256Begin();
bool soloHunterSha256FastPathActive();
bool soloHunterSha256Recover();
const char* soloHunterSha256LastFault();
const char* soloHunterSha256LastFallback();
const char* soloHunterSha256LastSelfTestFailure();
const char* soloHunterSha256Timing();
const char* soloHunterSha256ReferenceValidation();
uint32_t soloHunterSha256ChipRevision();
uint32_t soloHunterSha256RecoveryCount();
bool soloHunterSha256Mine(const uint32_t headerSwapped[20],
                          uint32_t& nextNonceSwapped,
                          uint16_t leadingZeroMask,
                          uint32_t maxHashes,
                          SoloHunterSha256Result& result);
