#pragma once

#include <Arduino.h>

struct SoloHunterMiningConfig {
  bool enabled = false;
  String poolHost;
  uint16_t poolPort = 3333;
  String username;
  String worker;
  String password = "x";
};

struct SoloHunterMiningStats {
  float hashrateKh = 0.0f;
  float primaryHashrateKh = 0.0f;
  float auxiliaryHashrateKh = 0.0f;
  uint64_t totalHashes = 0;
  uint32_t submittedShares = 0;
  uint32_t pendingShares = 0;
  uint32_t acceptedShares = 0;
  uint32_t rejectedShares = 0;
  uint32_t blocksFound = 0;
  uint32_t poolReconnects = 0;
  uint32_t uptimeSeconds = 0;
  uint32_t primaryStackFreeBytes = 0;
  uint32_t auxiliaryStackFreeBytes = 0;
  double bestDifficulty = 0.0;
  double poolDifficulty = 0.0;
  bool hardwareSha = false;
  String status = "OFF";
};

void soloHunterMinerBegin(const SoloHunterMiningConfig& config);
void soloHunterMinerConfigure(const SoloHunterMiningConfig& config);
SoloHunterMiningStats soloHunterMinerGetStats(bool includeStack = false);
