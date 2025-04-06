#ifndef ENCRYPTION_DETECTION_H
#define ENCRYPTION_DETECTION_H

#include <vector>
#include "../GOffsets/GOffsets.h"

// Encryption detection functions.
double calculateEntropy(const std::vector<Byte>& data);
bool IsFileEncrypted(const std::vector<Byte>& data);

#endif
