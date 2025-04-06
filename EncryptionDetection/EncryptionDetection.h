#include "./EncryptionDetection/EncryptionDetection.h"
#include "./GOffsets/GOffsets.h"
#include <cmath>
#include <vector>

double calculateEntropy(const std::vector<Byte>& data) {
    std::vector<double> freq(256, 0.0);
    for (Byte b : data) {
        freq[b]++;
    }
    double entropy = 0.0;
    for (double count : freq) {
        if (count > 0) {
            double p = count / static_cast<double>(data.size());
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

bool IsFileEncrypted(const std::vector<Byte>& data) {
    double entropy = calculateEntropy(data);
    return entropy > 7.5;
}
