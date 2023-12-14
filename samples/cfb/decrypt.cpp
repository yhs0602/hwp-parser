#include <iostream>
#include <openssl/aes.h>
#include <vector>
#include <cstring>

const unsigned int BLOCK_SIZE = 16;

std::vector<unsigned char> pad(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> paddedData = data;
    size_t paddingSize = BLOCK_SIZE - (data.size() % BLOCK_SIZE);
    paddedData.insert(paddedData.end(), paddingSize, static_cast<unsigned char>(paddingSize));
    return paddedData;
}

std::vector<unsigned char> unpad(const std::vector<unsigned char>& data) {
    if (data.empty()) return data;
    size_t paddingSize = data.back();
    if (paddingSize > data.size()) return data;
    return std::vector<unsigned char>(data.begin(), data.end() - paddingSize);
}

class AESCipher {
public:
    AESCipher(const std::vector<unsigned char>& key) {
        AES_set_encrypt_key(key.data(), 128, &aesKey_);
    }

    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& rawData) {
        std::vector<unsigned char> encryptedData(rawData.size());
        AES_ecb_encrypt(rawData.data(), encryptedData.data(), &aesKey_, AES_ENCRYPT);
        return encryptedData;
    }

    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& encData) {
        std::vector<unsigned char> decryptedData(encData.size());
        AES_ecb_encrypt(encData.data(), decryptedData.data(), &aesKey_, AES_DECRYPT);
        return decryptedData;
    }

private:
    AES_KEY aesKey_;
};

std::vector<unsigned char> gogo(const std::vector<unsigned char>& pwd, const std::vector<unsigned char>& data, bool isEncrypt = true) {
    std::vector<unsigned char> finalData;
    std::vector<unsigned char> TMP_IN(16, 0);

    for (size_t kkk = 0; kkk < data.size(); kkk += 16) {
        std::vector<unsigned char> REAL_INPUT(data.begin() + kkk, data.begin() + std::min(kkk + 16, data.size()));

        for (int i = 0; i < 128; ++i) {
            std::vector<unsigned char> OUT = AESCipher(pwd).encrypt(TMP_IN);
            unsigned char OUT0 = OUT[0];

            int ff = i & 7;
            if (isEncrypt) {
                REAL_INPUT[i >> 3] ^= (OUT0 & 0x80) >> (i & 7);
            }

            // ... (continue with the TMP_IN update logic as in the Python script)

            if (isEncrypt) {
                TMP_IN[15] = ((2 * TMP_IN[15]) & 0xff) | (REAL_INPUT[i >> 3] >> (7 - ff));
            } else {
                TMP_IN[15] = ((2 * TMP_IN[15]) & 0xff) | (REAL_INPUT[i >> 3] >> (7 - ff)) & 1;
            }
            if (!isEncrypt) {
                REAL_INPUT[i >> 3] ^= (OUT0 & 0x80) >> (i & 7);
            }

            // ... (continue with the final_data update logic as in the Python script)
        }

        if (isEncrypt) {
            finalData.insert(finalData.end(), TMP_IN.begin(), TMP_IN.end());
            // ... (add any additional handling as needed)
        } else {
            finalData.insert(finalData.end(), REAL_INPUT.begin(), REAL_INPUT.end());
        }
    }

    return finalData;
}

// int main() {
//     // Example usage
//     std::vector<unsigned char> pwd = {/* Your key here */};
//     std::vector<unsigned char> data = {/* Your data here */};
//
//     std::vector<unsigned char> encrypted = gogo(pwd, pad(data), true);
//     std::vector<unsigned char> decrypted = gogo(pwd, encrypted, false);
//
//     // Output results
//     // ...
//
//     return 0;
// }
