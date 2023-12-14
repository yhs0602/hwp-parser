//
// Created by 양현서 on 12/14/23.
//

#include "genkey.h"
#include <iostream>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <string>

std::string genkey(const std::string& pwd) {
    std::vector<unsigned char> buf(160, 0);
    const std::vector<unsigned char> password(pwd.begin(), pwd.end());

    for (size_t i = 0; i < password.size(); ++i) {
        unsigned char v6 = (i != 0) ? password[i - 1] : 0xEC;
        unsigned char v7 = (2 * v6 | (v6 >> 7)) & 0xFF;

        buf[i * 2] = v7;
        buf[i * 2 + 1] = password[i];
    }

    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(buf.data(), buf.size(), hash);

    std::stringstream ss;
    for (int i = 0; i < 16; ++i) { // Only first 32 characters of the hash
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return ss.str();
}

// int main() {
//     std::string password = "your_password_here";
//     std::string key = genkey(password);
//     std::cout << "Generated Key: " << key << std::endl;
//     return 0;
// }
