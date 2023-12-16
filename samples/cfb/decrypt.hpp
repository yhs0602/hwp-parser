//
// Created by 양현서 on 12/16/23.
//

#ifndef DECRYPT_HPP
#define DECRYPT_HPP

std::vector<unsigned char> pad(const std::vector<unsigned char>& data);
std::vector<unsigned char> unpad(const std::vector<unsigned char>& data);
std::vector<unsigned char> gogo(const std::vector<unsigned char>& pwd, const std::vector<unsigned char>& data,
                                bool isEncrypt = true);

#endif //DECRYPT_HPP
