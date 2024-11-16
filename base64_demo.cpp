#include "base64_demo.h"

#include <openssl/bio.h>
#include <openssl/evp.h>

std::string Base64Encode(std::string plain_text) {
    auto plain_text_len = plain_text.size();
    auto cipher_text_len = plain_text_len * 4 / 3 + 4;
    std::string cipher_text(cipher_text_len, '\0');
    int len = EVP_EncodeBlock((unsigned char*)cipher_text.data(), (unsigned char*)plain_text.data(), plain_text_len);
    cipher_text.resize(len);
    return cipher_text;
}

std::string Base64Decode(std::string cipher_text) {
    auto cipher_text_len = cipher_text.size();
    auto plain_text_len = cipher_text_len * 3 / 4;
    std::string plain_text(plain_text_len, '\0');
    int len = EVP_DecodeBlock((unsigned char*)plain_text.data(), (unsigned char*)cipher_text.data(), cipher_text_len);
    plain_text.resize(len);
    return plain_text;
}