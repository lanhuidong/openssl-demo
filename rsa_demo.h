#pragma once
#include <openssl/rsa.h>

#include <string>
RSA* CreateRsaKey();
void RsaEncrypt(RSA* key, unsigned char* in, int in_size, unsigned char* out, int* out_size);
void RsaDecrypt(RSA* key, unsigned char* cipher_data, int cipher_size, unsigned char* recovery_data);

EVP_PKEY* CreateRsaKeyEvp();
std::string RsaEncryptEvp(EVP_PKEY* key, unsigned char* plain_text, size_t plain_text_size);
std::string RsaDecryptEvp(EVP_PKEY* key, const unsigned char* cipher_text, const size_t cipher_text_size);
