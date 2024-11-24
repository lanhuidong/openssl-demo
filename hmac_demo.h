#pragma once
#include <openssl/evp.h>

#include <string>

EVP_PKEY* gen_hmac_key(const std::string& secret);

std::string hmac_it(const std::string& message, EVP_PKEY* pkey);
