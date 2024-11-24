#include "hmac_demo.h"

#include <openssl/err.h>

EVP_PKEY* gen_hmac_key(const std::string& secret) {
    return EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, (unsigned char*)secret.data(), secret.size());
}

std::string hmac_it(const std::string& message, EVP_PKEY* pkey) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
        return "";
    }

    int rc = EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey);
    if (rc != 1) {
        printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
        return "";
    }

    rc = EVP_DigestSignUpdate(ctx, (unsigned char*)message.data(), message.size());
    if (rc != 1) {
        printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
        return "";
    }

    size_t req{0};
    rc = EVP_DigestSignFinal(ctx, nullptr, &req);
    if (rc != 1) {
        printf("EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
        return "";
    }

    unsigned char* out = (unsigned char*)OPENSSL_malloc(req);
    if (out == nullptr) {
        printf("OPENSSL_malloc failed, error 0x%lx\n", ERR_get_error());
        return "";
    }

    rc = EVP_DigestSignFinal(ctx, out, &req);
    if (rc != 1) {
        printf("EVP_DigestSignFinal failed (3), return code %d, error 0x%lx\n", rc, ERR_get_error());
        return "";
    }
    std::string hmac(req, '\0');
    memcpy(hmac.data(), out, req);
    EVP_MD_CTX_free(ctx);
    OPENSSL_free(out);
    return hmac;
}