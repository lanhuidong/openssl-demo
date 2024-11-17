#include "digest_demo.h"

#include <openssl/evp.h>

std::string MD5(const std::string& message) {
    EVP_MD_CTX* mdctx;

    if ((mdctx = EVP_MD_CTX_new()) == NULL) {
        return "";
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_md5(), NULL)) {
        return "";
    }

    if (1 != EVP_DigestUpdate(mdctx, (unsigned char*)message.data(), message.size())) {
        return "";
    }

    unsigned char* digest;
    unsigned int digest_len{0};
    if ((digest = (unsigned char*)OPENSSL_malloc(EVP_MD_size(EVP_md5()))) == NULL) {
        return "";
    }

    if (1 != EVP_DigestFinal_ex(mdctx, digest, &digest_len)) {
        return "";
    }
    EVP_MD_CTX_free(mdctx);
    std::string result(digest_len, '\0');
    memcpy(result.data(), digest, digest_len);
    OPENSSL_free(digest);
    return result;
}