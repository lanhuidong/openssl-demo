#include "rsa_demo.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <iostream>

#define RSA_KEY_BITS_NUM 4096

void PrintBN(const BIGNUM* n) {
    unsigned char buf[RSA_KEY_BITS_NUM] = {0};
    BN_bn2bin(n, buf);
    auto len = BN_num_bytes(n);
    for (int i = 0; i < len; ++i) {
        printf("%02x", buf[i]);
    }
    std::cout << std::endl;
}

RSA* CreateRsaKey() {
    RSA* rsa_key_pair = RSA_new();
    BIGNUM* a = BN_new();
    BN_set_word(a, RSA_F4);
    RSA_generate_key_ex(rsa_key_pair, RSA_KEY_BITS_NUM, a, nullptr);
    BN_free(a);

    auto n = RSA_get0_n(rsa_key_pair);  // 模数
    auto e = RSA_get0_e(rsa_key_pair);  // 公钥指数
    auto d = RSA_get0_d(rsa_key_pair);  // 私钥指数

    std::cout << "n=";
    PrintBN(n);
    std::cout << "e=";
    PrintBN(e);
    std::cout << "d=";
    PrintBN(d);
    return rsa_key_pair;
}

void RsaEncrypt(RSA* key, unsigned char* in, int in_size, unsigned char* out, int* out_size) {
    int key_size = RSA_size(key);
    int block_size = key_size - RSA_PKCS1_PADDING_SIZE;
    int out_off{0};
    for (int i = 0; i < in_size; i += block_size) {
        int flen = block_size;
        if (in_size - i < block_size) {
            flen = in_size - i;
        }
        out_off += key_size;
        out_off = i + RSA_PKCS1_PADDING_SIZE * (i / block_size);
        int result = RSA_public_encrypt(flen, in + i, out + out_off, key, RSA_PKCS1_PADDING);
        if (result < 0) {
            ERR_print_errors_fp(stderr);
        }
        *out_size += result;
        std::cout << "out_size = " << *out_size << std::endl;
    }
}

void RsaDecrypt(RSA* key, unsigned char* cipher_data, int cipher_size, unsigned char* recovery_data) {
    RSA* rd = RSA_new();
    auto n = BN_new();
    auto d = BN_new();
    auto e = BN_new();
    BN_copy(n, RSA_get0_n(key));
    BN_copy(d, RSA_get0_d(key));
    BN_copy(e, RSA_get0_e(key));
    RSA_set0_key(rd, n, e, d);

    int key_size = RSA_size(rd);
    int out_off{0};
    for (int i = 0; i < cipher_size; i += key_size) {
        int result = RSA_private_decrypt(key_size, cipher_data + i, recovery_data + out_off, rd, RSA_PKCS1_PADDING);
        if (result < 0) {
            ERR_print_errors_fp(stderr);
        }
        out_off += result;
    }
    RSA_free(rd);
    std::cout << "out_off = " << out_off << std::endl;
}

EVP_PKEY* CreateRsaKeyEvp() {
    return EVP_RSA_gen(RSA_KEY_BITS_NUM);
}

std::string RsaEncryptEvp(EVP_PKEY* key, unsigned char* plain_text, size_t plain_text_size) {
    EVP_PKEY_CTX* ctx;
    unsigned char* out{nullptr};
    size_t outlen{0};
    ctx = EVP_PKEY_CTX_new(key, nullptr);
    if (!ctx) {
        std::cout << "EVP_PKEY_CTX_new error!" << std::endl;
        return "";
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        std::cout << "EVP_PKEY_encrypt_init error!" << std::endl;
        return "";
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        std::cout << "EVP_PKEY_CTX_set_rsa_padding error!" << std::endl;
        return "";
    }

    int key_size = EVP_PKEY_size(key);
    int block_size = key_size - 42;

    std::string cipher_text(outlen, '\0');
    size_t out_off{0};
    out = (unsigned char*)OPENSSL_malloc(key_size);
    if (!out) {
        return "";
    }
    for (int i = 0; i < key_size; i += block_size) {
        int flen = block_size;
        if (plain_text_size - i < block_size) {
            flen = plain_text_size - i;
        }
        if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, plain_text + i, flen) <= 0) {
            return "";
        }

        if (EVP_PKEY_encrypt(ctx, out, &outlen, plain_text + i, flen) <= 0) {
            std::cout << "EVP_PKEY_encrypt failed" << std::endl;
            return "";
        }
        cipher_text.resize(out_off + outlen);
        memcpy(cipher_text.data() + out_off, out, outlen);
        out_off += outlen;
    }
    OPENSSL_free(out);
    std::cout << "outlen = " << cipher_text.size() << std::endl;
    return cipher_text;
}

std::string RsaDecryptEvp(EVP_PKEY* key, const unsigned char* cipher_text, const size_t cipher_text_size) {
    EVP_PKEY_CTX* ctx;
    unsigned char* out;
    size_t outlen;
    ctx = EVP_PKEY_CTX_new(key, nullptr);
    if (!ctx) {
        return "";
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        return "";
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        return "";
    }
    std::string plain_text(cipher_text_size, '\0');
    size_t key_size = EVP_PKEY_size(key);
    size_t out_off{0};
    out = (unsigned char*)OPENSSL_malloc(key_size);
    if (!out) {
        return "";
    }
    for (int i = 0; i < cipher_text_size; i += key_size) {
        if (EVP_PKEY_decrypt(ctx, NULL, &outlen, cipher_text + i, key_size) <= 0) {
            return "";
        }
        std::cout << "out*len = " << outlen << std::endl;
        if (EVP_PKEY_decrypt(ctx, out, &outlen, cipher_text + i, key_size) <= 0) {
            std::cout << "EVP_PKEY_decrypt failed" << std::endl;
            return "";
        }
        std::cout << "*****" << std::endl;
        memcpy(plain_text.data() + i, out, outlen);
    }
    OPENSSL_free(out);
    return plain_text;
}
