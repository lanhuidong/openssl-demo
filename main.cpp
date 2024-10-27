#include <openssl/evp.h>
#include <openssl/rand.h>

#include <atomic>
#include <barrier>
#include <chrono>
#include <exception>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>
static const unsigned int KEY_SIZE = 32;
static const unsigned int BLOCK_SIZE = 16;
using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

std::vector<unsigned char> encrypt(const unsigned char* key, const unsigned char* iv,
                                   std::vector<unsigned char> plain_text) {
    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    int rc = EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key, iv);
    if (rc != 1) {
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    std::vector<unsigned char> cipher_text;
    cipher_text.resize(plain_text.size() + BLOCK_SIZE);
    int out_len1 = (int)cipher_text.size();

    rc = EVP_EncryptUpdate(ctx.get(), (unsigned char*)&cipher_text[0], &out_len1, (const unsigned char*)&plain_text[0],
                           (int)plain_text.size());
    if (rc != 1) {
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }

    int out_len2 = (int)cipher_text.size() - out_len1;
    rc = EVP_EncryptFinal_ex(ctx.get(), (unsigned char*)&cipher_text[0] + out_len1, &out_len2);
    if (rc != 1) {
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }

    cipher_text.resize(out_len1 + out_len2);
    return cipher_text;
}

std::vector<unsigned char> decrypt(const unsigned char* key, const unsigned char* iv,
                                   const std::vector<unsigned char>& cipher_text) {
    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    int rc = EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key, iv);
    if (rc != 1) {
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }

    std::vector<unsigned char> r_text;
    r_text.resize(cipher_text.size());
    int out_len1 = (int)r_text.size();

    rc = EVP_DecryptUpdate(ctx.get(), (unsigned char*)&r_text[0], &out_len1, (const unsigned char*)&cipher_text[0],
                           (int)cipher_text.size());
    if (rc != 1) {
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }

    int out_len2 = (int)r_text.size() - out_len1;
    rc = EVP_DecryptFinal_ex(ctx.get(), (unsigned char*)&r_text[0] + out_len1, &out_len2);
    std::cout << "rc: " << rc << std::endl;
    if (rc != 1) {
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
    }

    r_text.resize(out_len1 + out_len2);
    return r_text;
}

void gen_params(unsigned char key[KEY_SIZE], unsigned char iv[BLOCK_SIZE]) {
    int rc = RAND_bytes(key, KEY_SIZE);
    if (rc != 1) {
        throw std::runtime_error("RAND_bytes key failed");
    }

    rc = RAND_bytes(iv, BLOCK_SIZE);
    if (rc != 1) {
        throw std::runtime_error("RAND_bytes for iv failed");
    }
}

std::vector<unsigned char> plain_text;
unsigned char key[KEY_SIZE] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
                               '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'},
              iv[BLOCK_SIZE] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

void Run() {
    std::vector<unsigned char> cipher_text = encrypt(key, iv, plain_text);
    std::vector<unsigned char> r_text = decrypt(key, iv, cipher_text);
}

int main(int argc, char* argv[]) {
    std::string data = "Hello World!";
    for (int i = 0; i < data.length(); i++) {
        plain_text.push_back(data[i]);
    }

    std::cout << data << std::endl;

    EVP_add_cipher(EVP_aes_256_cbc());
    Run();

    OPENSSL_cleanse(key, KEY_SIZE);
    OPENSSL_cleanse(iv, BLOCK_SIZE);

    return 0;
}