#include "crypter.h"

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <iostream>

crypter::crypter()
{
    std::string in_str = "Hello world";
    const uint8_t in[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    uint8_t *out, *out1;
    size_t outlen, outlen1;
    size_t inlen = 5;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);

    if (!EVP_PKEY_keygen_init(ctx)) {
        std::cerr << "EVP_PKEY_keygen_init failed" << std::endl;
        return;
    }
    if (!EVP_PKEY_generate(ctx, &key)) {
        std::cerr << "EVP_PKEY_generate failed" << std::endl;
        return;
    }
    /*
    ctx = EVP_PKEY_CTX_new(key, nullptr);
    if (!ctx) {
        std::cerr << "EVP_PKEY_CTX_new failed" << std::endl;
        return;
    }*/
    // https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_encrypt.html
    auto encrypt = [&ctx, &key](const uint8_t* in, size_t inlen, uint8_t* out, size_t& outlen) {
        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
            std::cerr << "EVP_PKEY_encrypt_init failed" << std::endl;
            return;
        }
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            std::cerr << "EVP_PKEY_CTX_set_rsa_padding failed" << std::endl;
            return;
        }

        /* Determine buffer length */
        if (EVP_PKEY_encrypt(ctx, NULL, &outlen, in, inlen) <= 0) {
            std::cerr << "EVP_PKEY_encrypt failed" << std::endl;
            return;
        }

        out = (uint8_t*)OPENSSL_malloc(outlen);

        if (!out) {
            std::cerr << "OPENSSL_malloc failed" << std::endl;
            return;
        }

        if (EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen) <= 0) {
            std::cerr << "EVP_PKEY_encrypt failed" << std::endl;
            return;
        }
        for (int i = 0; i < outlen; i++) {
            std::cout << (int)out[i] << ' ';
        }
        // out = (uint8_t*)out_void;
    };

    // https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_decrypt.html
    auto decrypt = [&ctx, &key](uint8_t* in, size_t inlen, uint8_t* out, size_t& outlen) {
        if (EVP_PKEY_decrypt_init(ctx) <= 0) {
            std::cerr << "EVP_PKEY_encrypt failed" << std::endl;
            return;
        }

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            std::cerr << "EVP_PKEY_encrypt failed" << std::endl;
            return;
        }
        /* Determine buffer length */
        if (EVP_PKEY_decrypt(ctx, NULL, &outlen, in, inlen) <= 0) {
            std::cerr << "EVP_PKEY_encrypt failed" << std::endl;
            return;
        }
        void* out_void = OPENSSL_malloc(outlen);

        if (!out_void) {
            std::cerr << "EVP_PKEY_encrypt failed" << std::endl;
            return;
        }
        if (EVP_PKEY_decrypt(ctx, (uint8_t*)out_void, &outlen, in, inlen) <= 0) {
            std::cerr << "EVP_PKEY_encrypt failed" << std::endl;
            return;
        }

        out = (uint8_t*)out_void;
    };

    encrypt(in, inlen, out, outlen);

    std::cout << "OUTLEN " << outlen << std::endl;
    for (int i = 0; i < outlen; i++) {
        std::cout << ((char*)out)[i] << std::endl;
    }
    std::cout << std::endl;

    // decrypt(out, outlen, out1, outlen1);
}
