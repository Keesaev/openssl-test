#include "crypter.h"

#include <openssl/engine.h>
#include <openssl/rsa.h>

#include <iostream> // TODO RM
#include <memory>

crypter::crypter()
    : _key { EVP_RSA_gen(1024) }
    , _ctx { EVP_PKEY_CTX_new(_key, nullptr) }
{
    if (!_ctx) {
        std::cerr << "EVP_PKEY_CTX_new failed" << std::endl;
    }
}

std::basic_string<uint8_t> crypter::encrypt(std::basic_string<uint8_t> const& in_str)
{
    std::basic_string<uint8_t> out_str;
    // TODO delete
    size_t outlen, outlen1;
    size_t inlen = 5;

    if (!_ctx) {
        std::cerr << "EVP_PKEY_CTX_new failed" << std::endl;
        return out_str;
    }

    if (EVP_PKEY_encrypt_init(_ctx) <= 0) {
        std::cerr << "EVP_PKEY_encrypt_init failed" << std::endl;
        return out_str;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        std::cerr << "EVP_PKEY_CTX_set_rsa_padding failed" << std::endl;
        return out_str;
    }

    /* Determine buffer length */
    if (EVP_PKEY_encrypt(_ctx, NULL, &outlen, in_str.c_str(), inlen) <= 0) {
        std::cerr << "EVP_PKEY_encrypt failed" << std::endl;
        return out_str;
    }

    uint8_t* out = (uint8_t*)OPENSSL_malloc(outlen);

    if (!out) {
        std::cerr << "OPENSSL_malloc failed" << std::endl;
        return out_str;
    }

    if (EVP_PKEY_encrypt(_ctx, (uint8_t*)out, &outlen, in_str.c_str(), inlen) <= 0) {
        std::cerr << "EVP_PKEY_encrypt failed" << std::endl;
        return out_str;
    }

    out_str = std::basic_string<uint8_t>(out, outlen);
    return out_str;
}

std::basic_string<uint8_t> crypter::decrypt(std::basic_string<uint8_t> const& in)
{
    std::basic_string<uint8_t> out_str;
    return out_str; // TODO RM
    /*
        if (EVP_PKEY_decrypt_init(_ctx) <= 0) {
            std::cerr << "EVP_PKEY_encrypt failed" << std::endl;
            return out_str;
        }

        if (EVP_PKEY_CTX_set_rsa_padding(_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            std::cerr << "EVP_PKEY_encrypt failed" << std::endl;
            return out_str;
        }
        if (EVP_PKEY_decrypt(_ctx, NULL, &outlen, in, inlen) <= 0) {
            std::cerr << "EVP_PKEY_encrypt failed" << std::endl;
            return out_str;
        }
        out = (uint8_t*)OPENSSL_malloc(outlen);

        if (!out) {
            std::cerr << "EVP_PKEY_encrypt failed" << std::endl;
            return out_str;
        }
        if (EVP_PKEY_decrypt(_ctx, out, &outlen, in, inlen) <= 0) {
            std::cerr << "EVP_PKEY_encrypt failed" << std::endl;
            return out_str;
        }*/
}
