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

    size_t outlen;
    if (EVP_PKEY_encrypt(_ctx, NULL, &outlen, in_str.c_str(), in_str.size()) <= 0) {
        std::cerr << "EVP_PKEY_encrypt failed" << std::endl;
        return out_str;
    }

    auto openssl_deleter = [](uint8_t* a) {
        OPENSSL_free(a);
    };

    auto out = std::unique_ptr<uint8_t, decltype(openssl_deleter)>((uint8_t*)OPENSSL_malloc(outlen), openssl_deleter);

    if (!out.get()) {
        std::cerr << "OPENSSL_malloc failed" << std::endl;
        return out_str;
    }

    if (EVP_PKEY_encrypt(_ctx, out.get(), &outlen, in_str.c_str(), in_str.size()) <= 0) {
        std::cerr << "EVP_PKEY_encrypt failed" << std::endl;
        return out_str;
    }

    return std::basic_string<uint8_t>(out.get(), outlen);
}

std::basic_string<uint8_t> crypter::decrypt(std::basic_string<uint8_t> const& in_str)
{
    std::basic_string<uint8_t> out_str;

    if (EVP_PKEY_decrypt_init(_ctx) <= 0) {
        std::cerr << "EVP_PKEY_encrypt failed" << std::endl;
        return out_str;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        std::cerr << "EVP_PKEY_encrypt failed" << std::endl;
        return out_str;
    }

    size_t outlen;
    if (EVP_PKEY_decrypt(_ctx, NULL, &outlen, in_str.c_str(), in_str.size()) <= 0) {
        std::cerr << "EVP_PKEY_encrypt failed" << std::endl;
        return out_str;
    }

    auto openssl_deleter = [](uint8_t* a) {
        OPENSSL_free(a);
    };

    auto out = std::unique_ptr<uint8_t, decltype(openssl_deleter)>((uint8_t*)OPENSSL_malloc(outlen), openssl_deleter);

    if (!out.get()) {
        std::cerr << "EVP_PKEY_encrypt failed" << std::endl;
        return out_str;
    }
    if (EVP_PKEY_decrypt(_ctx, out.get(), &outlen, in_str.c_str(), in_str.size()) <= 0) {
        std::cerr << "EVP_PKEY_encrypt failed" << std::endl;
        return out_str;
    }

    return std::basic_string<uint8_t>(out.get(), outlen);
}
