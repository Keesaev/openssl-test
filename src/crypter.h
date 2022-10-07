#pragma once

#include <string>

#include <openssl/evp.h>

class crypter {
    EVP_PKEY* _key;
    EVP_PKEY_CTX* _ctx;

public:
    crypter();

    std::basic_string<uint8_t> encrypt(std::basic_string<uint8_t> const& in_str);
    std::basic_string<uint8_t> decrypt(std::basic_string<uint8_t> const& in_str);
};