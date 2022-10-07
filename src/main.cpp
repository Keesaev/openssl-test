#include <iostream>

#include "crypter.h"

int main()
{
    std::basic_string<uint8_t> source { 0x01, 0x02, 0x03 };

    std::cout << "SOURCE (of size = " << source.size() << ")\n";
    for(const int& i : source){
        std::cout << i << ' ';
    }
    std::cout << std::endl;

    crypter c;
    auto encrypted = c.encrypt(source);

    std::cout << "ENCRYPTED (of size = " << encrypted.size() << ")\n";
    for (const int& i : encrypted) {
        std::cout << i << ' ';
    }

    auto decrypted = c.decrypt(encrypted);

    std::cout << "\nDECRYPTED (of size = " << decrypted.size() << ")\n";
    for (const int& i : decrypted) {
        std::cout << i << ' ';
    }
    std::cout << std::endl;

    return 0;
}