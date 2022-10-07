#include <iostream>

#include "crypter.h"

int main(){

    crypter c;
    std::basic_string<uint8_t> in;
    auto out = c.encrypt(in);

    for(const int& i : out){
        std::cout << i << ' ';
    }
    std::cout << std::endl;

    return 0;
}