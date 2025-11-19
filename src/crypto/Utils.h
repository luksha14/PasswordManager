#pragma once
#include <string>
#include <cstddef> // za size_t

namespace Utils {
    std::string sha256(const std::string& input);
    std::string generateSalt(size_t length);
    std::string pbkdf2(const std::string& password, const std::string& salt, int iterations, size_t key_length); 
    std::string base64Encode(const std::string& data);
    std::string base64Decode(const std::string& data);
}