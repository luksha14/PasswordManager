#include "PasswordGenerator.h"
#include <algorithm>
#include <iterator>
#include <stdexcept>
#include <chrono>

const std::string PasswordGenerator::UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const std::string PasswordGenerator::LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
const std::string PasswordGenerator::DIGITS    = "0123456789";
const std::string PasswordGenerator::SYMBOLS   = "!@#$%^&*()-_+=<>?[]{}|";


std::random_device PasswordGenerator::rd;
std::mt19937 PasswordGenerator::generator(PasswordGenerator::rd());


std::string PasswordGenerator::generate(const Options& options) {
    if (options.length <= 0 || options.length > 1024) {
        throw std::runtime_error("Invalid password length.");
    }
    
    std::string characterSet = "";
    
    int numRequired = 0;
    if (options.useUppercase) { characterSet += UPPERCASE; numRequired++; }
    if (options.useLowercase) { characterSet += LOWERCASE; numRequired++; }
    if (options.useDigits)    { characterSet += DIGITS;    numRequired++; }
    if (options.useSymbols)   { characterSet += SYMBOLS;   numRequired++; }

    if (characterSet.empty()) {
        throw std::runtime_error("At least one character type must be selected.");
    }
    if (options.length < numRequired) {
        throw std::runtime_error("Length must be >= number of required types.");
    }
    
    std::string password = "";
    
    std::uniform_int_distribution<> distribution(0, 1000); 


    if (options.useUppercase) password += UPPERCASE[distribution(generator) % UPPERCASE.length()];
    if (options.useLowercase) password += LOWERCASE[distribution(generator) % LOWERCASE.length()];
    if (options.useDigits)    password += DIGITS[distribution(generator) % DIGITS.length()];
    if (options.useSymbols)   password += SYMBOLS[distribution(generator) % SYMBOLS.length()];
    

    std::uniform_int_distribution<> preciseDistribution(0, characterSet.length() - 1); 

    int remainingLength = options.length - password.length();

    for (int i = 0; i < remainingLength; ++i) {
        int randomIndex = preciseDistribution(generator);
        password += characterSet[randomIndex];
    }

    std::shuffle(password.begin(), password.end(), generator);
    
    return password;
}