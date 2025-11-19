#pragma once

#include <string>
#include <random>

class PasswordGenerator {
public:

    struct Options {
        int length = 16;
        bool useUppercase = true;
        bool useLowercase = true;
        bool useDigits = true;
        bool useSymbols = true;
    };

    /**
     * @brief Generira kriptografski sigurnu nasumičnu lozinku.
     * @param options Struktura koja definira dužinu i setove znakova.
     * @return Generirana lozinka.
     */
    static std::string generate(const Options& options);

private:
    // Kriptografski siguran generator slučajnih brojeva
    static std::random_device rd;
    static std::mt19937 generator;

    static const std::string UPPERCASE;
    static const std::string LOWERCASE;
    static const std::string DIGITS;
    static const std::string SYMBOLS;
};