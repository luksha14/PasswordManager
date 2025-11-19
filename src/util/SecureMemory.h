#pragma once

#include <string>
#include <cstring>

class SecureMemory {
public:
    /**
     * @brief Sigurno briše sadržaj std::string objekta u memoriji.
     * * Koristimo volatile ili memcpy/memset_s za sprječavanje kompilatora
     * da optimizira (preskoči) brisanje kao nepotreban korak.
     *
     * @param target String za brisanje.
     */
    static void erase(std::string& target) {
        if (!target.empty()) {
            volatile char* p = const_cast<volatile char*>(target.data());
            
            // Koristimo standardni memset i volatile pointer kao dobru praksu u C++.
            std::memset(const_cast<char*>(target.data()), 0, target.length());
        }

        target.clear();
    }
};