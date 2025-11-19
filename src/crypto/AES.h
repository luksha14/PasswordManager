#pragma once
#include <string>
#include <vector>

namespace Crypto {

    struct AESResult {
        std::string ciphertext;  // binary, not hex!
        std::string iv;          // 12 bytes for GCM
        std::string tag;         // 16 bytes authentication tag
    };

    class AESGCM {
    public:
        static AESResult encrypt(const std::string& plaintext,
                                 const std::string& key);

        static std::string decrypt(const std::string& ciphertext,
                                   const std::string& iv,
                                   const std::string& tag,
                                   const std::string& key);
    };

}
