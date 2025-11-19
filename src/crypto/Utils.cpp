#include "Utils.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>

std::string Utils::sha256(const std::string& input) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";

    if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr)) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    if (1 != EVP_DigestUpdate(ctx, input.data(), input.size())) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    if (1 != EVP_DigestFinal_ex(ctx, hash, &hash_len)) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    EVP_MD_CTX_free(ctx);

    // Pretvaramo hash u hex string
    std::stringstream ss;
    for (unsigned int i = 0; i < hash_len; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];

    return ss.str();
}

std::string Utils::generateSalt(size_t length) {
    unsigned char *salt = new unsigned char[length];
    
    // RAND_bytes generira kriptografski sigurne nasumične bajtove
    int rc = RAND_bytes(salt, length);
    
    if (rc != 1) {
        delete[] salt;
        throw std::runtime_error("Failed to generate secure random bytes (salt).");
    }

    std::string result((char*)salt, length);
    delete[] salt;
    return result;
}

// IMPLEMENTACIJA pbkdf2
std::string Utils::pbkdf2(const std::string& password, const std::string& salt, int iterations, size_t key_length) {
    unsigned char *derived_key = new unsigned char[key_length];

    int rc = PKCS5_PBKDF2_HMAC((const char*)password.c_str(), password.length(),
                                (const unsigned char*)salt.c_str(), salt.length(),
                                iterations, EVP_sha256(), key_length, derived_key);

    if (rc != 1) {
        delete[] derived_key;
        throw std::runtime_error("PKCS5_PBKDF2_HMAC failed.");
    }

    std::string result((char*)derived_key, key_length);
    delete[] derived_key;
    return result;
}

std::string Utils::base64Encode(const std::string& data) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // bez new line
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string encoded(bufferPtr->data, bufferPtr->length);

    BIO_free_all(bio);
    return encoded;
}

std::string Utils::base64Decode(const std::string& data) {
    BIO *bio, *b64;

    std::string decoded(data.size(), '\0');

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_mem_buf(data.data(), data.size());
    bio = BIO_push(b64, bio);

    int decodedLen = BIO_read(bio, &decoded[0], data.size());
    decoded.resize(decodedLen);

    BIO_free_all(bio);
    return decoded;
}
