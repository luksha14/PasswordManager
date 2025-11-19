#include "AES.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>

using namespace Crypto;

static void handleError(const char* msg) {
    throw std::runtime_error(msg);
}

AESResult AESGCM::encrypt(const std::string& plaintext,
                          const std::string& key) 
{
    if (key.size() != 32) {
        throw std::runtime_error("AES-256 requires 32-byte key.");
    }

    AESResult result;

    // GCM standard → 12-byte IV
    result.iv.resize(12);
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&result.iv[0]), 12) != 1)
        handleError("Failed to generate IV");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleError("EVP_CIPHER_CTX_new failed");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                                reinterpret_cast<const unsigned char*>(key.data()),
                                reinterpret_cast<const unsigned char*>(result.iv.data())))
        handleError("EncryptInit failed");

    result.ciphertext.resize(plaintext.size());

    int len;
    if (1 != EVP_EncryptUpdate(ctx,
                               reinterpret_cast<unsigned char*>(&result.ciphertext[0]),
                               &len,
                               reinterpret_cast<const unsigned char*>(plaintext.data()),
                               plaintext.size()))
        handleError("EncryptUpdate failed");

    int final_len;
    if (1 != EVP_EncryptFinal_ex(ctx,
                                 reinterpret_cast<unsigned char*>(&result.ciphertext[0]) + len,
                                 &final_len))
        handleError("EncryptFinal failed");

    result.ciphertext.resize(len + final_len);

    result.tag.resize(16);
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16,
                                 reinterpret_cast<unsigned char*>(&result.tag[0])))
        handleError("GET_TAG failed");

    EVP_CIPHER_CTX_free(ctx);

    return result;
}

std::string AESGCM::decrypt(const std::string& ciphertext,
                            const std::string& iv,
                            const std::string& tag,
                            const std::string& key)
{
    if (key.size() != 32) {
        throw std::runtime_error("AES-256 requires 32-byte key.");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleError("CTX new failed");

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                                reinterpret_cast<const unsigned char*>(key.data()),
                                reinterpret_cast<const unsigned char*>(iv.data())))
        handleError("DecryptInit failed");

    std::string plaintext;
    plaintext.resize(ciphertext.size());

    int len;
    if (1 != EVP_DecryptUpdate(ctx,
                               reinterpret_cast<unsigned char*>(&plaintext[0]),
                               &len,
                               reinterpret_cast<const unsigned char*>(ciphertext.data()),
                               ciphertext.size()))
        handleError("DecryptUpdate failed");

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                 (void*)tag.data()))
        handleError("SET_TAG failed");

    int final_len = 0;
    int rc = EVP_DecryptFinal_ex(ctx,
                                 (unsigned char*)&plaintext[0] + len,
                                 &final_len);

    EVP_CIPHER_CTX_free(ctx);

    if (rc != 1) {
        throw std::runtime_error("Decryption failed — wrong key or modified data.");
    }

    plaintext.resize(len + final_len);
    return plaintext;
}
