#pragma once
#include <string>
#include <vector>
#include "../db/Database.h"

// CredentialService.h (Korigirano)

struct Credential {
    int id;
    std::string service;
    std::string username;
    std::string rawCiphertext; 
    std::string decryptedPassword; 
    std::string iv;
    std::string tag;
    std::string createdAt;
};

class CredentialService {
public:
    CredentialService(Database& db);

    bool addCredential(const std::string& service,
                       const std::string& username,
                       const std::string& plaintextPassword, // Sada primamo čistu lozinku
                       const std::string& encryptionKey);    // Primamo ključ

    std::vector<Credential> getAllCredentials(const std::string& encryptionKey);
    std::vector<Credential> searchCredentials(const std::string& query, const std::string& encryptionKey);

    bool deleteCredential(int id);

    std::string exportAllEncryptedData() const;
    bool importEncryptedData(const std::string& rawData);

private:
    Database& db;
};