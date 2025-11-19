#pragma once
#include <string>
#include "../db/Database.h"

class AuthService {
public:
    AuthService(Database& db);

    bool masterPasswordExists();
    void createMasterPassword(const std::string& password);
    bool verifyMasterPassword(const std::string& password);

    std::string deriveEncryptionKey(const std::string& password);

private:
    Database& db;
};
