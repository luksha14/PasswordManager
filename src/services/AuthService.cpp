#include "AuthService.h"
#include "../crypto/Utils.h" 
#include <cstddef>

const size_t ENCRYPTION_KEY_LENGTH = 32; 
const int PBKDF2_ITERATIONS = 200000;

AuthService::AuthService(Database& database) : db(database) {}

bool AuthService::masterPasswordExists() {
    auto rows = db.query("SELECT value FROM settings WHERE key='master_hash'");
    return !rows.empty();
}

void AuthService::createMasterPassword(const std::string& password) {
    std::string salt = Utils::generateSalt(32);
    std::string hash = Utils::sha256(password + salt);

    db.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?)",
        { "master_hash", hash + ":" + salt }
    );
}

bool AuthService::verifyMasterPassword(const std::string& password) {
    auto rows = db.query("SELECT value FROM settings WHERE key='master_hash'");
    if (rows.empty()) return false;

    std::string stored = rows[0][0];
    auto pos = stored.find(":");

    std::string hash = stored.substr(0, pos);
    std::string salt = stored.substr(pos + 1);

    std::string attempt = Utils::sha256(password + salt);

    return (attempt == hash);
}

std::string AuthService::deriveEncryptionKey(const std::string& password) {
    auto rows = db.query("SELECT value FROM settings WHERE key='master_hash'");

    std::string stored = rows[0][0];
    auto pos = stored.find(":");
    std::string salt = stored.substr(pos + 1);

    return Utils::pbkdf2(password, salt, PBKDF2_ITERATIONS, ENCRYPTION_KEY_LENGTH);
}