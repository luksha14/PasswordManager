#include "Migrations.h"
#include "Database.h"
#include <iostream>

void Migrations::run(Database& db) {
    // users table (ako želiš držati master hash ovdje umjesto settings)
    const char* usersSql =
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT UNIQUE,"
        "master_password_hash TEXT"
        ");";

    // settings table - key/value storage (koristimo za master_hash)
    const char* settingsSql =
        "CREATE TABLE IF NOT EXISTS settings ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "key TEXT UNIQUE NOT NULL,"
        "value BLOB NOT NULL"
        ");";

    const char* credentialsSql =
        "CREATE TABLE IF NOT EXISTS credentials ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "service TEXT NOT NULL,"
        "username TEXT NOT NULL,"
        "password_enc BLOB NOT NULL,"
        "iv BLOB NOT NULL,"
        "tag BLOB NOT NULL,"
        "created_at TEXT DEFAULT CURRENT_TIMESTAMP"
        ");";

    if (!db.execute(usersSql)) {
        std::cerr << "[MIGRATIONS] Failed to create users table\n";
    }
    if (!db.execute(settingsSql)) {
        std::cerr << "[MIGRATIONS] Failed to create settings table\n";
    }
    if (!db.execute(credentialsSql)) {
        std::cerr << "[MIGRATIONS] Failed to create credentials table\n";
    }

    std::cout << "[MIGRATIONS] Done\n";
}
