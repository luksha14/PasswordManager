#pragma once
#include "../db/Database.h"
#include "../services/AuthService.h"
#include "../services/CredentialService.h"
#include <ctime>

class AppController {
public:
    AppController(Database& db);
    bool checkAutoLock();
    bool handleLogin();
    void start();

private:
    Database& db;
    AuthService auth;
    CredentialService credentials;
    std::string encryptionKey;
    std::time_t lastActivityTime;
    const int AUTO_LOCK_TIMEOUT_SECONDS = 60;

    void showWelcomeScreen();
    void handleRegistration();
    void mainMenu();
    void handleStorePassword();
    void handleViewAllPasswords();
    void handleDeletePassword();
    void handleSearchPasswords();
    void handleGeneratePassword();
    void executeStore(const std::string& service, const std::string& username, const std::string& password);
    void handleExport();
    void handleImport();
};
