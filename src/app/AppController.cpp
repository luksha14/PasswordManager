#include "AppController.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <limits>
#include <string>
#include <stdexcept> 
#include "../services/PasswordGenerator.h"
#include "../util/ConsoleColor.h"
#include "../util/SecureMemory.h"
#include "../util/ActivityLogger.h"

AppController::AppController(Database& database)
    : db(database), auth(database), credentials(database) {}

void AppController::start() {
    showWelcomeScreen();

    if (!auth.masterPasswordExists()) {
        handleRegistration();
    } else {
        handleLogin();
    }
    mainMenu();
}

void AppController::showWelcomeScreen() {
    using namespace Color; 

    std::cout << BOLD << GREEN << "=================================================\n";
    std::cout << BOLD << GREEN << "          CLI Password Manager v1.0\n";
    std::cout << BOLD << GREEN << "=================================================\n";
    std::cout << RESET;
}

#ifdef _WIN32
    // Windows: Use conio.h and _getch()
    #include <conio.h> 
    #define GETCH _getch
#else
    // Linux/macOS (UNIX-like): Use termios.h and unistd.h
    #include <termios.h>
    #include <unistd.h>
    
    // Custom function to mimic _getch() behavior on UNIX-like systems
    int getch_unix() {
        int ch;
        struct termios oldt, newt;
        
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~(ICANON | ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        
        ch = getchar();
        
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        return ch;
    }
    #define GETCH getch_unix
#endif

// Helper function to read a masked password
std::string getMaskedPassword(const std::string& prompt) {
    std::string password;
    char character;
    std::cout << prompt;

    while (true) {
        character = GETCH();

        if (character == 13) { // ENTER key
            break;
        }

        if (character == 8) { // BACKSPACE key
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b"; 
            }
        } else if (character >= 32) { 
            password.push_back(character);
            std::cout << "*";
        }
    }
    std::cout << std::endl;
    return password;
}

void AppController::handleRegistration() {
    std::string pass1, pass2;

    std::cout << "Welcome! Master password is not set yet.\n";
    std::cout << "   Please create a master password.\n\n";

    while (true) {
        std::cout << "Enter master password: ";
        std::getline(std::cin, pass1);

        std::cout << "Repeat master password: ";
        std::getline(std::cin, pass2);

        if (pass1 != pass2) {
            std::cout << "Passwords do not match. Try again.\n\n";
            continue;
        }

        if (pass1.length() < 4) {
            std::cout << "Password must be at least 4 characters long.\n\n";
            continue;
        }

        // 1. Pokusaj registracije kljuca
        try {
            auth.createMasterPassword(pass1); 
            
            // 2. SUCCESS: Deriviraj i pohrani enkripcijski ključ
            this->encryptionKey = auth.deriveEncryptionKey(pass1);

            std::cout << "Master password successfully created!\n\n";
            break; 
            
        } catch (const std::runtime_error& e) {
            std::cerr << "CRITICAL ERROR: Failed to save master password or derive key: " << e.what() << "\n";
            std::cout << "Error saving password. Please check database connection and try again.\n";
        } catch (const std::exception& e) {
            std::cerr << "UNEXPECTED ERROR: " << e.what() << "\n";
            std::cout << "An unexpected error occurred. Please try again.\n";
        }
    }
}

bool AppController::handleLogin() {
    std::string pass;

    std::cout << "\nEnter master password to access:\n";

    while (true) {
        
        pass = getMaskedPassword("Password: "); 

        if (auth.verifyMasterPassword(pass)) {
            
            // Derive and store the encryption key
            try {
                encryptionKey = auth.deriveEncryptionKey(pass);
            } catch (const std::runtime_error& e) {
                 std::cerr << "CRITICAL ERROR: Failed to derive encryption key: " << e.what() << "\n";
                 exit(1);
            }
            
            std::cout << "Login successful! Welcome back.\n\n";
            this->encryptionKey = encryptionKey; 
            this->lastActivityTime = std::time(nullptr); 
            ActivityLogger::log("SUCCESS", "User successfully logged in.");
            return true;
        } else {
            std::cout << "Incorrect password. Try again.\n";
            ActivityLogger::log("WARNING", "Failed login attempt with provided Master Key.");
        }
    }
}


void AppController::handleStorePassword() {
    using namespace Color;
    std::string service, username, plaintextPassword;
    
    std::cout << "\n--- " << BOLD << PROMPT << "Store New Password" << RESET << " ---\n";

    std::cout << PROMPT << "Service/Website name: " << RESET;
    std::getline(std::cin, service);
    
    std::cout << PROMPT << "Username/Email: " << RESET;
    std::getline(std::cin, username);

    std::cout << PROMPT << "Password to store (plaintext): " << RESET;
    std::getline(std::cin, plaintextPassword);
    
    // (Ovdje možemo dodati provjeru lozinke, ali za sada, samo je spremi)

    executeStore(service, username, plaintextPassword);

    this->lastActivityTime = std::time(nullptr);
}

void AppController::handleViewAllPasswords() {
    using namespace Color;
    std::cout << "\n--- " << BOLD << PROMPT << "All Stored Credentials" << RESET << " ---\n";

    try {
        // POZIVAMO CredentialService s KLJUČEM za dekripciju!
        std::vector<Credential> list = credentials.getAllCredentials(this->encryptionKey);

        if (list.empty()) {
            std::cout << "No credentials stored yet.\n";
            return;
        }

        // Prikaz
        for (const auto& c : list) {
        std::cout << HIGHLIGHT << "------------------------------------------" << RESET << "\n";
        std::cout << BOLD << "ID: " << c.id << "\n" << RESET;
        std::cout << "Service: " << HIGHLIGHT << c.service << RESET << "\n";
        std::cout << "Username: " << c.username << "\n";
        std::cout << "Password (Encrypted): " << c.rawCiphertext << "\n"; 
        std::cout << "Password (Decrypted): " << SUCCESS << BOLD << c.decryptedPassword << RESET << "\n"; // Lozinka u naglašenoj boji
        std::cout << "IV/Tag check: " << c.iv.substr(0, 4) << "... / " << c.tag.substr(0, 4) << "...\n"; 
        std::cout << "Created: " << c.createdAt << "\n";
        }
    std::cout << HIGHLIGHT << "------------------------------------------" << RESET << "\n";

    } catch (const std::exception& e) {
        std::cerr << "\nError viewing credentials: " << e.what() << "\n";
    }
    this->lastActivityTime = std::time(nullptr);
}

void AppController::handleDeletePassword() {
    using namespace Color;
    std::string input;
    int idToDelete = -1;

    handleViewAllPasswords();

    std::cout << "\n--- Delete Password ---\n";
    std::cout << "Enter the ID of the credential to delete (or 0 to cancel): ";
    std::getline(std::cin, input);

    try {
        idToDelete = std::stoi(input);
    } catch (const std::exception&) {
        std::cout << "\nInvalid input. Please enter a valid number.\n";
        return;
    }

    if (idToDelete == 0) {
        std::cout << "\nOperation cancelled.\n";
        return;
    }

    // Pozivamo CredentialService::deleteCredential(id)
    try {
        if (credentials.deleteCredential(idToDelete)) {
            std::cout << "\n" << SUCCESS << "Credential with ID " << idToDelete << " successfully deleted." << RESET << "\n";
        } else {
            std::cout << "\n" << ERROR << "Failed to delete credential (ID " << idToDelete << " not found or DB error)." << RESET << "\n";
        }
    } catch (const std::exception& e) {
        std::cerr << ERROR << "\nError during deletion: " << e.what() << RESET << "\n";
    }
    this->lastActivityTime = std::time(nullptr);
}

void AppController::handleSearchPasswords() {
    std::string query;
    std::cout << "\n--- Search Passwords ---\n";

    std::cout << "Enter service or username to search: ";
    std::getline(std::cin, query);

    if (query.empty()) {
        std::cout << "Search cancelled.\n";
        return;
    }

    try {
        // Pozivamo CredentialService s KLJUČEM i upitom
        std::vector<Credential> results = credentials.searchCredentials(query, this->encryptionKey);

        if (results.empty()) {
            std::cout << "\nNo credentials found matching '" << query << "'.\n";
            return;
        }

        std::cout << "\n✔ Found " << results.size() << " result(s) for '" << query << "':\n";
        
        for (const auto& c : results) {
            std::cout << "------------------------------------------\n";
            std::cout << "ID: " << c.id << "\n";
            std::cout << "Service: " << c.service << "\n";
            std::cout << "Username: " << c.username << "\n";
            std::cout << "Password (Encrypted): " << c.rawCiphertext << "\n";
            std::cout << "Password (Decrypted): " << c.decryptedPassword << "\n";
            std::cout << "Created: " << c.createdAt << "\n";
        }
        std::cout << "------------------------------------------\n";

    } catch (const std::exception& e) {
        std::cerr << "\nError during search: " << e.what() << "\n";
    }
    this->lastActivityTime = std::time(nullptr);
}

void AppController::handleGeneratePassword() {
    using namespace Color;
    PasswordGenerator::Options options;
    std::string input;
    std::string service, username, generatedPass;

    std::cout << "\n--- " << BOLD << HIGHLIGHT << "Password Generator" << RESET << " ---\n";

    std::cout << PROMPT << "Enter Service/Website name: " << RESET;
    std::getline(std::cin, service);
    if (service.empty()) {
        std::cout << ERROR << "Service name cannot be empty. Operation cancelled.\n" << RESET;
        return;
    }

    std::cout << PROMPT << "Enter Username/Email: " << RESET;
    std::getline(std::cin, username);
    if (username.empty()) {
        std::cout << ERROR << "Username cannot be empty. Operation cancelled.\n" << RESET;
        return;
    }
    // Unos duljine
    std::cout << PROMPT << "Enter desired length (Default 16): " << RESET;
    std::getline(std::cin, input);
    if (!input.empty()) {
        try {
            int length = std::stoi(input);
            if (length > 0) options.length = length;
        } catch (const std::exception&) {
        }
    }

    std::cout << "Include Symbols (!@#$)? (y/N - Default Y): ";
    std::getline(std::cin, input);
    if (!input.empty() && (input == "n" || input == "N")) options.useSymbols = false;

    std::cout << "Include Digits (0-9)? (y/N - Default Y): ";
    std::getline(std::cin, input);
    if (!input.empty() && (input == "n" || input == "N")) options.useDigits = false;

    try {
        std::string generatedPass = PasswordGenerator::generate(options);

        std::cout << "\nGenerated Password (" << generatedPass.length() << " chars):\n";
        std::cout << "------------------------------------------\n";
        std::cout << HIGHLIGHT << generatedPass << RESET << "\n";
        std::cout << "------------------------------------------\n";
        
        executeStore(service, username, generatedPass);

    } catch (const std::runtime_error& e) {
        std::cerr << ERROR << "Generator Error: " << e.what() << RESET << "\n";
    }
    this->lastActivityTime = std::time(nullptr);
}

void AppController::executeStore(const std::string& service, 
                                 const std::string& username, 
                                 const std::string& password) 
{
    using namespace Color;
    try {
        if (credentials.addCredential(service, username, password, this->encryptionKey)) {
            std::cout << "\n" << SUCCESS << BOLD << "Credential stored and encrypted successfully!\n" << RESET;
            ActivityLogger::log("ACTIVITY", "New credential stored for service: " + service);
        } else {
            std::cout << "\n" << ERROR << "FAILED to store the credential.\n" << RESET;
        }
    } catch (const std::exception& e) {
        std::cerr << ERROR << "Error during storing: " << e.what() << RESET << "\n";
    }
}

void AppController::handleExport() {
    using namespace Color;
    std::cout << "\n--- " << BOLD << HIGHLIGHT << "Export Credentials" << RESET << " ---\n";

    std::string data = credentials.exportAllEncryptedData();

    if (data.empty()) {
        std::cout << ERROR << "No credentials found to export.\n" << RESET;
        return;
    }

    std::string filename = "encrypted_export.csv";
    
    std::ofstream outfile(filename);
    if (outfile.is_open()) {
        outfile << data;
        outfile.close();
        std::cout << SUCCESS << BOLD << "Export successful! " << RESET 
                  << "Data saved to '" << HIGHLIGHT << filename << RESET << "'.\n";
                  ActivityLogger::log("ACTIVITY", "Data successfully exported to encrypted_export.csv");
        std::cout << YELLOW << "Remeinder: Data is still encrypted, but treat this file as highly sensitive.\n" << RESET;
    } else {
        std::cout << ERROR << "Could not open file for writing: " << filename << RESET << "\n";
    }
    this->lastActivityTime = std::time(nullptr);
}

void AppController::handleImport() {
    using namespace Color;
    std::string filename;
    std::string fileContent;

    std::cout << "\n--- " << BOLD << HIGHLIGHT << "Import Credentials" << RESET << " ---\n";
    std::cout << YELLOW << "Only import files previously exported by this application (Encrypted CSV).\n" << RESET;
    std::cout << PROMPT << "Enter filename to import (e.g., encrypted_export.csv): " << RESET;
    
    std::getline(std::cin, filename);

    if (filename.empty()) {
        std::cout << ERROR << "Operation cancelled.\n" << RESET;
        return;
    }

    // Čitanje datoteke
    std::ifstream infile(filename);
    if (infile.is_open()) {
        // Čita cijeli sadržaj datoteke u jedan string
        std::stringstream buffer;
        buffer << infile.rdbuf();
        fileContent = buffer.str();
        infile.close();

        if (fileContent.empty()) {
            std::cout << ERROR << "File is empty or could not be read.\n" << RESET;
            return;
        }

        // Pozivanje servisa za uvoz
        if (credentials.importEncryptedData(fileContent)) {
            std::cout << "\n" << SUCCESS << BOLD << "Import finished successfully! Credentials added to your database.\n" << RESET;
            ActivityLogger::log("ACTIVITY", "Data successfully exported to encrypted_export.csv");
        } else {
            std::cout << "\n" << ERROR << "Import failed or no valid credentials were found in the file.\n" << RESET;
        }

    } else {
        std::cout << ERROR << "Could not open file: " << filename << RESET << "\n";
    }
    this->lastActivityTime = std::time(nullptr);
}

bool AppController::checkAutoLock() {
    if (this->encryptionKey.empty()) {
        return false; 
    }

    std::time_t currentTime = std::time(nullptr);
    double elapsedSeconds = std::difftime(currentTime, this->lastActivityTime);

    if (elapsedSeconds >= AUTO_LOCK_TIMEOUT_SECONDS) {
        
        // Izvrši sigurno brisanje ključa
        SecureMemory::erase(this->encryptionKey);

        // Logiranje i postavljanje statusa odjave
        ActivityLogger::log("INFO", "SESSION LOCKED: Auto-lock triggered due to " + std::to_string(AUTO_LOCK_TIMEOUT_SECONDS) + "s inactivity.");
        this->encryptionKey = ""; 
        
        std::cout << "\n" << Color::ERROR << "WARNING: Session locked! " 
                  << AUTO_LOCK_TIMEOUT_SECONDS << " seconds of inactivity detected." 
                  << Color::RESET << "\n";
                  
        return true; 
    }
    return false; 
}

// --- Main Menu ---
void AppController::mainMenu() {
    using namespace Color;
    while (true) {

        if (this->encryptionKey.empty()) {
            return; 
        }
        if (checkAutoLock()) {
            return; 
        }

        std::cout << "\n----------------------------------------\n";
        std::cout << BOLD << PROMPT << "                MAIN MENU\n"; 
        std::cout << RESET << "----------------------------------------\n";
        
        std::cout << WHITE << "1. " << CYAN << "Store a new password\n";
        std::cout << WHITE << "2. " << CYAN << "View all passwords\n";
        std::cout << WHITE << "3. " << CYAN << "Search passwords\n";
        std::cout << WHITE << "4. " << CYAN << "Delete a password\n";
        std::cout << WHITE << "5. " << CYAN << "Generate a secure password\n"; 
        std::cout << WHITE << "6. " << MAGENTA << "Export all credentials (Encrypted)\n";
        std::cout << WHITE << "7. " << MAGENTA << "Import credentials (Encrypted)\n";
        std::cout << WHITE << "0. " << RED << "Exit\n"; 
        std::cout << RESET << "----------------------------------------\n";
        std::cout << PROMPT << "Select option: " << RESET;

        char choice;
        std::cin >> choice;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        std::time_t currentTime = std::time(nullptr);
        double elapsed = std::difftime(currentTime, this->lastActivityTime);
        if (elapsed >= AUTO_LOCK_TIMEOUT_SECONDS) {
            checkAutoLock(); 
            return; 
        }
        this->lastActivityTime = currentTime;

        switch (choice) {
        case '1':
            handleStorePassword();
            break;
        case '2':
            handleViewAllPasswords();
            break;
        case '3':
            handleSearchPasswords();
            break;
        case '4':
            handleDeletePassword();
            break;
        case '5':
            handleGeneratePassword(); 
            break;
        case '6': 
            handleExport();
            break;
        case '7': 
            handleImport();
            break;
        case '0':
            SecureMemory::erase(this->encryptionKey);
            ActivityLogger::log("INFO", "Encryption key securely erased and user logged out.");
            std::cout << "\n" << Color::SUCCESS << "Thanks for using the Password Manager!\nEncryption key securely erased from memory." << Color::RESET << "\n";
            return; 
        default:
            std::cout << "\n" << Color::ERROR << "Invalid option. Please try again." << Color::RESET << "\n";
        }
    }
}