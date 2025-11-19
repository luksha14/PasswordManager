#include "CredentialService.h"
#include "../crypto/AES.h" 
#include "../crypto/Utils.h"
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <map>

using namespace Crypto; 

CredentialService::CredentialService(Database& database)
    : db(database) {}


// addCredential (Sada KRIPTIRA i sprema sve 3 komponente)
bool CredentialService::addCredential(const std::string& service,
                                      const std::string& username,
                                      const std::string& plaintextPassword, 
                                      const std::string& encryptionKey)
{
    // 1. KRIPTIRAJ LOZINKU
    AESResult encrypted;
    try {
        encrypted = AESGCM::encrypt(plaintextPassword, encryptionKey);
    } catch (const std::runtime_error& e) {
        std::cerr << "Encryption failed: " << e.what() << std::endl;
        return false;
    }
    
    // 2. AŽURIRAJ SQL: SADA SPREMAMO 5 VRIJEDNOSTI (service, username, ciphertext, iv, tag)
    std::string sql =
        "INSERT INTO credentials (service, username, password_enc, iv, tag) VALUES (?, ?, ?, ?, ?);";

    // 3. IZVRŠI
    return db.execute(sql, { 
        service, 
        username, 
        encrypted.ciphertext, // Kriptirani podaci
        encrypted.iv,         
        encrypted.tag         
    });
}


// getAllCredentials (Sada DEKRIPTIRA lozinke)
std::vector<Credential> CredentialService::getAllCredentials(const std::string& encryptionKey)
{
    // AŽURIRAJ SQL: DOHVAĆAMO password_enc, iv, i tag
    std::string sql =
        "SELECT id, service, username, password_enc, iv, tag, created_at FROM credentials;";

    auto rows = db.query(sql);
    std::vector<Credential> list;

    for (auto& row : rows) {
        Credential c;

        try {
            c.id = std::stoi(row[0]); 
        } catch (const std::exception&) {
            c.id = -1; 
        }

        c.service = row[1];       
        c.username = row[2];      
        c.rawCiphertext = row[3];
        c.iv = row[4];
        c.tag = row[5];
        c.createdAt = row[6];

        // DEKRIPTIRANJE
        try {
            c.decryptedPassword = AESGCM::decrypt(c.rawCiphertext, c.iv, c.tag, encryptionKey);
        } catch (const std::runtime_error& e) {
            c.decryptedPassword = "DECRYPTION FAILED: " + std::string(e.what());
        }
        
        list.push_back(c);
    }

    return list;
}

// CredentialService.cpp (deleteCredential)

bool CredentialService::deleteCredential(int id)
{
    // KORAK 1: Provjeri postoji li zapis s tim ID-jem.
    std::string count_sql = "SELECT COUNT(*) FROM credentials WHERE id = ?;";
    
    auto count_rows = db.query(count_sql, { std::to_string(id) });
    
    // Provjeri broj redaka. Ako je 0, ID ne postoji.
    if (count_rows.empty() || std::stoi(count_rows[0][0]) == 0) {
        return false; 
    }

    std::string delete_sql = "DELETE FROM credentials WHERE id = ?;";
    db.execute(delete_sql, { std::to_string(id) }); 

    return true; 
}

std::vector<Credential> CredentialService::searchCredentials(const std::string& query, const std::string& encryptionKey)
{
    // Priprema SQL upita: Tražimo po service ILI username (case-insensitive)
    std::string sql =
        "SELECT id, service, username, password_enc, iv, tag, created_at FROM credentials "
        "WHERE service LIKE ? OR username LIKE ?;";

    // Pripremamo query za LIKE operator 
    std::string wildcardQuery = "%" + query + "%";

    auto rows = db.query(sql, { wildcardQuery, wildcardQuery });

    std::vector<Credential> list;

    for (auto& row : rows) {
        Credential c;
        c.id = std::stoi(row[0]);
        c.service = row[1];
        c.username = row[2];
        c.rawCiphertext = row[3];
        c.iv = row[4];
        c.tag = row[5];
        c.createdAt = row[6];
        
        // DEKRIPTIRANJE
        try {
            c.decryptedPassword = AESGCM::decrypt(c.rawCiphertext, c.iv, c.tag, encryptionKey);
        } catch (const std::runtime_error& e) {
            c.decryptedPassword = "DECRYPTION FAILED: " + std::string(e.what());
        }
        
        list.push_back(c);
    }

    return list;
}


std::string CredentialService::exportAllEncryptedData() const {
    std::string query = "SELECT id, service, username, password_enc, iv, tag FROM credentials";
    
    std::vector<std::vector<std::string>> results = db.query(query);

    if (results.empty()) {
        return ""; 
    }

    
    std::string csvData = "id|service|username|ciphertext|iv|tag\n"; 
    
    for (const auto& row : results) {

        if (row.size() >= 6) { 
            csvData += row[0] + "|"; // id
            csvData += row[1] + "|"; // service
            csvData += row[2] + "|"; // username
            csvData += Utils::base64Encode(row[3]) + "|"; // password_enc (ciphertext)
            csvData += Utils::base64Encode(row[4]) + "|"; // iv
            csvData += Utils::base64Encode(row[5]) + "\n"; // tag
        } else {

        }
    }

    return csvData;
}


bool CredentialService::importEncryptedData(const std::string& rawData) {
    std::stringstream ss(rawData);
    std::string line;
    int importedCount = 0;
    
    // Preskoči header "id|service|username|ciphertext|iv|tag"
    std::getline(ss, line);

    while (std::getline(ss, line)) {
        if (line.empty()) 
            continue;

        std::stringstream lineStream(line);
        std::string segment;
        std::vector<std::string> parts;

        // Parsanje po '|'
        while (std::getline(lineStream, segment, '|')) {
            parts.push_back(segment);
        }

        if (parts.size() < 6) {
            std::cerr << "Warning: Skipping malformed line during import.\n";
            continue;
        }

        // Extract with Base64 decode
        std::string service = parts[1];
        std::string username = parts[2];

        std::string ciphertext = Utils::base64Decode(parts[3]);
        std::string iv         = Utils::base64Decode(parts[4]);
        std::string tag        = Utils::base64Decode(parts[5]);

        // Siguran insert (bez SQL injection)
        bool ok = db.execute(
            "INSERT INTO credentials (service, username, password_enc, iv, tag) VALUES (?, ?, ?, ?, ?)",
            { service, username, ciphertext, iv, tag }
        );

        if (ok) {
            importedCount++;
        } else {
            std::cerr << "Error inserting credential: " << service << "\n";
        }
    }

    if (importedCount > 0) {
        std::cout << "\nSuccessfully imported " << importedCount << " credentials.\n";
        return true;
    }

    return false;
}
