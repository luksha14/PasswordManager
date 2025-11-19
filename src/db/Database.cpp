#include "Database.h"
#include <iostream>

Database::Database(const std::string& path) {
    int rc = sqlite3_open(path.c_str(), &connection);

    if (rc != SQLITE_OK) {
        std::cerr << "[DB ERROR] Failed to open database: "
                  << sqlite3_errmsg(connection) << std::endl;
        throw std::runtime_error("Database connection failed");
    }

    std::cout << "[DB] Database opened: " << path << std::endl;
}

Database::~Database() {
    if (connection) {
        sqlite3_close(connection);
        std::cout << "[DB] Database connection closed." << std::endl;
    }
}

sqlite3* Database::get() {
    return connection;
}

bool Database::execute(const std::string& sql,
                       const std::vector<std::string>& params) 
{
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(connection, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "[DB ERROR] SQL prepare failed: " << sqlite3_errmsg(connection) << std::endl;
        return false;
    }

    // Bind parameters
    for (size_t i = 0; i < params.size(); i++) {
        sqlite3_bind_text(stmt, static_cast<int>(i + 1), params[i].c_str(), -1, SQLITE_TRANSIENT);
    }

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "[DB ERROR] SQL step failed: " << sqlite3_errmsg(connection) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;
}

std::vector<std::vector<std::string>> Database::query(
    const std::string& sql,
    const std::vector<std::string>& params)
{
    sqlite3_stmt* stmt;
    std::vector<std::vector<std::string>> results;

    if (sqlite3_prepare_v2(connection, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "SQL prepare failed: " << sqlite3_errmsg(connection) << std::endl;
        return results;
    }

    // Bind param
    for (int i = 0; i < params.size(); i++) {
        sqlite3_bind_text(stmt, i + 1, params[i].c_str(), -1, SQLITE_TRANSIENT);
    }

    // Fetch rows
    int cols = sqlite3_column_count(stmt);

    while (true) {
        int rc = sqlite3_step(stmt);

        if (rc == SQLITE_ROW) {
            std::vector<std::string> row;

            for (int c = 0; c < cols; c++) {
                const unsigned char* text = sqlite3_column_text(stmt, c);
                row.push_back(text ? reinterpret_cast<const char*>(text) : "");
            }

            results.push_back(row);
        }
        else if (rc == SQLITE_DONE) {
            break;
        }
        else {
            std::cerr << "SQL step failed: " << sqlite3_errmsg(connection) << std::endl;
            break;
        }
    }

    sqlite3_finalize(stmt);
    return results;
}

