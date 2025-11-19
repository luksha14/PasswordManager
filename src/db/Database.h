#pragma once
#include <string>
#include <vector>
#include <sqlite3.h>

class Database {
public:
    explicit Database(const std::string& path);
    ~Database();

    sqlite3* get();

    bool execute(const std::string& sql,
                 const std::vector<std::string>& params = {});

    std::vector<std::vector<std::string>> query(
        const std::string& sql,
        const std::vector<std::string>& params = {}
    );

private:
    sqlite3* connection = nullptr;
    bool bindParameters(sqlite3_stmt* stmt, const std::vector<std::string>& params); 
};