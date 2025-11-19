#pragma once
class Database;

class Migrations {
public:
    static void run(Database& db);
};
