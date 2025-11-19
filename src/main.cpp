#include <iostream>
#include "db/Database.h"
#include "db/Migrations.h"
#include "app/AppController.h"

int main() {
    try {
        Database db("password_manager.db");

        Migrations::run(db);

        AppController app(db);
        app.start();

    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
