#pragma once

#include <string>
#include <fstream>
#include <ctime>
#include <iomanip>
#include <iostream>

class ActivityLogger {
private:
    static const std::string LOG_FILE;

    static std::string getTimestamp() {
        // Dobivanje trenutnog vremena i formatiranje
        std::time_t now = std::time(nullptr);
        std::tm* ltm = std::localtime(&now);

        char buffer[80];
        // Format: YYYY-MM-DD HH:MM:SS
        std::strftime(buffer, sizeof(buffer), "%d-%m-%Y %H:%M:%S", ltm);
        return std::string(buffer);
    }

public:
    static void log(const std::string& level, const std::string& message) {

        std::ofstream outfile(LOG_FILE, std::ios_base::app); 
        
        if (outfile.is_open()) {
            outfile << "[" << getTimestamp() << "] ";
            outfile << "[" << level << "] ";
            outfile << message << "\n";
            outfile.close();
        } else {
            std::cerr << "ERROR: Could not open log file: " << LOG_FILE << std::endl;
        }
    }
};

const std::string ActivityLogger::LOG_FILE = "app_activity.log";