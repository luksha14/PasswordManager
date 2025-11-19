#pragma once

#include <iostream>
#include <string>

// ANSI escape kodovi
namespace Color {
    const std::string RESET = "\033[0m"; 
    const std::string BOLD = "\033[1m";  

    // Tekst (Prednja boja)
    const std::string RED = "\033[31m";
    const std::string GREEN = "\033[32m";
    const std::string YELLOW = "\033[33m";
    const std::string BLUE = "\033[34m";
    const std::string MAGENTA = "\033[35m";
    const std::string CYAN = "\033[36m";
    const std::string WHITE = "\033[37m";
    
    // Boje za Manager:
    const std::string PROMPT = CYAN;   
    const std::string SUCCESS = GREEN; 
    const std::string ERROR = RED;     
    const std::string HIGHLIGHT = YELLOW; 
}