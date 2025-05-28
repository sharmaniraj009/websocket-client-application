#include "websocket_client.h"
#include <iostream>
#include <string>
#include <thread>
#include <chrono>

void printUsage() {
    std::cout << "WebSocket Client Commands:\n";
    std::cout << "  connect <url>     - Connect to WebSocket server\n";
    std::cout << "  send <message>    - Send text message\n";
    std::cout << "  sendb <hex_data>  - Send binary message (hex format)\n";
    std::cout << "  disconnect        - Disconnect from server\n";
    std::cout << "  status            - Show connection status\n";
    std::cout << "  help              - Show this help\n";
    std::cout << "  quit              - Exit application\n\n";
}

int main() {
    WebSocketClient client;
    std::string input;
    
    std::cout << "WebSocket Client v1.0\n";
    std::cout << "=====================\n\n";
    printUsage();
    
    while (true) {
        std::cout << "> ";
        std::getline(std::cin, input);
        
        if (input.empty()) continue;
        
        std::istringstream iss(input);
        std::string command;
        iss >> command;
        
        if (command == "quit" || command == "exit") {
            client.disconnect();
            break;
        }
        else if (command == "help") {
            printUsage();
        }
        else if (command == "connect") {
            std::string url;
            iss >> url;
            if (url.empty()) {
                std::cout << "Usage: connect <url>\n";
                std::cout << "Example: connect wss://echo.websocket.events/.ws\n";
                continue;
            }
            
            std::cout << "Connecting to " << url << "...\n";
            if (client.connect(url)) {
                std::cout << "Connected successfully!\n";
            } else {
                std::cout << "Connection failed!\n";
            }
        }
        else if (command == "send") {
            std::string message;
            std::getline(iss, message);
            if (message.empty()) {
                std::cout << "Usage: send <message>\n";
                continue;
            }
            // Remove leading space
            if (!message.empty() && message[0] == ' ') {
                message = message.substr(1);
            }
            
            if (client.sendText(message)) {
                std::cout << "Message sent: " << message << "\n";
            } else {
                std::cout << "Failed to send message. Not connected?\n";
            }
        }
        else if (command == "sendb") {
            std::string hexData;
            iss >> hexData;
            if (hexData.empty()) {
                std::cout << "Usage: sendb <hex_data>\n";
                std::cout << "Example: sendb 48656c6c6f (Hello in hex)\n";
                continue;
            }
            
            // Convert hex string to binary data
            std::vector<uint8_t> binaryData;
            for (size_t i = 0; i < hexData.length(); i += 2) {
                if (i + 1 < hexData.length()) {
                    std::string byteStr = hexData.substr(i, 2);
                    try {
                        uint8_t byte = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
                        binaryData.push_back(byte);
                    } catch (const std::exception& e) {
                        std::cout << "Invalid hex data: " << byteStr << "\n";
                        binaryData.clear();
                        break;
                    }
                }
            }
            
            if (!binaryData.empty()) {
                if (client.sendBinary(binaryData)) {
                    std::cout << "Binary message sent (" << binaryData.size() << " bytes)\n";
                } else {
                    std::cout << "Failed to send binary message. Not connected?\n";
                }
            }
        }
        else if (command == "disconnect") {
            client.disconnect();
            std::cout << "Disconnected.\n";
        }
        else if (command == "status") {
            std::cout << "Connection status: " << (client.isConnected() ? "Connected" : "Disconnected") << "\n";
        }
        else {
            std::cout << "Unknown command: " << command << "\n";
            std::cout << "Type 'help' for available commands.\n";
        }
    }
    
    std::cout << "Goodbye!\n";
    return 0;
}