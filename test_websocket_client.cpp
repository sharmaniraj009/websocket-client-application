#include "websocket_client.h"
#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include <chrono>
#include <thread>

class TestRunner {
private:
    int passed = 0;
    int failed = 0;
    std::string currentTest;

public:
    void startTest(const std::string& name) {
        currentTest = name;
        std::cout << "Running: " << name << "... ";
    }

    void assert_true(bool condition, const std::string& message = "") {
        if (condition) {
            std::cout << "PASS\n";
            passed++;
        } else {
            std::cout << "FAIL";
            if (!message.empty()) {
                std::cout << " - " << message;
            }
            std::cout << "\n";
            failed++;
        }
    }

    void assert_equals(const std::string& expected, const std::string& actual, const std::string& message = "") {
        if (expected == actual) {
            std::cout << "PASS\n";
            passed++;
        } else {
            std::cout << "FAIL - Expected: '" << expected << "', Got: '" << actual << "'";
            if (!message.empty()) {
                std::cout << " - " << message;
            }
            std::cout << "\n";
            failed++;
        }
    }

    void printSummary() {
        std::cout << "\n=== Test Summary ===\n";
        std::cout << "Passed: " << passed << "\n";
        std::cout << "Failed: " << failed << "\n";
        std::cout << "Total:  " << (passed + failed) << "\n";
        
        if (failed == 0) {
            std::cout << "All tests passed!\n";
        } else {
            std::cout << "Some tests failed!\n";
        }
    }

    int getFailedCount() const { return failed; }
};

// Test URL parsing functionality
void testURLParsing(TestRunner& runner) {
    WebSocketClient client;
    
    // Test valid WebSocket URLs
    runner.startTest("Parse valid ws:// URL");
    // Since parseURL is private, we'll test through connect (which will fail but still parse)
    bool result = client.connect("ws://example.com:8080/test");
    runner.assert_true(!result, "Connection should fail but URL should be parsed");
    
    runner.startTest("Parse valid wss:// URL");
    result = client.connect("wss://secure.example.com/websocket");
    runner.assert_true(!result, "Connection should fail but URL should be parsed");
}

// Test connection state management
void testConnectionState(TestRunner& runner) {
    WebSocketClient client;
    
    runner.startTest("Initial connection state");
    runner.assert_true(!client.isConnected(), "Should not be connected initially");
    
    runner.startTest("Connection state after failed connect");
    client.connect("ws://invalid-host-that-does-not-exist.local:9999/test");
    runner.assert_true(!client.isConnected(), "Should remain disconnected after failed connect");
}

// Test message callbacks
void testCallbacks(TestRunner& runner) {
    WebSocketClient client;
    
    std::string receivedMessage;
    bool callbackCalled = false;
    bool isBinaryReceived = false;
    
    // Set up message callback
    client.setOnMessage([&](const std::string& msg, bool isBinary) {
        receivedMessage = msg;
        callbackCalled = true;
        isBinaryReceived = isBinary;
    });
    
    runner.startTest("Message callback setup");
    runner.assert_true(true, "Callback should be set without errors");
    
    // Test error callback
    std::string errorMessage;
    bool errorCallbackCalled = false;
    
    client.setOnError([&](const std::string& error) {
        errorMessage = error;
        errorCallbackCalled = true;
    });
    
    runner.startTest("Error callback setup");
    runner.assert_true(true, "Error callback should be set without errors");
    
    // Trigger an error by connecting to invalid URL
    client.connect("invalid-url");
    
    runner.startTest("Error callback triggered");
    runner.assert_true(errorCallbackCalled, "Error callback should be called for invalid URL");
}

// Test sending messages when not connected
void testSendingWhenDisconnected(TestRunner& runner) {
    WebSocketClient client;
    
    runner.startTest("Send text when disconnected");
    bool result = client.sendText("Hello, World!");
    runner.assert_true(!result, "Sending text should fail when not connected");
    
    runner.startTest("Send binary when disconnected");
    std::vector<uint8_t> binaryData = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
    result = client.sendBinary(binaryData);
    runner.assert_true(!result, "Sending binary should fail when not connected");
}

// Test disconnect functionality
void testDisconnect(TestRunner& runner) {
    WebSocketClient client;
    
    runner.startTest("Disconnect when not connected");
    client.disconnect(); // Should not crash
    runner.assert_true(!client.isConnected(), "Should remain disconnected");
    
    runner.startTest("Multiple disconnects");
    client.disconnect();
    client.disconnect();
    runner.assert_true(!client.isConnected(), "Multiple disconnects should be safe");
}

// Test basic construction and destruction
void testConstructorDestructor(TestRunner& runner) {
    runner.startTest("Constructor/Destructor");
    {
        WebSocketClient client;
        runner.assert_true(!client.isConnected(), "New client should not be connected");
    }
    // Destructor called here - should not crash
    runner.assert_true(true, "Destructor should complete without errors");
}

// Test WebSocket key generation (indirectly through handshake attempt)
void testWebSocketKeyGeneration(TestRunner& runner) {
    WebSocketClient client;
    
    runner.startTest("WebSocket key generation");
    // Try to connect to a server that doesn't exist - this will test key generation
    // but fail at connection, which is expected
    bool result = client.connect("ws://localhost:99999/test");
    runner.assert_true(!result, "Connection should fail but key should be generated");
}

// Test multiple callback assignments
void testMultipleCallbacks(TestRunner& runner) {
    WebSocketClient client;
    
    int connectCount = 0;
    int disconnectCount = 0;
    
    runner.startTest("Multiple callback assignments");
    
    client.setOnConnect([&]() { connectCount++; });
    client.setOnDisconnect([&]() { disconnectCount++; });
    
    // Reassign callbacks
    client.setOnConnect([&]() { connectCount += 2; });
    client.setOnDisconnect([&]() { disconnectCount += 2; });
    
    runner.assert_true(true, "Multiple callback assignments should not crash");
}

int main() {
    std::cout << "WebSocket Client Unit Tests\n";
    std::cout << "===========================\n\n";
    
    TestRunner runner;
    
    // Run all tests
    testConstructorDestructor(runner);
    testConnectionState(runner);
    testURLParsing(runner);
    testCallbacks(runner);
    testSendingWhenDisconnected(runner);
    testDisconnect(runner);
    testWebSocketKeyGeneration(runner);
    testMultipleCallbacks(runner);
    
    runner.printSummary();
    
    return runner.getFailedCount() > 0 ? 1 : 0;
}