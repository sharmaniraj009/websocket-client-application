#pragma once

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <sstream>

// Forward declarations for SSL types
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

class WebSocketClient {
public:
    // Callback types
    using OnMessageCallback = std::function<void(const std::string&, bool)>; // message, is_binary
    using OnConnectCallback = std::function<void()>;
    using OnDisconnectCallback = std::function<void()>;
    using OnErrorCallback = std::function<void(const std::string&)>;

    WebSocketClient();
    ~WebSocketClient();

    // Core functionality
    bool connect(const std::string& url);
    void disconnect();
    bool isConnected() const;
    
    // Message sending
    bool sendText(const std::string& message);
    bool sendBinary(const std::vector<uint8_t>& data);
    
    // Callback setters
    void setOnMessage(OnMessageCallback callback);
    void setOnConnect(OnConnectCallback callback);
    void setOnDisconnect(OnDisconnectCallback callback);
    void setOnError(OnErrorCallback callback);

private:
    struct WebSocketFrame {
        bool fin;
        uint8_t opcode;
        bool masked;
        uint64_t payloadLength;
        uint32_t maskingKey;
        std::vector<uint8_t> payload;
    };

    // Connection management
    bool connectSocket(const std::string& host, int port);
    bool performHandshake(const std::string& host, const std::string& path);
    void startReceiveLoop();
    void receiveLoop();
    
    // SSL/TLS support
    bool initSSL();
    void cleanupSSL();
    bool connectSSL();
    
    // WebSocket protocol
    std::string generateWebSocketKey();
    bool parseFrame(const std::vector<uint8_t>& data, WebSocketFrame& frame);
    std::vector<uint8_t> createFrame(uint8_t opcode, const std::vector<uint8_t>& payload, bool mask = true);
    void handleFrame(const WebSocketFrame& frame);
    bool sendFrame(uint8_t opcode, const std::vector<uint8_t>& payload);

    // Network I/O
    int socketRead(void* buffer, int length);
    int socketWrite(const void* buffer, int length);
    
    // URL parsing
    struct ParsedURL {
        std::string protocol;
        std::string host;
        int port;
        std::string path;
        bool isSecure;
    };
    
    bool parseURL(const std::string& url, ParsedURL& parsed);
    
    // Utility functions
    std::string base64Encode(const std::vector<uint8_t>& input);
    std::string sha1Hash(const std::string& input);
    uint32_t generateMaskingKey();
    void applyMask(std::vector<uint8_t>& data, uint32_t mask);
    
    // Member variables
    int m_socket;
    SSL* m_ssl;
    SSL_CTX* m_sslContext;
    bool m_isSecure;
    std::atomic<bool> m_connected;
    std::atomic<bool> m_shouldStop;
    
    std::thread m_receiveThread;
    std::mutex m_sendMutex;
    
    // Callbacks
    OnMessageCallback m_onMessage;
    OnConnectCallback m_onConnect;
    OnDisconnectCallback m_onDisconnect;
    OnErrorCallback m_onError;
    
    // Buffer for receiving data
    std::vector<uint8_t> m_receiveBuffer;
    
    // WebSocket constants
    static const std::string WEBSOCKET_MAGIC_STRING;
    static const uint8_t OPCODE_CONTINUATION = 0x0;
    static const uint8_t OPCODE_TEXT = 0x1;
    static const uint8_t OPCODE_BINARY = 0x2;
    static const uint8_t OPCODE_CLOSE = 0x8;
    static const uint8_t OPCODE_PING = 0x9;
    static const uint8_t OPCODE_PONG = 0xA;
};