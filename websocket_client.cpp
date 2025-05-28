#include "websocket_client.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <iostream>
#include <random>
#include <regex>
#include <algorithm>
#include <iomanip>

const std::string WebSocketClient::WEBSOCKET_MAGIC_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

WebSocketClient::WebSocketClient() 
    : m_socket(-1)
    , m_ssl(nullptr)
    , m_sslContext(nullptr)
    , m_isSecure(false)
    , m_connected(false)
    , m_shouldStop(false) {
    
    // Set default callbacks that print to console
    m_onMessage = [](const std::string& message, bool isBinary) {
        if (isBinary) {
            std::cout << "Received binary message (" << message.size() << " bytes): ";
            for (size_t i = 0; i < std::min(message.size(), size_t(16)); ++i) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') 
                         << (unsigned char)message[i] << " ";
            }
            if (message.size() > 16) std::cout << "...";
            std::cout << std::dec << "\n";
        } else {
            std::cout << "Received: " << message << "\n";
        }
    };
    
    m_onConnect = []() {
        std::cout << "WebSocket connected!\n";
    };
    
    m_onDisconnect = []() {
        std::cout << "WebSocket disconnected!\n";
    };
    
    m_onError = [](const std::string& error) {
        std::cout << "Error: " << error << "\n";
    };
    
    initSSL();
}

WebSocketClient::~WebSocketClient() {
    disconnect();
    cleanupSSL();
}

bool WebSocketClient::initSSL() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    m_sslContext = SSL_CTX_new(TLS_client_method());
    if (!m_sslContext) {
        m_onError("Failed to create SSL context");
        return false;
    }
    
    // Set options for better security
    SSL_CTX_set_options(m_sslContext, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    
    return true;
}

void WebSocketClient::cleanupSSL() {
    if (m_ssl) {
        SSL_free(m_ssl);
        m_ssl = nullptr;
    }
    
    if (m_sslContext) {
        SSL_CTX_free(m_sslContext);
        m_sslContext = nullptr;
    }
}

bool WebSocketClient::parseURL(const std::string& url, ParsedURL& parsed) {
    std::regex urlRegex(R"(^(ws|wss)://([^:/]+)(?::(\d+))?(/.*)?$)");
    std::smatch matches;
    
    if (!std::regex_match(url, matches, urlRegex)) {
        return false;
    }
    
    parsed.protocol = matches[1].str();
    parsed.host = matches[2].str();
    parsed.isSecure = (parsed.protocol == "wss");
    
    if (matches[3].matched) {
        parsed.port = std::stoi(matches[3].str());
    } else {
        parsed.port = parsed.isSecure ? 443 : 80;
    }
    
    parsed.path = matches[4].matched ? matches[4].str() : "/";
    
    return true;
}

bool WebSocketClient::connect(const std::string& url) {
    if (m_connected) {
        disconnect();
    }
    
    ParsedURL parsed;
    if (!parseURL(url, parsed)) {
        m_onError("Invalid WebSocket URL: " + url);
        return false;
    }
    
    m_isSecure = parsed.isSecure;
    
    if (!connectSocket(parsed.host, parsed.port)) {
        return false;
    }
    
    if (m_isSecure && !connectSSL()) {
        close(m_socket);
        m_socket = -1;
        return false;
    }
    
    if (!performHandshake(parsed.host, parsed.path)) {
        disconnect();
        return false;
    }
    
    m_connected = true;
    m_shouldStop = false;
    startReceiveLoop();
    
    if (m_onConnect) {
        m_onConnect();
    }
    
    return true;
}

bool WebSocketClient::connectSocket(const std::string& host, int port) {
    // Resolve hostname
    struct hostent* hostEntry = gethostbyname(host.c_str());
    if (!hostEntry) {
        m_onError("Failed to resolve hostname: " + host);
        return false;
    }
    
    // Create socket
    m_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (m_socket < 0) {
        m_onError("Failed to create socket");
        return false;
    }
    
    // Setup server address
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr = *((struct in_addr*)hostEntry->h_addr);
    
    // Connect
    if (::connect(m_socket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        m_onError("Failed to connect to server");
        close(m_socket);
        m_socket = -1;
        return false;
    }
    
    return true;
}

bool WebSocketClient::connectSSL() {
    if (!m_sslContext) {
        m_onError("SSL context not initialized");
        return false;
    }
    
    m_ssl = SSL_new(m_sslContext);
    if (!m_ssl) {
        m_onError("Failed to create SSL object");
        return false;
    }
    
    if (SSL_set_fd(m_ssl, m_socket) != 1) {
        m_onError("Failed to set SSL file descriptor");
        return false;
    }
    
    int result = SSL_connect(m_ssl);
    if (result != 1) {
        int error = SSL_get_error(m_ssl, result);
        m_onError("SSL connection failed with error: " + std::to_string(error));
        return false;
    }
    
    return true;
}

std::string WebSocketClient::generateWebSocketKey() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    std::vector<uint8_t> keyBytes(16);
    for (int i = 0; i < 16; ++i) {
        keyBytes[i] = dis(gen);
    }
    
    return base64Encode(keyBytes);
}

std::string WebSocketClient::base64Encode(const std::vector<uint8_t>& input) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    
    BIO_write(bio, input.data(), input.size());
    BIO_flush(bio);
    
    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    
    return result;
}

std::string WebSocketClient::sha1Hash(const std::string& input) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);
    
    std::vector<uint8_t> hashVector(hash, hash + SHA_DIGEST_LENGTH);
    return base64Encode(hashVector);
}

bool WebSocketClient::performHandshake(const std::string& host, const std::string& path) {
    std::string key = generateWebSocketKey();
    
    std::stringstream request;
    request << "GET " << path << " HTTP/1.1\r\n";
    request << "Host: " << host << "\r\n";
    request << "Upgrade: websocket\r\n";
    request << "Connection: Upgrade\r\n";
    request << "Sec-WebSocket-Key: " << key << "\r\n";
    request << "Sec-WebSocket-Version: 13\r\n";
    request << "\r\n";
    
    std::string requestStr = request.str();
    if (socketWrite(requestStr.c_str(), requestStr.length()) <= 0) {
        m_onError("Failed to send handshake request");
        return false;
    }
    
    // Read response
    char buffer[4096];
    int bytesRead = socketRead(buffer, sizeof(buffer) - 1);
    if (bytesRead <= 0) {
        m_onError("Failed to receive handshake response");
        return false;
    }
    
    buffer[bytesRead] = '\0';
    std::string response(buffer);
    
    // Validate response
    if (response.find("HTTP/1.1 101") != 0) {
        m_onError("Invalid handshake response");
        return false;
    }
    
    // Verify Sec-WebSocket-Accept
    std::string expectedAccept = sha1Hash(key + WEBSOCKET_MAGIC_STRING);
    if (response.find("Sec-WebSocket-Accept: " + expectedAccept) == std::string::npos) {
        m_onError("Invalid Sec-WebSocket-Accept header");
        return false;
    }
    
    return true;
}

void WebSocketClient::startReceiveLoop() {
    m_receiveThread = std::thread(&WebSocketClient::receiveLoop, this);
}

void WebSocketClient::receiveLoop() {
    const size_t BUFFER_SIZE = 4096;
    std::vector<uint8_t> buffer(BUFFER_SIZE);
    
    while (!m_shouldStop && m_connected) {
        int bytesRead = socketRead(buffer.data(), BUFFER_SIZE);
        if (bytesRead <= 0) {
            if (!m_shouldStop) {
                m_onError("Connection lost");
                m_connected = false;
            }
            break;
        }
        
        // Add to receive buffer
        m_receiveBuffer.insert(m_receiveBuffer.end(), buffer.begin(), buffer.begin() + bytesRead);
        
        // Try to parse frames
        while (m_receiveBuffer.size() >= 2) {
            WebSocketFrame frame;
            size_t frameSize = 0;
            
            // Calculate frame size
            uint8_t payloadLenByte = m_receiveBuffer[1] & 0x7F;
            size_t headerSize = 2;
            
            if (payloadLenByte == 126) {
                if (m_receiveBuffer.size() < 4) break;
                headerSize = 4;
                frame.payloadLength = (m_receiveBuffer[2] << 8) | m_receiveBuffer[3];
            } else if (payloadLenByte == 127) {
                if (m_receiveBuffer.size() < 10) break;
                headerSize = 10;
                frame.payloadLength = 0;
                for (int i = 2; i < 10; ++i) {
                    frame.payloadLength = (frame.payloadLength << 8) | m_receiveBuffer[i];
                }
            } else {
                frame.payloadLength = payloadLenByte;
            }
            
            // Check if we have the complete frame
            frameSize = headerSize + frame.payloadLength;
            if (m_receiveBuffer.size() < frameSize) {
                break;
            }
            
            // Parse frame
            frame.fin = (m_receiveBuffer[0] & 0x80) != 0;
            frame.opcode = m_receiveBuffer[0] & 0x0F;
            frame.masked = (m_receiveBuffer[1] & 0x80) != 0;
            
            // Extract payload
            frame.payload.assign(
                m_receiveBuffer.begin() + headerSize,
                m_receiveBuffer.begin() + frameSize
            );
            
            // Remove processed frame from buffer
            m_receiveBuffer.erase(m_receiveBuffer.begin(), m_receiveBuffer.begin() + frameSize);
            
            // Handle frame
            handleFrame(frame);
        }
    }
    
    if (m_onDisconnect) {
        m_onDisconnect();
    }
}

void WebSocketClient::handleFrame(const WebSocketFrame& frame) {
    switch (frame.opcode) {
        case OPCODE_TEXT:
            if (m_onMessage) {
                std::string message(frame.payload.begin(), frame.payload.end());
                m_onMessage(message, false);
            }
            break;
            
        case OPCODE_BINARY:
            if (m_onMessage) {
                std::string message(frame.payload.begin(), frame.payload.end());
                m_onMessage(message, true);
            }
            break;
            
        case OPCODE_CLOSE:
            m_connected = false;
            m_shouldStop = true;
            break;
            
        case OPCODE_PING:
            // Respond with pong
            sendFrame(OPCODE_PONG, frame.payload);
            break;
            
        case OPCODE_PONG:
            // Handle pong if needed
            break;
    }
}

bool WebSocketClient::sendText(const std::string& message) {
    if (!m_connected) return false;
    
    std::vector<uint8_t> payload(message.begin(), message.end());
    return sendFrame(OPCODE_TEXT, payload);
}

bool WebSocketClient::sendBinary(const std::vector<uint8_t>& data) {
    if (!m_connected) return false;
    
    return sendFrame(OPCODE_BINARY, data);
}

bool WebSocketClient::sendFrame(uint8_t opcode, const std::vector<uint8_t>& payload) {
    std::lock_guard<std::mutex> lock(m_sendMutex);
    
    std::vector<uint8_t> frame = createFrame(opcode, payload, true);
    
    int bytesSent = socketWrite(frame.data(), frame.size());
    return bytesSent == static_cast<int>(frame.size());
}

std::vector<uint8_t> WebSocketClient::createFrame(uint8_t opcode, const std::vector<uint8_t>& payload, bool mask) {
    std::vector<uint8_t> frame;
    
    // First byte: FIN (1) + RSV (000) + Opcode (4 bits)
    frame.push_back(0x80 | opcode);
    
    // Payload length
    if (payload.size() < 126) {
        frame.push_back((mask ? 0x80 : 0x00) | static_cast<uint8_t>(payload.size()));
    } else if (payload.size() < 65536) {
        frame.push_back((mask ? 0x80 : 0x00) | 126);
        frame.push_back((payload.size() >> 8) & 0xFF);
        frame.push_back(payload.size() & 0xFF);
    } else {
        frame.push_back((mask ? 0x80 : 0x00) | 127);
        for (int i = 7; i >= 0; --i) {
            frame.push_back((payload.size() >> (i * 8)) & 0xFF);
        }
    }
    
    // Masking key (if client)
    uint32_t maskingKey = 0;
    if (mask) {
        maskingKey = generateMaskingKey();
        frame.push_back((maskingKey >> 24) & 0xFF);
        frame.push_back((maskingKey >> 16) & 0xFF);
        frame.push_back((maskingKey >> 8) & 0xFF);
        frame.push_back(maskingKey & 0xFF);
    }
    
    // Payload
    std::vector<uint8_t> maskedPayload = payload;
    if (mask) {
        applyMask(maskedPayload, maskingKey);
    }
    
    frame.insert(frame.end(), maskedPayload.begin(), maskedPayload.end());
    
    return frame;
}

uint32_t WebSocketClient::generateMaskingKey() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dis;
    return dis(gen);
}

void WebSocketClient::applyMask(std::vector<uint8_t>& data, uint32_t mask) {
    uint8_t maskBytes[4] = {
        static_cast<uint8_t>((mask >> 24) & 0xFF),
        static_cast<uint8_t>((mask >> 16) & 0xFF),
        static_cast<uint8_t>((mask >> 8) & 0xFF),
        static_cast<uint8_t>(mask & 0xFF)
    };
    
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= maskBytes[i % 4];
    }
}

int WebSocketClient::socketRead(void* buffer, int length) {
    if (m_isSecure && m_ssl) {
        return SSL_read(m_ssl, buffer, length);
    } else {
        return recv(m_socket, buffer, length, 0);
    }
}

int WebSocketClient::socketWrite(const void* buffer, int length) {
    if (m_isSecure && m_ssl) {
        return SSL_write(m_ssl, buffer, length);
    } else {
        return send(m_socket, buffer, length, 0);
    }
}

void WebSocketClient::disconnect() {
    if (m_connected) {
        // Send close frame
        std::vector<uint8_t> closePayload;
        sendFrame(OPCODE_CLOSE, closePayload);
    }
    
    m_shouldStop = true;
    m_connected = false;
    
    if (m_receiveThread.joinable()) {
        m_receiveThread.join();
    }
    
    if (m_ssl) {
        SSL_shutdown(m_ssl);
        SSL_free(m_ssl);
        m_ssl = nullptr;
    }
    
    if (m_socket >= 0) {
        close(m_socket);
        m_socket = -1;
    }
    
    m_receiveBuffer.clear();
}

bool WebSocketClient::isConnected() const {
    return m_connected;
}

// Callback setters
void WebSocketClient::setOnMessage(OnMessageCallback callback) {
    m_onMessage = callback;
}

void WebSocketClient::setOnConnect(OnConnectCallback callback) {
    m_onConnect = callback;
}

void WebSocketClient::setOnDisconnect(OnDisconnectCallback callback) {
    m_onDisconnect = callback;
}

void WebSocketClient::setOnError(OnErrorCallback callback) {
    m_onError = callback;
}