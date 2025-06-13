[![C/C++ CI](https://github.com/sharmaniraj009/websocket-client-application/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/sharmaniraj009/websocket-client-application/actions/workflows/c-cpp.yml)


# WebSocket Client Application

A low-level WebSocket client implementation in C++ using raw Berkeley sockets and OpenSSL. This application connects securely to a WebSocket server over `wss://`, sends and receives messages, and handles framing, masking, and TLS encryption manually — without using any high-level WebSocket libraries.

## 🔧 Features

* Connects to WebSocket servers over secure TLS (wss)
* Manual handshake construction with proper headers
* Frame encoding and decoding (FIN, opcode, masking, payload length, etc.)
* SHA1 and Base64 used for generating `Sec-WebSocket-Accept`
* Clean separation of socket logic and WebSocket protocol handling
* SSL/TLS support using OpenSSL

## 📁 Project Structure

```
.
├── main.cpp
├── websocket_client.cpp
├── test_websocket_client.cpp
├── websocket_client.h
├── BUILD.gn
├── BUILDCONFIG.gn
├── build/
    ├── BUILD.gn

```

## 🚀 Getting Started

### Prerequisites

* C++17 compatible compiler
* OpenSSL development libraries
* CMake (>= 3.10)

### Building the Application

```bash
git clone https://github.com/sharmaniraj009/websocket-client-application.git
cd websocket-client-application
mkdir build && cd build
gn gen out
ninja -C out/test websocket_tests

```

### Running

```bash
./websocket-client.exe
```



---

## 🧠 Learnings & Purpose

This project was built to **understand and implement the WebSocket protocol from scratch** — especially the low-level intricacies of:

* TLS handshake and encryption (OpenSSL)
* WebSocket frame structure
* Client-side handshake logic
* Masking and unmasking data payloads

It serves as an educational tool for anyone looking to deeply understand how WebSockets work under the hood.

---

## 📜 References

* [RFC 6455 - The WebSocket Protocol](https://datatracker.ietf.org/doc/html/rfc6455)
* [OpenSSL Documentation](https://www.openssl.org/docs/)
* [Berkeley Sockets](https://beej.us/guide/bgnet/)

---



## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

