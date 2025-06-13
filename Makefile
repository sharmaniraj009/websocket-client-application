CXX = g++
CXXFLAGS = -std=c++17
LDFLAGS = -lssl -lcrypto -lpthread

SRC = main.cpp websocket_client.cpp
OUT = websocket_client

all: $(OUT)

$(OUT): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(OUT) $(LDFLAGS)

clean:
	rm -f $(OUT)
