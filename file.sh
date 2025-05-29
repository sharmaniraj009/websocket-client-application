#!/bin/bash

set -e

echo "[+] Setting up GN build environment..."

# Step 1: Clean and create necessary directories
rm -rf .gn build toolchain out
mkdir -p build/config toolchain

# Step 2: Create .gn
cat <<EOF > .gn
buildconfig = "//build/config/BUILDCONFIG.gn"
EOF

# Step 3: Create build/config/BUILDCONFIG.gn
cat <<EOF > build/config/BUILDCONFIG.gn
set_default_toolchain("//toolchain:gcc")
EOF

# Step 4: Create toolchain/BUILD.gn
cat <<EOF > toolchain/BUILD.gn
toolchain("gcc") {
  tool("cc") {
    command = "g++ -c \$in -o \$out"
    description = "CC \$in"
    outputs = [ "\$out" ]
  }

  tool("cxx") {
    command = "g++ -c \$in -o \$out"
    description = "CXX \$in"
    outputs = [ "\$out" ]
  }

  tool("link") {
    command = "g++ -o \$out \$in -lssl -lcrypto -lpthread"
    description = "LINK \$out"
    outputs = [ "\$out" ]
  }

  tool("stamp") {
    command = "touch \$out"
    description = "STAMP \$out"
    outputs = [ "\$out" ]
  }
}
EOF

# Step 5: Create main BUILD.gn
cat <<EOF > BUILD.gn
executable("websocket_client") {
  sources = [
    "main.cpp",
    "websocket_client.cpp",
  ]

  include_dirs = [ "." ]
  cflags = [ "-std=c++17" ]
}
EOF

# Step 6: Generate and build
echo "[+] Generating build files with GN..."
gn gen out

echo "[+] Building with Ninja..."
ninja -C out

echo "[✔] Build complete! Run it with: ./out/websocket_client"
