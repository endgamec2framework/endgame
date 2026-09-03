CC    = x86_64-w64-mingw32-gcc
CFLAGS = -O2 -s -Wall -Wno-unused-variable
LDFLAGS = -shared -lgdi32 -luser32 -lkernel32 -mwindows

OUT_DIR = ../../bin

ASSETS_DIR = ../agent-go/assets

all: $(OUT_DIR)/vnc_dll_x64.dll

$(OUT_DIR)/vnc_dll_x64.dll: vnc_dll.c
	@mkdir -p $(OUT_DIR)
	@mkdir -p $(ASSETS_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	cp $@ $(ASSETS_DIR)/vnc_dll_x64.dll
	@echo "[+] Built $@"

clean:
	rm -f $(OUT_DIR)/vnc_dll_x64.dll

.PHONY: all clean
