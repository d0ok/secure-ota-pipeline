VERSION ?= 1.0.0
BUILD   ?= local
OUT     ?= ../build

all: $(OUT)/firmware.bin

$(OUT)/firmware.bin: main.c
	mkdir -p $(OUT)
	$(CC) -Wall -Wextra -O2 -DFW_VERSION='"$(VERSION)"' -DFW_BUILD='"$(BUILD)"' -o $@ main.c

clean:
	rm -rf $(OUT)

.PHONY: all clean
