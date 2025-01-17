CC = $(shell xcrun --sdk iphoneos --find clang)
MAKE_BIN = $(shell realpath ../resources/make_bin.sh)
MAKE_B64 = $(shell realpath ../resources/make_b64.sh)

CFLAGS = -arch armv7 -miphoneos-version-min=7.0

all: $(SRC)
	$(CC) $(CFLAGS) -c ./src/main.s -o loader.o
	$(MAKE_BIN) loader.o loader.bin
	$(MAKE_B64) loader.bin loader.b64

clean:
	@rm -rf loader.o
	@rm -rf loader.bin
	@rm -rf loader.b64
	@rm -rf *.o


