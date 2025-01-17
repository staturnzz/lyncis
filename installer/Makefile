CC = $(shell xcrun --sdk iphoneos --find clang)
STRIP = $(shell xcrun --sdk iphoneos --find strip)
LDID = $(shell which ldid)
MAKE_B64 = $(shell realpath ../resources/make_b64.sh)

SDK = $(shell xcrun --sdk iphoneos --show-sdk-path)
SRC = $(wildcard ./src/*.m) $(wildcard ./src/*.s) $(wildcard ../exploit/src/*.c) $(wildcard ../common/src/*.c)
LIBS = $(SDK)/usr/lib

CFLAGS = -isysroot $(SDK) -miphoneos-version-min=7.0 -arch armv7 -Wno-deprecated-declarations
CFLAGS +=  -fno-objc-arc -I./include -I../exploit/include -I../common/include 
LDFLAGS = -L$(LIBS) -framework IOKit -framework Foundation -framework CoreFoundation

all: $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o installer $^
	$(STRIP) installer
	$(LDID) -S installer
	$(MAKE_B64) installer installer.b64

clean:
	@rm -rf installer
	@rm -rf installer.b64
	@rm -rf *.o
