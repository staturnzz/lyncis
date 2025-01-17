CC = $(shell xcrun --sdk iphoneos --find clang)
STRIP = $(shell xcrun --sdk iphoneos --find strip)
AR = $(shell xcrun --sdk iphoneos --find ar)
LDID = $(shell which ldid)
MAKE_B64 = $(shell realpath ../resources/make_b64.sh)

SDK = $(shell xcrun --sdk iphoneos --show-sdk-path)
SRC = $(wildcard ./src/*.c) $(wildcard ../exploit/src/*.c) $(wildcard ../common/src/*.c)
LIBS = $(SDK)/usr/lib
DEB_VERSION = 1.0.0

CFLAGS = -isysroot $(SDK) -miphoneos-version-min=7.0 -arch armv7 -DUNTETHER
CFLAGS += -I./include -I../exploit/include -I../common/include
LDFLAGS = -L$(LIBS) -lc -lSystem -framework IOKit

all: $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o lyncis $^
	$(STRIP) lyncis
	$(LDID) -S./resources/ents.xml lyncis

	@mkdir -p ./staging/DEBIAN
	@umask u=rwx,g=rx,o=rx && mkdir -p ./staging/System/Library/Caches/com.apple.dyld
	@umask u=rwx,g=rx,o=rx && mkdir -p ./staging/usr/lib
	@umask u=rwx,g=rx,o=rx && mkdir -p ./staging/private/etc

	@cp -a ./resources/libmis.dylib ./staging/usr/lib/libmis.dylib
	@cp -a ./resources/install.sh ./staging/install.sh
	@cp -a ./lyncis ./staging/lyncis
	@touch ./staging/System/Library/Caches/com.apple.dyld/enable-dylibs-to-override-cache
	@cp -a ./resources/fstab ./staging/private/etc/fstab
	@cp -a ./resources/control ./staging/DEBIAN/control
	@cp -a ./resources/postinst ./staging/DEBIAN/postinst
	@cp -a ./resources/preinst ./staging/DEBIAN/preinst
	@sed -i '' 's/REPLACE_VERSION/$(DEB_VERSION)/g' ./staging/DEBIAN/control

	@chmod 0644 ./staging/private/etc/fstab
	@chmod 0644 ./staging/System/Library/Caches/com.apple.dyld/enable-dylibs-to-override-cache
	@chmod 0755 ./staging/usr/lib/libmis.dylib
	@chmod 0755 ./staging/DEBIAN/preinst
	@chmod 0755 ./staging/DEBIAN/postinst
	@chmod 0777 ./staging/lyncis
	@chmod 0777 ./staging/install.sh

package: clean all
	dpkg-deb -Znone --root-owner-group --build ./staging ./com.staturnz.lyncis.untether_$(DEB_VERSION)_iphoneos-arm.deb
	$(AR) -p ./com.staturnz.lyncis.untether_$(DEB_VERSION)_iphoneos-arm.deb data.tar > lyncis.tar
	$(MAKE_B64) lyncis.tar lyncis.tar.b64
	
clean:
	@rm -rf lyncis
	@rm -rf lyncis.tar
	@rm -rf lyncis.tar.b64
	@rm -rf staging
	@rm -rf *.o
