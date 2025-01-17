MAKE_B64 = $(shell realpath ./common/resources/make_b64.sh)

all:
	@rm -rf ./output
	mkdir output

	$(MAKE) -C loader clean
	$(MAKE) -C loader all
	@cp -a ./loader/loader.bin ./output/loader.bin
	@cp -a ./loader/loader.b64 ./output/loader.b64

	$(MAKE) -C untether clean
	$(MAKE) -C untether package
	@cp -a ./untether/lyncis.tar ./output/lyncis.tar
	@cp -a ./untether/lyncis.tar.b64 ./output/lyncis.tar.b64

	$(MAKE) -C installer clean
	$(MAKE) -C installer all
	@cp -a ./installer/installer ./output/installer
	@cp -a ./installer/installer.b64 ./output/installer.b64


clean:
	$(MAKE) -C installer clean
	$(MAKE) -C loader clean
	$(MAKE) -C untether clean
	@rm -rf output
