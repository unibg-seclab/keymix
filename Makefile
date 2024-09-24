.PHONY: doc run-test

SOURCES = $(wildcard src/*.c)
OBJECTS = $(SOURCES:%.c=%.o)

FLAMEGRAPH_DIR = $(file < .FlameGraphDir)

OUT = main
TEST = test
VERIFY = verify
PERFDATA = perf.data
KEYMIXER = keymixer
LIBRARY = libkeymix.so

RESOURCE = resource.txt
ENC_RESOURCE = resource.txt.enc
SECRET = secret

# ------------ Compiler flags

CC = gcc
CFLAGS = -O3 -msse2 -msse -march=native -maes -Wno-cpp -Iinclude -Isrc
LDLIBS = -lblake3 -lcrypto -lXKCP -lm -lwolfssl -pthread

# ------------ Generic building

build: CFLAGS += $(if $(SIZE_MACRO),-DSIZE_MACRO=$(SIZE_MACRO),)
build: $(OBJECTS)

all: $(OUT) $(TEST) $(VERIFY) $(KEYMIXER)

$(LIBRARY): CFLAGS += -fPIC
$(LIBRARY): $(OBJECTS)
	@ gcc -shared -o $(LIBRARY) $(OBJECTS)

blake3:
	@ echo "[*] Look into https://github.com/BLAKE3-team/BLAKE3/tree/master/c for the best compilation for your cpu architecture"
	@ cd deps/BLAKE3/c && \
	  gcc -shared -O3 -o libblake3.so blake3.c blake3_dispatch.c blake3_portable.c \
      	  blake3_sse2_x86-64_unix.S blake3_sse41_x86-64_unix.S blake3_avx2_x86-64_unix.S \
      	  blake3_avx512_x86-64_unix.S
	@ echo "[*] Installing BLAKE3 library in /usr/local/lib ..."
	sudo mkdir -p /usr/local/include/blake3
	sudo cp -r deps/BLAKE3/c/blake3.h /usr/local/include/blake3/blake3.h
	sudo chown root:root deps/BLAKE3/c/libblake3.so
	sudo mv deps/BLAKE3/c/libblake3.so /usr/local/lib/libblake3.so
	@ echo "[*] Updating shared library cache ..."
	sudo ldconfig

wolfssl:
ifneq ($(shell which makepkg &> /dev/null),)
	@ cd deps/wolfssl-ecb && makepkg -sfi
else
	@ cd deps/wolfssl-ecb && ./install.sh
endif

XKCP_TARGET = AVX2

xkcp:
ifneq ($(shell which makepkg &> /dev/null),)
	@ cd deps/xkcp && makepkg -sfi
else
	@ echo "[*] Look into https://github.com/XKCP/XKCP for the best compilation target for your cpu architecture (default: AVX2)"
	@ cd deps/XKCP && git submodule update --init && make $(XKCP_TARGET)/libXKCP.so
	@ echo "[*] Installing XKCP library in /usr/local/lib ..."
	sudo mkdir -p /usr/local/include/xkcp
	sudo cp -r deps/XKCP/bin/$(XKCP_TARGET)/libXKCP.so.headers/* /usr/local/include/xkcp
	sudo cp deps/XKCP/bin/$(XKCP_TARGET)/libXKCP.so /usr/local/lib/libXKCP.so
	@ echo "[*] Updating shared library cache ..."
	sudo ldconfig
endif

# ------------ main.c for quick tests

$(OUT): CFLAGS += $(if $(SIZE_MACRO),-DSIZE_MACRO=$(SIZE_MACRO),)
$(OUT): main.o $(OBJECTS)
run: CFLAGS += $(if $(SIZE_MACRO),-DSIZE_MACRO=$(SIZE_MACRO),)
run: $(OUT)
	@ ./$(OUT)

# ------------ Testing

$(TEST): test.o $(OBJECTS)

keymix-test: CFLAGS += -DDO_KEYMIX_TESTS
keymix-test: clean | $(TEST)

enc-test: CFLAGS += -DDO_ENCRYPTION_TESTS
enc-test: clean | $(TEST)

all-test: CFLAGS += -DDO_KEYMIX_TESTS
all-test: CFLAGS += -DDO_ENCRYPTION_TESTS
all-test: clean | $(TEST)

run-test:
	@ ./$(TEST) 2> log & disown
	@ echo "Started"

# ------------ Verifying

$(VERIFY): verify.o $(OBJECTS)

# ------------ Keymixer

$(KEYMIXER): keymixer.o $(OBJECTS)
cli: $(KEYMIXER)

# ------------ Documentation

doc: $(KEYMIXER)
	@ (which help2man &> /dev/null) || (echo "You need to install help2man for this"; exit 1)
	@ help2man --no-info --no-discard-stderr './keymixer' > doc/keymixer

# ------------ Cleaning

clean:
	@ rm -rf $(OBJECTS)
	@ rm -rf *.o
	@ rm -rf $(OUT) $(TEST) $(VERIFY) $(KEYMIXER)
	@ rm -rf $(LIBRARY)

clean_resources:
	@ rm -f $(RESOURCE) $(SECRET) $(ENC_RESOURCE)

# ------------ Performance and flamegraph

perf: $(OUT)
	@ sudo perf record --call-graph dwarf ./$(OUT)

perf-report: $(PERFDATA)
	@ sudo perf report

perf-flame: $(PERFDATA)
	@ echo $(FLAMEGRAPH_DIR)
	@ sudo cp perf.data $(FLAMEGRAPH_DIR)/
	@ cd $(FLAMEGRAPH_DIR); pwd; sudo perf script | ./stackcollapse-perf.pl |./flamegraph.pl > perf.svg
	@ google-chrome --incognito $(FLAMEGRAPH_DIR)/perf.svg

# ------------ Graphs

graph.%:
	@ python graphs/$*.py

# ------------ Resources

$(RESOURCE):
#	create a 1GB resource for test
#	@dd if=/dev/zero of=$@ bs=648 count=1
#	@dd if=/dev/zero of=$@ bs=72 count=363893
	@dd if=/dev/zero of=$@ bs=97 count=1594323
#	@dd if=/dev/zero of=$@ bs=48 count=129140163
$(SECRET):
#	create a 1GB resource for test
#	@dd if=/dev/zero of=$@ bs=432 count=1
	@dd if=/dev/zero of=$@ bs=48 count=729
#	@dd if=/dev/zero of=$@ bs=48 count=1594323
#	@dd if=/dev/zero of=$@ bs=48 count=129140163
