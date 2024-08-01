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
LDLIBS = -lcrypto -lm -lwolfssl -pthread

# ------------ Generic building

build: $(OBJECTS)

all: $(OUT) $(TEST) $(VERIFY) $(KEYMIXER)

$(LIBRARY): CFLAGS += -fPIC
$(LIBRARY): $(OBJECTS)
	@ gcc -shared -o $(LIBRARY) $(OBJECTS)

wolfssl:
ifeq ($(shell which makepkg &> /dev/null && echo "yes" || echo "no"), yes)
	@ cd deps/wolfssl-ecb && makepkg -sfi
else
	@ cd deps/wolfssl-ecb && ./install.sh
endif

# ------------ main.c for quick tests

$(OUT): main.o $(OBJECTS)
run: $(OUT)
	@ ./$(OUT)

# ------------ Testing

$(TEST): test.o $(OBJECTS)

exp-test: CFLAGS += -DDO_KEYMIX_TESTS
exp-test: clean | $(TEST)

enc-test: CFLAGS += -DDO_ENCRYPTION_TESTS
enc-test: clean | $(TEST)

all-test: CFLAGS += -DDO_KEYMIX_TESTS
all-test: CFLAGS += -DDO_ENCRYPTION_TESTS
all-test: clean | $(TEST)

run-test:
	@ ./$(TEST) data/out.csv data/enc.csv 2> log & disown
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
