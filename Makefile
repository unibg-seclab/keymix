SOURCES = $(wildcard src/*.c)
OBJECTS = $(SOURCES:%.c=%.o)

FLAMEGRAPH_DIR = $(file < .FlameGraphDir)

OUT = main
TEST = test
VERIFY = verify
PERFDATA = perf.data
KEYMIXER = keymixer

RESOURCE = resource.txt
ENC_RESOURCE = resource.txt.enc
SECRET = secret

# ------------ Compiler flags

CC = gcc
CFLAGS = -O3 -msse2 -msse -march=native -maes -Wno-cpp -Iinclude
LDLIBS = -lcrypto -lm -lwolfssl -pthread

# ------------ Generic building

build: $(OBJECTS)

%.c: %.h

wolfssl:
ifeq ($(shell which makepkg 2> /dev/null), /usr/bin/makepkg)
	@ cd pkgs/wolfssl-ecb && makepkg -sfi
else
	@ cd pkgs/wolfssl-ecb && ./install.sh
endif

# ------------ main.c for quick tests

$(OUT): main.o $(OBJECTS)
run: $(OUT)
	@ ./$(OUT)

# ------------ Testing

$(TEST): test.o $(OBJECTS)
run-test: $(TEST)
	@ ./$(TEST) data/out.csv data/enc.csv

daemon: $(TEST)
	@ ./$(TEST) data/out.csv data/enc.csv 2> log & disown

# ------------ Verifying

$(VERIFY): verify.o $(OBJECTS)

# ------------ Keymixer

$(KEYMIXER): keymixer.o $(OBJECTS)

# ------------ Cleaning

clean:
	@ rm -rf $(OBJECTS)
	@ rm -rf $(OUT).o $(TEST).o $(KEYMIXER).o
	@ rm -rf $(OUT) $(TEST) $(KEYMIXER)

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
#	@dd if=/dev/zero of=$@ bs=48 count=1594323
	@dd if=/dev/zero of=$@ bs=48 count=129140163
$(SECRET):
#	create a 1GB resource for test
#	@dd if=/dev/zero of=$@ bs=432 count=1
#	@dd if=/dev/zero of=$@ bs=48 count=1594323
	@dd if=/dev/zero of=$@ bs=48 count=129140163
