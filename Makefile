SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:%.c=%.o)

FLAMEGRAPH_DIR = $(file < .FlameGraphDir)

KEYMIX = main

CC = gcc
CFLAGS = -O3 -msse2 -msse -march=native -maes -Wno-cpp
LDLIBS = -lcrypto -lm -lwolfssl -pthread

$(KEYMIX): $(OBJECTS)
build: $(OBJECTS)

PERFDATA = perf.data

%.c: %.h

k: $(KEYMIX)
	@ ./$(KEYMIX)

clean:
	@ rm -rf $(OBJECTS)
	@ rm -rf $(KEYMIX)

perf: $(KEYMIX)
	@ sudo perf record --call-graph dwarf ./$(KEYMIX)

perf-report: $(PERFDATA)
	@ sudo perf report

perf-flame: $(PERFDATA)
	@ echo $(FLAMEGRAPH_DIR)
	@ sudo cp perf.data $(FLAMEGRAPH_DIR)/
	@ cd $(FLAMEGRAPH_DIR); pwd; sudo perf script | ./stackcollapse-perf.pl |./flamegraph.pl > perf.svg
	@ google-chrome --incognito $(FLAMEGRAPH_DIR)/perf.svg

wolfssl:
ifeq ($(shell which makepkg), /usr/bin/makepkg)
	@ cd pkgs/wolfssl-ecb && makepkg -sfi
else
	@ cd pkgs/wolfssl-ecb && ./install.sh
endif
