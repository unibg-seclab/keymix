SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:%.c=%.o)

FLAMEGRAPH_DIR = $(file < .FlameGraphDir)

KEYMIX = keymix

CC = gcc
CFLAGS = -O3
LDLIBS = -lcrypto -lm -lwolfssl

$(OUT): $(OBJECTS)
build: $(OBJECTS)

PERFDATA = perf.data

%.c: %.h

k: $(KEYMIX)
	@ ./$(KEYMIX)

clean:
	@ rm -rf $(OUT) $(CBC) $(KEYS) $(MIX) $(WOLF)

perf: $(KEYMIX)
	@ sudo perf record --call-graph dwarf ./$(KEYMIX)

perf-report: $(PERFDATA)
	@ sudo perf report

perf-flame: $(PERFDATA)
	@ echo $(FLAMEGRAPH_DIR)
	@ sudo cp perf.data $(FLAMEGRAPH_DIR)/
	@ cd $(FLAMEGRAPH_DIR); pwd; sudo perf script | ./stackcollapse-perf.pl |./flamegraph.pl > perf.svg
	@ google-chrome --incognito $(FLAMEGRAPH_DIR)/perf.svg
