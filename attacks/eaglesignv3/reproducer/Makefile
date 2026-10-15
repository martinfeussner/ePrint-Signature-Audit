CXX ?= g++
CXXFLAGS ?= -std=c++20 -O3 -DNDEBUG -Wall -Wextra -Wpedantic
LDLIBS ?= -lcrypto

SOURCES := selftest keygen oracle recover verify compare_ground_truth
BINARIES := $(addprefix build/bin/,$(SOURCES))

.PHONY: all build smoke full clean

all: build

build: $(BINARIES)

build/bin/%: src/%.cpp src/public_scheme.hpp src/secret_scheme.hpp
	mkdir -p build/bin
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDLIBS)

smoke: build/bin/selftest
	./reproduce.sh --smoke

full: build
	./reproduce.sh --full

clean:
	rm -rf build output

