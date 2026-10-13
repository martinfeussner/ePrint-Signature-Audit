CC ?= cc

CPPFLAGS := -DGLP_N=1024 -Ivendor/glyph -Isrc -Icompat \
	-include compat/openssl_aes_ctr_compat.h
COMMON_CFLAGS := -O2 -std=gnu11 -ffunction-sections -fdata-sections \
	-Wall -Wextra -Wpedantic -Wno-deprecated-declarations
LOCAL_CFLAGS := $(COMMON_CFLAGS) -Werror -Wconversion -Wshadow
UPSTREAM_CFLAGS := $(COMMON_CFLAGS) -Wno-shift-negative-value
LDFLAGS := -Wl,--gc-sections
LDLIBS := -lcrypto -lm

TARGET := build/glyph-reproducer
OBJECTS := \
	build/reproducer.o \
	build/public_forge.o \
	build/openssl_aes_ctr_compat.o \
	build/glp.o \
	build/glp_utils.o \
	build/glp_rand.o \
	build/glp_rand_openssl_aes.o \
	build/FFT_1024_59393.o

.PHONY: all clean verify-pins

all: $(TARGET)

verify-pins:
	sha256sum -c UPSTREAM-SOURCES.sha256

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS) $(LDLIBS)

build/reproducer.o: src/reproducer.c src/public_forge.h | build
	$(CC) $(CPPFLAGS) $(LOCAL_CFLAGS) -c -o $@ $<

build/public_forge.o: src/public_forge.c src/public_forge.h | build
	$(CC) $(CPPFLAGS) $(LOCAL_CFLAGS) -c -o $@ $<

build/openssl_aes_ctr_compat.o: compat/openssl_aes_ctr_compat.c \
	compat/openssl_aes_ctr_compat.h | build
	$(CC) $(CPPFLAGS) $(LOCAL_CFLAGS) -c -o $@ $<

build/glp.o: vendor/glyph/glp.c | build
	$(CC) $(CPPFLAGS) $(UPSTREAM_CFLAGS) -c -o $@ $<

build/glp_utils.o: vendor/glyph/glp_utils.c | build
	$(CC) $(CPPFLAGS) $(UPSTREAM_CFLAGS) -c -o $@ $<

build/glp_rand.o: vendor/glyph/glp_rand.c | build
	$(CC) $(CPPFLAGS) $(UPSTREAM_CFLAGS) -c -o $@ $<

build/glp_rand_openssl_aes.o: vendor/glyph/glp_rand_openssl_aes.c | build
	$(CC) $(CPPFLAGS) $(UPSTREAM_CFLAGS) -c -o $@ $<

build/FFT_1024_59393.o: vendor/glyph/FFT/FFT_1024_59393.c | build
	$(CC) $(CPPFLAGS) $(UPSTREAM_CFLAGS) -c -o $@ $<

build:
	mkdir -p build

clean:
	rm -rf build
