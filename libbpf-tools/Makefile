# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bin/bpftool
LIBBPF_SRC := $(abspath ../src/cc/libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
INCLUDES := -I$(OUTPUT) -I../src/cc/libbpf/include/uapi
CFLAGS := -g -O2 -Wall
INSTALL ?= install
prefix ?= /usr/local
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

ifeq ($(wildcard $(ARCH)/),)
$(error Architecture $(ARCH) is not supported yet. Please open an issue)
endif

APPS = \
	bashreadline \
	bindsnoop \
	biolatency \
	biopattern \
	biosnoop \
	biostacks \
	bitesize \
	cachestat \
	cpudist \
	cpufreq \
	drsnoop \
	execsnoop \
	exitsnoop \
	filelife \
	filetop \
	fsdist \
	fsslower \
	funclatency \
	gethostlatency \
	hardirqs \
	klockstat \
	ksnoop \
	llcstat \
	mountsnoop \
	numamove \
	offcputime \
	oomkill \
	opensnoop \
	readahead \
	runqlat \
	runqlen \
	runqslower \
	softirqs \
	solisten \
	statsnoop \
	syscount \
	tcpconnect \
	tcpconnlat \
	tcprtt \
	vfsstat \
	#

FSDIST_ALIASES = btrfsdist ext4dist nfsdist xfsdist
FSSLOWER_ALIASES = btrfsslower ext4slower nfsslower xfsslower
APP_ALIASES = $(FSDIST_ALIASES) $(FSSLOWER_ALIASES)

COMMON_OBJ = \
	$(OUTPUT)/trace_helpers.o \
	$(OUTPUT)/syscall_helpers.o \
	$(OUTPUT)/errno_helpers.o \
	$(OUTPUT)/map_helpers.o \
	$(OUTPUT)/uprobe_helpers.o \
	#

ifdef ENABLE_MIN_CORE_BTFS

ifndef BTF_HUB_ARCHIVE
$(error Please set BTF_HUB_ARCHIVE to the folder where btfhub-archive resides)
endif

COMMON_OBJ += $(OUTPUT)/min_core_btf_helpers.o
CFLAGS += -DENABLE_MIN_CORE_BTFS
endif

.PHONY: all
all: $(APPS) $(APP_ALIASES)

ifeq ($(V),1)
Q =
msg =
else
Q = @
msg = @printf '  %-8s %s%s\n' "$(1)" "$(notdir $(2))" "$(if $(3), $(3))";
MAKEFLAGS += --no-print-directory
endif

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS) $(APP_ALIASES)

$(OUTPUT) $(OUTPUT)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) $(COMMON_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(LDFLAGS) -lelf -lz -o $@

$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c $(wildcard %.h) $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(ARCH)/vmlinux.h | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH)	      \
		     -I$(ARCH)/ $(INCLUDES) -c $(filter %.c,$^) -o $@ &&      \
	$(LLVM_STRIP) -g $@

ifdef ENABLE_MIN_CORE_BTFS
$(OUTPUT)/min_core_btf_helpers.o: $(OUTPUT)/min_core_btfs.h

SOURCE_BTF_FILES = $(shell find $(BTF_HUB_ARCHIVE)/ -iregex ".*$(subst x86,x86_64,$(ARCH)).*" -type f -name '*.btf')
MIN_CORE_BTF_FILES = $(patsubst $(BTF_HUB_ARCHIVE)/%.btf, $(OUTPUT)/min_core_btfs/%.btf, $(SOURCE_BTF_FILES))
BPF_O_FILES = $(patsubst %,$(OUTPUT)/%.bpf.o,$(APPS))

$(MIN_CORE_BTF_FILES): $(BPF_O_FILES)

# Create reduced version of BTF files to be embeed within the tools executables
$(OUTPUT)/min_core_btfs/%.btf: $(BTF_HUB_ARCHIVE)/%.btf
	$(call msg,BTFGEN,$@)
	@mkdir -p "$(@D)"
	$(Q)$(BPFTOOL) gen min_core_btf $< $@ $(OUTPUT)/*.bpf.o

# Compress reduced BTF files and create C header with its content
$(OUTPUT)/min_core_btfs.h: $(MIN_CORE_BTF_FILES)
	$(call msg,TAR,$@)
	$(Q)tar c --gz -f $(OUTPUT)/min_core_btfs.tar.gz $(OUTPUT)/min_core_btfs/
	$(Q)xxd -i -g 1 $(OUTPUT)/min_core_btfs.tar.gz > $(OUTPUT)/min_core_btfs.h
endif

# Build libbpf.a
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch]) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

$(FSSLOWER_ALIASES): fsslower
	$(call msg,SYMLINK,$@)
	$(Q)ln -f -s $^ $@

$(FSDIST_ALIASES): fsdist
	$(call msg,SYMLINK,$@)
	$(Q)ln -f -s $^ $@

install: $(APPS) $(APP_ALIASES)
	$(call msg, INSTALL libbpf-tools)
	$(Q)$(INSTALL) -m 0755 -d $(DESTDIR)$(prefix)/bin
	$(Q)$(INSTALL) $(APPS) $(DESTDIR)$(prefix)/bin
	$(Q)cp -a $(APP_ALIASES) $(DESTDIR)$(prefix)/bin

# delete failed targets
.DELETE_ON_ERROR:
# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
