# common tool config
LEVEL = .
CUR_DIR = $(realpath $(LEVEL))
NJOB := ${shell nproc}

LLVM_BIN_DIR   = $(CUR_DIR)/../bin/llvm/bin
LLVM_LIB_DIR   = $(CUR_DIR)/../bin/llvm/lib
CLANG_TOOL_DIR = $(CUR_DIR)/../llvm/tools/clang/tools

CC    = $(LLVM_BIN_DIR)/clang
CPP   = $(LLVM_BIN_DIR)/clang++

FSCK_BUILD   = $(CLANG_TOOL_DIR)/scan-build/fss-build
CHECKER_FLAG = --use-analyzer=$(LLVM_BIN_DIR)/clang

OUTPUT_DIR = output

# verbose flag
BUILD_VERBOSE = $(V)
ifeq ($(BUILD_VERBOSE),1)
  Q =
else
  Q = @
endif
export Q

# checker flag
FSSB = CCC_CC=${CC} CLANG=${CC} $(FSCK_BUILD) $(CHECKER_FLAG)
V_LVL = > /dev/null 2>&1

ifeq ($(V),1)
  V_LVL =
endif 

# target dirs
UNIT_DIRS = 1 2 3 4 5 6 ipa logs lock
FS_REPRO_DIRS = rename simplified-rename set-xattr fitrim-ioctl get-parent deadlock write-begin

all: fs unit

# XXX. before_$$d -> $$d_before
# XXX. should be able to specify single target
unit:
	$(Q)for d in $(UNIT_DIRS); \
		do ( echo; \
			echo '==================================================='; \
			echo '[*] BUILDING '$$d; \
			cd $$d; \
			$(MAKE) clean; \
			$(FSSB) --fss-output-dir=$(CUR_DIR)/$(OUTPUT_DIR)/before_$$d $(MAKE) before.out ${V_LVL};\
			$(MAKE) clean; \
			$(FSSB) --fss-output-dir=$(CUR_DIR)/$(OUTPUT_DIR)/after_$$d $(MAKE) after.out ${V_LVL};\
		); \
	done

fs:
	$(Q)for d in $(FS_REPRO_DIRS); \
		do ( echo; \
			echo '==================================================='; \
			echo '[*] BUILDING '$$d; \
			cd $$d; \
			$(MAKE) clean; \
			$(FSSB) --fss-output-dir=$(CUR_DIR)/$(OUTPUT_DIR)/before_$$d $(MAKE) before.out ${V_LVL};\
			$(MAKE) clean; \
			$(FSSB) --fss-output-dir=$(CUR_DIR)/$(OUTPUT_DIR)/after_$$d $(MAKE) after.out ${V_LVL};\
		); \
	done

clean:
	rm -rf $(OUTPUT_DIR)
	$(Q)for d in $(UNIT_DIRS) $(FS_REPRO_DIRS); \
		do ( echo '[*] CLEAN '$$d; \
			cd $$d; \
			$(MAKE) clean \
		); \
	done


.PHONY: all clean unit fs
