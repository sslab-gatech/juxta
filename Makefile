LINX := linux-3.17
CONF := config/config-x86_64-full-fs-4.0
NJOB := ${shell nproc}
ARGS := 

LLVM_SRC  := $(PWD)/llvm
LLVM_DIR  := $(PWD)/bin/llvm
CLANG_BIN := $(LLVM_DIR)/bin/clang
CLANG_TOOL_DIR  := $(LLVM_SRC)/tools/clang/tools
CLANG_MAKE_ARGS := --no-print-directory -j${NJOB}

FSCK_BUILD   = $(CLANG_TOOL_DIR)/scan-build/fss-build
CHECKER_FLAG = --use-analyzer=$(CLANG_BIN)
PATH := ${LLVM_DIR}/bin:${PATH}

MERGER_BUILD = $(PWD)/merger

# build type
CLANG_BUILD_TYPE := Release
ifeq ("$(origin BUILD)", "command line")
  CLANG_BUILD_TYPE = $(BUILD}
endif

# run static fsck
RUN_CHECKER = $(FSCK)
ifeq ($(RUN_CHECKER),2)
  FSSB = CCC_CC=${CLANG_BIN} CLANG=${CLANG_BIN} $(FSCK_BUILD) $(CHECKER_FLAG) -html -V
  V_LVL = > /dev/null 2>&1
else ifeq ($(RUN_CHECKER),1)
  FSS_OUTPUT_DIR := $(shell mktemp -d /tmp/fss-output-XXXX)
  FSSB = CCC_CC=${CLANG_BIN} CLANG=${CLANG_BIN} $(FSCK_BUILD) $(CHECKER_FLAG) --fss-output-dir=$(FSS_OUTPUT_DIR)
  V_LVL = > /dev/null 2>&1
endif

ifeq ($(V),1)
  V_LVL =
endif 

all: ${LINX}/.config ${CLANG_BIN}
	@echo "FSS_OUTPUT_DIR : $(FSS_OUTPUT_DIR)"
	(cd ${LINX}; ${FSSB} make HOSTCC=${CLANG_BIN} CC=${CLANG_BIN} -j${NJOB} ${ARGS} ${V_LVL})

fs: ${LINX}/.config ${CLANG_BIN}
	@echo "FSS_OUTPUT_DIR : $(FSS_OUTPUT_DIR)"
	(cd ${LINX}; ${FSSB} make HOSTCC=${CLANG_BIN} CC=${CLANG_BIN} -j${NJOB} fs ${ARGS} ${V_LVL})

${LINX}/.config: ${CONF}
	cp -f $< $@

# incremental build short-cuts for clang
clang:
	(cd ${LLVM_DIR} && make ${CLANG_MAKE_ARGS})

clang-full:
	@mkdir -p ${LLVM_DIR}
	(cd ${LLVM_DIR} \
	  && cmake ${LLVM_SRC} -DLLVM_TARGETS_TO_BUILD=X86 -DCMAKE_BUILD_TYPE=${CLANG_BUILD_TYPE} \
	  && make ${CLANG_MAKE_ARGS})
	${CLANG_BIN} -v

${CLANG_BIN}:
	@mkdir -p ${LLVM_DIR}
	(cd ${LLVM_DIR} \
	  && cmake ${LLVM_SRC} -DLLVM_TARGETS_TO_BUILD=X86 -DCMAKE_BUILD_TYPE=${CLANG_BUILD_TYPE} \
	  && make ${CLANG_MAKE_ARGS})
	${CLANG_BIN} -v

z3:
	@echo "XXX. sudo .."
	(cd analyzer/z3 \
	  && python scripts/mk_make.py \
	  && cd build \
	  && make -j${NJOB} \
	  && sudo make install)

merge-fs-all:
	(cd merger \
	  && ./populate.sh ../${LINX})

merge-fs:
	(cd ${MERGER_BUILD} \
	  && ./merger.py -l ../${LINX} ${FS})

build-merge-fs: ${LINX}/.config ${CLANG_BIN}
	(cd ${MERGER_BUILD}/out/${FS}; ${FSSB} make CC=${CLANG_BIN} -j${NJOB} -f Makefile.build ${V_LVL})

help:
	@cat README

.PHONY: all qemu help clang z3 merge-fs-all merge-fs
