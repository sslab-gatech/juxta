BEFORE_FLAG =
FS_SEMANTIC_CFG = $(CUR_DIR)/fss.cfg
FS_SEMANTIC_OUT_DIR = $(CUR_DIR)
FS_SEMANTIC_FLAG = $(BEFORE_FLAG) -ffs-semantic=$(FS_SEMANTIC_CFG) -ffs-semantic-out-dir=$(FS_SEMANTIC_OUT_DIR)
FS_SEMANTIC_DEBUG_FLAG = $(FS_SEMANTIC_FLAG) -mllvm -fs-semantic-verbose

all : before.out after.out

before.out: $(SRCS)
	$(Q)$(CC) $(BEFORE_FLAG) $^ -o $@

after.out: $(SRCS)
	$(Q)$(CC) $(BEFORE_FLAG) -D__PATCH__ $^ -o $@

clean:
	$(Q)rm -rf *.out rm *.ll $(FS_SEMANTIC_OUT_DIR)/*.fss
