GIT_HASH ?= $(shell git --no-pager log --format="%h" -n 1) # get the git hash for image tag
PROJECT  := malloc
IMAGE := $(PROJECT):$(GIT_HASH)
UNAME_S := $(shell uname -s)
CC       ?= gcc
CSTD     ?= -std=c17
WARN     := -Wall -Wextra -Werror -Wpedantic
DBG      := -O0 -g
# Do NOT use AddressSanitizer when you override malloc/free globally.
SAN      := -fsanitize=undefined     # no ASan when overriding malloc

TESTING := -DTESTING
ENABLE_LOG := -DENABLE_LOG 

ifeq ($(UNAME_S),Darwin)
	SBRK_EXPECTATION := -DSHOW_SBRK_RELEASE_FAIL
else
	SBRK_EXPECTATION := -DSHOW_SBRK_RELEASE_SUCCEEDS 
endif

EXPECT_RELEASE := -DEXPECT_RELEASE

TRACK_RET_ADDR := -DTRACK_RET_ADDR

INTERPOSE := -DINTERPOSE
INTERPOSE_LOG := -DINTERPOSE_LOG

# VERBOSE ?= $(TRACK_RET_ADDR) $(ENABLE_LOG)
VERBOSE ?= $(ENABLE_LOG)

TEST_DEFS  := $(TESTING) $(VERBOSE) $(SBRK_EXPECTATION) -DENABLE_MM_SBRK   # turn on test-only asserts/hooks 

# `-fno-builtin` prevents gcc from assuming builtin malloc/free semantics.
INCLUDE_INTERNAL := -Isrc # only for when building lib/tests
INCLUDE_PUBLIC   := -Iinclude

# common compile flags 
ARFLAGS  := rcs
LDLIBS := -lm

# --- layout ---
SRC_DIR  := src
TEST_DIR := tests
BLD_DIR  := build
OBJ_DIR  := $(BLD_DIR)/obj
TST_DIR  := $(BLD_DIR)/tests

ifeq ($(UNAME_S),Darwin)
	# On macOS, use libtool to produce a static archive compatible with ld64
	MAKE_STATIC_LIB = libtool -static -o
	NEED_RANLIB     = 0
	INTERPOSE_SRC := $(SRC_DIR)/interpose.c
	INTERPOSE_DYLIB := $(BLD_DIR)/libmalloc_interpose.dylib
	TEST_DEFS += $(INTERPOSE)
	ifneq ($(VERBOSE),)
		TEST_DEFS += $(INTERPOSE_LOG)
	endif
else
	AR ?= ar 
	MAKE_STATIC_LIB = $(AR) $(ARFLAGS)
	NEED_RANLIB     = 1
endif

CFLAGS   := $(CSTD) $(WARN) $(DBG) $(SAN) -fno-builtin $(TEST_DEFS) $(INCLUDE_PUBLIC) $(INCLUDE_INTERNAL)

# --- sources ---
# filter-out interpose.c, it will only be compiled and linked in Darwin
SRCS     := $(filter-out $(SRC_DIR)/interpose.c,$(wildcard $(SRC_DIR)/*.c))
OBJS     := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))
LIB      := $(BLD_DIR)/lib$(strip $(PROJECT)).a

# All test .c files become executables of the same basename in build/tests
TEST_SOURCES := $(filter-out $(TEST_DIR)/acutest.h,$(wildcard $(TEST_DIR)/*.c))
TESTS    := $(patsubst $(TEST_DIR)/%.c,$(TST_DIR)/%,$(TEST_SOURCES))

.PHONY: all clean test dirs test-container investigation-container

all: dirs $(LIB) $(TESTS)

# --- objects ---
# Build object files from sources in src/
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# --- library ---
$(LIB): $(OBJS)
	$(MAKE_STATIC_LIB) $@ $(OBJS)
ifneq ($(NEED_RANLIB),0)
	@ranlib $@
endif

# Compile test source to object in build/tests
$(TST_DIR)/%.o: $(TEST_DIR)/%.c | $(TST_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Link test object with our library (library last is conventional)
$(TST_DIR)/%: $(TST_DIR)/%.o $(LIB)
	$(CC) $(CFLAGS) $< $(LIB) $(LDLIBS) -o $@

test: all
	@for t in $(TESTS); do echo "==> $$t"; "$$t" || exit 1; done
	@echo "All tests passed."

# ---- interposing ----
ifeq ($(UNAME_S),Darwin)
.PHONY: test-interpose

$(INTERPOSE_DYLIB): $(INTERPOSE_SRC) | $(BLD_DIR)
 # the real targets that interposition calls are implemented by malloc.c
 # and we want interposing dylib to be able find it in runtime thus the 
 # -undefined dynamic_lookup  
	$(CC) -dynamiclib $(INCLUDE_INTERNAL) -undefined dynamic_lookup $(TESTING) $(VERBOSE) $(INTERPOSE) -o $@ $< src/non_allocating_print.c

# Run all tests with our interpose dylib hooking malloc via DYLD_INSERT_LIBRARIES
test-interpose: all $(INTERPOSE_DYLIB)
	@for t in $(TESTS); do \
	  echo "==> $$t (interposed)"; \
	  DYLD_INSERT_LIBRARIES=$(INTERPOSE_DYLIB) "$$t" || exit 1; \
	done; \
	echo "All interposed tests passed."
endif
# ---- interposing ----

# --- directory creators ---
dirs: | $(BLD_DIR) $(OBJ_DIR) $(TST_DIR)

$(BLD_DIR) $(OBJ_DIR) $(TST_DIR):
	@mkdir -p $@

test-container:
	docker build -t $(IMAGE) .
	docker run --rm $(IMAGE)

# if just want to exec into it, set USE_GDB to nothing/empty: make investigation-container USE_GDB=
USE_GDB ?= 1

investigation-container:
	docker build -f Dockerfile.investigation -t malloc-investigation .
	docker run --rm -it \
	-e USE_GDB=$(USE_GDB) \
	--platform=linux/arm64 \
	-v $(PWD):/app \
	-w /app \
	malloc-investigation

install-git-hooks:
	git config core.hooksPath githooks

clean:
	$(RM) -r $(BLD_DIR)
	docker rmi -f $(IMAGE) >/dev/null 2>&1 || true; 
	docker rmi -f malloc-investigation >/dev/null 2>&1 || true; 
