GIT_HASH ?= $(shell git log --format="%h" -n 1) # get the git hash for image tag
PROJECT  := malloc
CC       ?= gcc
CSTD     ?= -std=c17
WARN     := -Wall -Wextra -Werror -Wpedantic
DBG      := -O0 -g
# Do NOT use AddressSanitizer when you override malloc/free globally.
SAN      := -fsanitize=undefined     # no ASan when overriding malloc
TEST_DEFS     := -DTESTING -DENABLE_LOG -DENABLE_MM_SBRK                # turn on test-only asserts/hooks
SHOW_SBRK_RELEASE_FAIL := -DSHOW_SBRK_RELEASE_FAIL

# `-fno-builtin` prevents gcc from assuming builtin malloc/free semantics.
INCLUDE_INTERNAL := -Isrc # only for when building lib/tests
INCLUDE_PUBLIC   := -Iinclude
# common compile flags 
CFLAGS   := $(CSTD) $(WARN) $(DBG) $(SAN) -fno-builtin $(TEST_DEFS) $(INCLUDE_PUBLIC) $(INCLUDE_INTERNAL)
ARFLAGS  := rcs
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  # On macOS, use libtool to produce a static archive compatible with ld64
  MAKE_STATIC_LIB = libtool -static -o
  NEED_RANLIB     = 0
else
  MAKE_STATIC_LIB = $(AR) $(ARFLAGS)
  NEED_RANLIB     = 1
endif

# --- layout ---
SRC_DIR  := src
TEST_DIR := tests
BLD_DIR  := build
OBJ_DIR  := $(BLD_DIR)/obj
TST_DIR  := $(BLD_DIR)/tests

# --- sources ---
SRCS     := $(wildcard $(SRC_DIR)/*.c)
OBJS     := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))
LIB      := $(BLD_DIR)/lib$(strip $(PROJECT)).a

# All test .c files become executables of the same basename in build/tests
TEST_SOURCES := $(filter-out $(TEST_DIR)/acutest.h,$(wildcard $(TEST_DIR)/*.c))
TESTS    := $(patsubst $(TEST_DIR)/%.c,$(TST_DIR)/%,$(TEST_SOURCES))

.PHONY: all clean test dirs

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
	$(CC) $(CFLAGS) $< $(LIB) -o $@

test: all
	@for t in $(TESTS); do echo "==> $$t"; "$$t" || exit 1; done
	@echo "All tests passed."

# --- directory creators ---
dirs: | $(BLD_DIR) $(OBJ_DIR) $(TST_DIR)

$(BLD_DIR) $(OBJ_DIR) $(TST_DIR):
	@mkdir -p $@

clean:
	$(RM) -r $(BLD_DIR)
