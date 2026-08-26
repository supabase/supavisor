# pgparser NIF build chain:
#   download libpg_query (pinned sha256) -> apply patches/ -> build libpg_query.a
#   -> compile c_src -> link priv/native/pgparser.so
#
# Offline/nix build: LIBPG_QUERY_TARBALL=/path/to/libpg_query-17-6.2.1.tar.gz make
# After patches/ changes, run `make distclean` to re-extract the sources.

LPQ_VERSION := 17-6.2.1
LPQ_SHA256 := 678434d59511c8892c37ba5b9816ab641bd007cef2eda215b2297c39b79c861d

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
VENDOR_DIR := $(ROOT)/vendor
LPQ_TARBALL := $(VENDOR_DIR)/libpg_query-$(LPQ_VERSION).tar.gz
LPQ_URL := https://github.com/pganalyze/libpg_query/archive/refs/tags/$(LPQ_VERSION).tar.gz
LPQ_SRC := $(VENDOR_DIR)/libpg_query-$(LPQ_VERSION)
LPQ_LIB := $(LPQ_SRC)/libpg_query.a

ERTS_INCLUDE_DIR ?= $(shell erl -eval 'io:format("~ts/erts-~ts/include", [code:root_dir(), erlang:system_info(version)])' -s init stop -noshell)

PRIV_DIR := $(abspath $(ROOT)/../../priv/native)
NIF_SO := $(PRIV_DIR)/pgparser.so

NODETAGS_INC := $(ROOT)/c_src/pg_nodetags.inc

CC ?= cc
NIF_CFLAGS := -O2 -fPIC -fno-strict-aliasing -fwrapv -Wall -std=c11 -pthread \
	-I$(ERTS_INCLUDE_DIR) \
	-I$(LPQ_SRC) -I$(LPQ_SRC)/src/include -I$(LPQ_SRC)/src/postgres/include -I$(LPQ_SRC)/vendor

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	SO_LDFLAGS := -bundle -undefined dynamic_lookup
else
	SO_LDFLAGS := -shared
endif

C_SRCS := $(wildcard $(ROOT)/c_src/*.c)
OBJS := $(C_SRCS:.c=.o)

all: $(NIF_SO)

$(LPQ_TARBALL):
	@mkdir -p $(VENDOR_DIR)
ifdef LIBPG_QUERY_TARBALL
	cp $(LIBPG_QUERY_TARBALL) $(LPQ_TARBALL)
else
	curl -fSL --retry 3 -o $(LPQ_TARBALL) $(LPQ_URL)
endif
	@echo "$(LPQ_SHA256)  $(LPQ_TARBALL)" | sha256sum -c - 2>/dev/null || \
		echo "$(LPQ_SHA256)  $(LPQ_TARBALL)" | shasum -a 256 -c - || \
		{ rm -f $(LPQ_TARBALL); false; }

$(LPQ_SRC)/.patched: $(LPQ_TARBALL)
	rm -rf $(LPQ_SRC)
	tar xzf $(LPQ_TARBALL) -C $(VENDOR_DIR)
	for p in $(ROOT)/patches/*.patch; do \
		[ -e "$$p" ] || continue; \
		echo "applying $$p"; \
		patch -p1 -d $(LPQ_SRC) < "$$p"; \
	done
	touch $@

$(LPQ_LIB): $(LPQ_SRC)/.patched
	$(MAKE) -C $(LPQ_SRC) build

# Generate switch arms from nodetags.h: T_SelectStmt -> "SelectStmt" (protobuf-compatible naming)
$(NODETAGS_INC): $(LPQ_SRC)/.patched
	awk '/^\tT_[A-Za-z0-9_]+ = [0-9]+,$$/ { tag = $$1; name = tag; sub(/^T_/, "", name); \
		printf "\tcase %s: return \"%s\";\n", tag, name }' \
		$(LPQ_SRC)/src/postgres/include/nodes/nodetags.h > $@

$(ROOT)/c_src/%.o: $(ROOT)/c_src/%.c $(NODETAGS_INC) $(LPQ_SRC)/.patched
	$(CC) $(NIF_CFLAGS) -c -o $@ $<

$(NIF_SO): $(OBJS) $(LPQ_LIB)
	@mkdir -p $(PRIV_DIR)
	$(CC) -o $@ $(OBJS) $(LPQ_LIB) $(SO_LDFLAGS) -pthread

# C unit tests (exclude pg_nif.o to avoid the erl_nif dependency)
TEST_BIN := $(ROOT)/test/shape_cache_tests
TEST_OBJS := $(filter-out $(ROOT)/c_src/pg_nif.o,$(OBJS))

test: $(TEST_BIN)
	$(TEST_BIN)

$(TEST_BIN): $(ROOT)/test/shape_cache_tests.c $(TEST_OBJS) $(LPQ_LIB)
	$(CC) $(NIF_CFLAGS) -I$(ROOT)/c_src -o $@ $< $(TEST_OBJS) $(LPQ_LIB) -pthread

clean:
	rm -f $(OBJS) $(NIF_SO) $(NODETAGS_INC) $(TEST_BIN)

distclean: clean
	rm -rf $(VENDOR_DIR)

.PHONY: all clean distclean test
