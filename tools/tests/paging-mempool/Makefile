XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test-paging-mempool

.PHONY: all
all: $(TARGET)

run: $(TARGET)
	$(call RUN_TARGETS_IF_CC_IS_HOSTCC)

# The tests in this directory need to run in a privileged domain (Dom0)
# with libxenctrl and a matching the hypervisor to test running it.
# Therefore, they don't run with the native test target for build-time tests.
.PHONY: test
test:

.PHONY: clean
clean:
	$(RM) -- *.o $(TARGET) $(DEPS_RM)

.PHONY: distclean
distclean: clean
	$(RM) -- *~

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC)/tests
	$(INSTALL_PROG) $(TARGET) $(DESTDIR)$(LIBEXEC)/tests

.PHONY: uninstall
uninstall:
	$(RM) -- $(DESTDIR)$(LIBEXEC)/tests/$(TARGET)

CFLAGS += $(CFLAGS_xeninclude)
CFLAGS += $(CFLAGS_libxenctrl)
CFLAGS += $(CFLAGS_libxendevicemodel)
CFLAGS += $(CFLAGS_libxenforeignmemory)
CFLAGS += $(APPEND_CFLAGS)

LDFLAGS += $(LDLIBS_libxenctrl)
LDFLAGS += $(LDLIBS_libxendevicemodel)
LDFLAGS += $(LDLIBS_libxenforeignmemory)
LDFLAGS += $(APPEND_LDFLAGS)

%.o: Makefile

$(TARGET): test-paging-mempool.o
	$(CC) -o $@ $< $(LDFLAGS)

-include $(DEPS_INCLUDE)
