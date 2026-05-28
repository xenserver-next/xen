XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test-tsx

.PHONY: all
all: $(TARGET)

.PHONY: run
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

.PHONY: uninstall
uninstall:

CFLAGS += -I$(XEN_ROOT)/tools/libs/ctrl -I$(XEN_ROOT)/tools/libs/guest
CFLAGS += $(CFLAGS_xeninclude)
CFLAGS += $(CFLAGS_libxenctrl)
CFLAGS += $(CFLAGS_libxenguest)
CFLAGS += $(APPEND_CFLAGS)

LDFLAGS += $(LDLIBS_libxenctrl)
LDFLAGS += $(LDLIBS_libxenguest)
LDFLAGS += $(APPEND_LDFLAGS)

%.o: Makefile

$(TARGET): test-tsx.o
	$(CC) -o $@ $< $(LDFLAGS)

-include $(DEPS_INCLUDE)
