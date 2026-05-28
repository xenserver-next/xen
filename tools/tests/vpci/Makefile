XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test_vpci

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

$(TARGET): vpci.c vpci.h list.h private.h main.c emul.h
	$(CC) $(CFLAGS_xeninclude) -include emul.h -g -o $@ vpci.c main.c

.PHONY: clean
clean:
	rm -rf $(TARGET) *.o *~ vpci.h vpci.c list.h private.h

.PHONY: distclean
distclean: clean

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC)/tests
	$(INSTALL_PROG) $(TARGET) $(DESTDIR)$(LIBEXEC)/tests

.PHONY: uninstall
uninstall:
	$(RM) -- $(DESTDIR)$(LIBEXEC)/tests/$(TARGET)

vpci.c: $(XEN_ROOT)/xen/drivers/vpci/vpci.c
	sed -e '/#include/d' <$< >$@

private.h: %.h: $(XEN_ROOT)/xen/drivers/vpci/%.h
	sed -e '/#include/d' <$< >$@

list.h vpci.h: %.h: $(XEN_ROOT)/xen/include/xen/%.h
	sed -e '/#include/d' <$< >$@
