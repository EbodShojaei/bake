ifeq ($(CFG_WITH_LONGTESTS),yes)
ifeq ($(DRIVER_STD),newest)
CPPFLAGS += $(CFG_CXXFLAGS_STD)
else
CPPFLAGS += else_term
endif
ifneq ($(DRIVER_STD),newest)
ifneq ($(DRIVER_STD),newest)
CPPFLAGS += ifneq_term
endif
endif
endif

define TEST_SNAP_template
mkdir -p $(TEST_SNAP_DIR)
rm -rf $(TEST_SNAP_DIR)/obj_$(1)
cp -r obj_$(1) $(TEST_SNAP_DIR)/
find $(TEST_SNAP_DIR)/obj_$(1) \( $(TEST_SNAP_IGNORE:%=-name "%" -o) \
  -type f -executable \) -prune | xargs rm -r
endef

ifeq ($(FOO),yes)
define FOO_template
something
endef
else
define FOO_template
something_else
endef
endif
