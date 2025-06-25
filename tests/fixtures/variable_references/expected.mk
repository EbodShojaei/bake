# Test for numeric targets in define blocks
# These should not be flagged as duplicate targets

define CXX_ASTMT_template
  $(1): $(basename $(1)).cpp V3PchAstMT.h.gch
  $(OBJCACHE) ${CXX} ${CXXFLAGS} ${CPPFLAGSWALL} ${CFG_CXXFLAGS_PCH_I} V3PchAstMT.h${CFG_GCH_IF_CLANG} -c $(srcdir)/$(basename $(1)).cpp -o $(1)

endef

$(foreach obj,$(RAW_OBJS_PCH_ASTMT),$(eval $(call CXX_ASTMT_template,$(obj))))

define CXX_ASTNOMT_template
  $(1): $(basename $(1)).cpp V3PchAstNoMT.h.gch
  $(OBJCACHE) ${CXX} ${CXXFLAGS} ${CPPFLAGSWALL} ${CFG_CXXFLAGS_PCH_I} V3PchAstNoMT.h${CFG_GCH_IF_CLANG} -c $(srcdir)/$(basename $(1)).cpp -o $(1)

endef

$(foreach obj,$(RAW_OBJS_PCH_ASTNOMT),$(eval $(call CXX_ASTNOMT_template,$(obj))))

# Also test other numeric parameters
define MULTI_PARAM_template
  $(1) $(2): $(3)
  echo "Building $(1) and $(2) from $(3)"

endef

# Test nested numeric targets
define NESTED_template
  $(1):
  $(MAKE) $(2)
  $(MAKE) $(3)

endef

# Test extended variable formats - should not be flagged as duplicates
define EXTENDED_template
  ${1}: ${1}.c
  gcc -o ${1} ${1}.c

endef

define NAMED_VAR_template
  $(VK_OBJS): $(SRC_FILES)
  $(CC) $(CFLAGS) -o $(VK_OBJS) $(SRC_FILES)

endef

define CURLY_NAMED_template
  ${VK_OBJS}: ${SRC_FILES}
  ${CC} ${CFLAGS} -o ${VK_OBJS} ${SRC_FILES}

endef

# Test mixed formats in same define block
define MIXED_template
  $(1) ${2}: $(3)
  echo "Building $(1) and ${2} from $(3)"

endef
