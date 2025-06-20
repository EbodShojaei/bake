# Test include directives and export statements
include   config.mk
include build/common.mk   
  include 	dependencies/*.mk

# Conditional includes with poor spacing
ifeq ($(PLATFORM),linux)
include   platform/linux.mk
endif

ifneq ($(TOOLCHAIN),)
  include toolchain/$(TOOLCHAIN).mk
endif

# Optional includes
-include  local.mk
-include	.env
  -include $(wildcard *.local)

# Export statements with inconsistent formatting
export CC CXX   
export    CFLAGS CXXFLAGS
export LDFLAGS="-L/usr/local/lib"

# Unexport statements
unexport  DEBUG_FLAGS
unexport	TEMP_VAR

# Export with assignment
export PATH:=/usr/local/bin:$(PATH)
export    PKG_CONFIG_PATH += /usr/local/lib/pkgconfig

# VPATH with poor formatting
VPATH = src:include:build
vpath %.c    src/
vpath   %.h  include/  
vpath %.o   build/

# Variable definitions that should be exported
IMPORTANT_VAR = value
export IMPORTANT_VAR
ANOTHER_VAR:=another_value
export   ANOTHER_VAR

# Include with variables
INCLUDE_DIR = config
include $(INCLUDE_DIR)/settings.mk
include   $(wildcard $(INCLUDE_DIR)/*.mk) 