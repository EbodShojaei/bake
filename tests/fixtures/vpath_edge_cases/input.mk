# VPATH edge cases and error scenarios
VPATH = 
VPATH = src:include:build::
VPATH = :src:include:build:
VPATH = src::include::build
VPATH = src: include: build
VPATH = src : include : build

# VPATH with quotes (should be preserved)
VPATH = "src:include:build"
VPATH = 'src include build'

# VPATH with escaped characters
VPATH = src\:include\:build
VPATH = src\ include\ build

# VPATH with special characters in directory names
VPATH = src-dir:include_dir:build.dir
VPATH = src+dir:include-dir:build_dir
