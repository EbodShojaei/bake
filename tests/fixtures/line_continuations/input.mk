# Test line continuation formatting
SOURCES = main.c \  
    utils.c \	
    parser.c

# Line continuation in recipe with trailing spaces
build:
	echo "Starting build" && \ 
	mkdir -p $(BUILD_DIR) && \ 	
	$(CC) $(CFLAGS) \  
		-o $(TARGET) \
		$(SOURCES) 

# Minimal test for tab/space/continuation issues

ifeq ($(CFG),yes)
foo:
	@echo "Hello world" \
	     continued line \
	     another line
else
foo:
	@echo "Alt" \
	     alt continued
endif

# Comments at left margin should not affect indentation
# This is a left comment
foo:
	@echo "Should still be tabbed" 