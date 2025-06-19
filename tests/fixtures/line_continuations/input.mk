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