# Advanced target patterns and dependencies
.PHONY: all clean test install uninstall

# Double-colon rules with inconsistent formatting
src/%.o:: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

src/%.o::src/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Target with multiple dependency groups
main: $(OBJECTS) $(EXTRA_OBJECTS) \
	$(LIBRARIES)
	$(CC) -o $@ $^ $(LDFLAGS)

# Targets with order-only prerequisites
$(OBJECTS): | $(BUILD_DIR)

$(BUILD_DIR):
	mkdir -p $@

# Pattern rules with multiple targets
%.h %.c: %.y
	yacc -d $<
	mv y.tab.c $*.c
	mv y.tab.h $*.h

# Targets with complex prerequisites
install: all | $(DESTDIR)$(bindir) $(DESTDIR)$(mandir)
	install -m755 $(TARGET) $(DESTDIR)$(bindir)/
	install -m644 $(TARGET).1 $(DESTDIR)$(mandir)/

# Static pattern rules
$(OBJECTS): %.o: %.c | $(DEPDIR)
	$(CC) $(CFLAGS) -c -o $@ $<
	$(CC) $(CFLAGS) -MM -MT $@ $< > $(DEPDIR)/$*.d

# Target-specific variables with poor formatting
debug: CFLAGS += -g -DDEBUG
debug: LDFLAGS += -rdynamic
debug: all

# Target-specific variable assignment forms that should not warn
ollama/run/cpu: DOCKER_IMAGE_NAME = ollama-wrapper
ollama/run/cpu: DOCKER_UID ?= $(shell id -u)
ollama/run/cpu: DOCKER_GID ?= $(shell id -g)
ollama/run/cpu: MODEL ?= llama3.1
ollama/run/cpu: .make/ollama-docker FORCE
ollama/run/cpu:
	docker container rm ollama ; true
	docker run \
		--detach \
		--name ollama \
		--publish 11434:11434 \
		--user $(DOCKER_UID):$(DOCKER_GID) \
		--volume $(CURDIR)/data/ollama:/home/ollama/.ollama \
		$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG) $(MODEL)

release: CFLAGS += -O2 -DNDEBUG
release: CFLAGS += -march=native
release: all

# Conditional targets
ifeq ($(BUILD_TESTS),yes)
test: $(TEST_OBJECTS)
	$(CC) -o test_runner $(TEST_OBJECTS) $(LDFLAGS)
	./test_runner
endif
