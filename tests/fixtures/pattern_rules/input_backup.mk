# Test pattern rule formatting
%.o:%.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.a: %.o
	$(AR) $(ARFLAGS) $@ $^

# Static pattern rule
$(OBJECTS): %.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Multiple pattern rules
%.d: %.c %.h
	$(CC) -MM $(CFLAGS) $< > $@

# Add a default target to resolve the "No targets" error
.PHONY: all
all:
	@echo "Makefile processed successfully." 