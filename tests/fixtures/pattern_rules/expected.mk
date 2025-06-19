# Test pattern rule formatting
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.a: %.o
	$(AR) $(ARFLAGS) $@ $^

# Static pattern rule
$(OBJECTS): %.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Multiple pattern rules
%.d: %.c %.h
	$(CC) -MM $(CFLAGS) $< > $@