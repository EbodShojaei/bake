# Test shell script formatting in recipes
test:
	# Complex shell command with inconsistent indentation
	if [ "$(DEBUG)" = "yes" ]; then \
	  echo "Debug mode enabled"; \
	  CFLAGS="-g -O0"; \
	else \
	  CFLAGS="-O2"; \
	fi; \
	$(CC) $$CFLAGS -o $(TARGET) $(SOURCES)

deploy:
	for file in $(wildcard *.txt); do \
	  cat $$file | \
	  sed 's/foo/bar/g' > \
	  processed_$$(basename $$file); \
	done
