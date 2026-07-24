.PHONY: benchmark

benchmark:
	uv run benchmark code-eval \
	--extract-scripts \
	--chat-model=gpt-5.2

build:
	docker build \
	--no-cache \
	--tag=myimage:latest .

# Variable assignment continuations are unaffected
SOURCES = file1.c \
          file2.c \
          file3.c
