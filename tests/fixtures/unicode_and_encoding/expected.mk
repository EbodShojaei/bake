# Unicode and special encoding test
# Makefile with various Unicode characters and encodings

# Variables with Unicode characters
PROJECT_NAME = tëst-prøjëct
AUTHOR = José María González
COPYRIGHT = © 2024 Ëxample Corp™

# Paths with Unicode characters
SRC_DIR = src/测试
BUILD_DIR = build/тест
DOCS_DIR = docs/ドキュメント

# Variables with special characters and symbols
SYMBOLS = ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿
MATH_SYMBOLS = ∀∁∂∃∄∅∆∇∈∉∊∋∌∍∎∏∐∑−∓∔∕∖∗∘∙√∛∜∝∞∟∠∡∢∣∤∥∦∧∨∩∪∫∬∭∮∯∰∱∲∳∴∵∶∷∸∹∺∻∼∽∾∿

# Targets with Unicode names
тест:
	@echo "Running тест target"

测试: $(SRC_DIR)/main.c
	gcc -o $@ $<

# Commands with Unicode output and paths
compile-docs:
	@echo "Compiling documentation in $(DOCS_DIR)"
	pandoc README.md -o $(DOCS_DIR)/documentation.pdf

# Variables with emoji (modern Unicode)
STATUS_ICONS = ✅❌⚠️🔧🚀📦
BUILD_EMOJI = 🔨
TEST_EMOJI = 🧪

# File patterns with Unicode
UNICODE_SOURCES = $(wildcard $(SRC_DIR)/*.c) \
                  $(wildcard $(SRC_DIR)/测试/*.c) \
                  $(wildcard $(SRC_DIR)/тест/*.c)

# Target with Unicode comments
unicode-demo: # Target with Unicode: 你好世界 🌍
	@echo "Hello World in different languages:"
	@echo "English: Hello World"
	@echo "中文: 你好世界"
	@echo "日本語: こんにちは世界"
	@echo "Русский: Привет мир"
	@echo "العربية: مرحبا بالعالم"
	@echo "Español: Hola Mundo"

# Complex Unicode in shell commands
unicode-test:
	for lang in "English" "中文" "日本語" "Русский"; do \
		echo "Testing $$lang support"; \
	done

# Unicode in file operations
unicode-files:
	touch "файл.txt"
	touch "ファイル.txt"
	touch "文件.txt"
	ls -la *.txt

# Variable with mixed ASCII and Unicode
MIXED_VAR = Hello世界مرحبا¡Hola!Привет🌍 
