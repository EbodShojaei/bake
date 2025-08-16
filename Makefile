.PHONY: lint

lint:
	black mbake
	ruff check mbake
	mypy mbake
