define YAML
key: 1
endef

.ONESHELL:
SHELL := bash

.PHONY: test_split
test_split:
	files=$(call ls)
	$(call first)

define first
    FIRST=$(word 1, $(subst _, ,$@))
    echo "$${FIRST}"
endef
