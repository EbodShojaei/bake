# Invalid target syntax test cases

# Invalid target with = sign
target=value: prerequisites
	recipe

# Invalid target with .RECIPEPREFIX character
.RECIPEPREFIX := >
>invalid: prerequisites
	recipe

# Another invalid target with custom prefix
.RECIPEPREFIX := @
@another_invalid: deps
	recipe

# Valid targets for comparison
valid_target: prerequisites
	recipe

.RECIPEPREFIX := >
valid_recipe:
>	echo "This is valid"

# Invalid target in conditional
ifeq ($(DEBUG),yes)
debug_target=value: debug_deps
	debug_recipe
endif

# Valid target in conditional
ifeq ($(RELEASE),yes)
release_target: release_deps
	release_recipe
endif
