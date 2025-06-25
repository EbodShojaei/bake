# bake-format off
NO_FORMAT_1= \
      1 \
  45678 \

#bake-format on

# bake-format off : optional comment
NO_FORMAT_2= \
      1 \
  45678 \

#bake-format on

# This will be formatted normally
VAR1:=value1
target1:
    echo 'spaces will become tabs'

# bake-format off
NO_FORMAT_1= \
      1 \
  45678 \

badly_spaced_target:
  echo 'these spaces will NOT become tabs'
    echo 'even weird indentation is preserved'
.PHONY:not_grouped
#bake-format on

# This should be formatted again
VAR2:=value2

# bake-format off : optional comment
ANOTHER_UNFORMATTED_VAR:=no_spaces_added_here
    weird_target_with_spaces:
        echo 'preserved as-is'
# bake-format on

# Back to normal formatting
VAR3:=value3
target3:
    echo 'back to normal' 