# This makefile is designed to be a complete mess.
# It has deeply nested conditionals and inconsistent indentation.
# Good luck, formatter!

all: chaos

# A target to test nested conditionals and indentation.
chaos:
	@echo "--- CHAOS MODE INITIATED ---"
	@echo "  This Makefile is intentionally a mess to stress-test the formatter."
ifeq ($(MAKECMDGOALS), chaos)
    ifeq ($(shell uname -s), Darwin)
        @echo "    Running on a Mac, as expected."
       ifdef TEST_MAC_VARIABLE
	@echo "      This nested test variable is defined."
       else
	@echo "      This nested test variable is NOT defined."
endif
      else
        @echo "    Running on a non-Mac system."
	   ifndef NOT_A_MAC_SYSTEM
	@echo "      This should not be printed on a non-Mac system."
	   endif
    endif
	@echo "  This echo is outside the second ifeq but inside the first."
endif

# Another target to test tricky indentation with shell commands.
deep_chaos:
	@echo "--- DEEP CHAOS INITIATED ---"
	ifeq ($(shell hostname), my_test_machine)
	   @echo "    Running on the test machine."
	   @echo "    Executing a complex shell command."
	       bash -c 'if [ "a" = "a" ]; then
	echo "    This is from a nested shell command.";
fi'
	else
	 @echo "    Running on a different machine."
	  @echo "    Executing a different complex shell command."
		   bash -c 'if [ "b" = "b" ]; then
		   echo "    This is from another nested shell command.";
fi'
endif

# An exit point
exit:
	@echo "--- CHAOS MODE EXITED ---"