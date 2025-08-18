all:
ifdef VAR1
  ifneq ($(VAR2),value2)
    ifdef VAR3
	  @echo " VAR3 is defined"
      ifndef VAR4
	    @echo " VAR4 is NOT defined"
        ifeq ($(VAR5),value5)
	      @echo " VAR5 matches value5"
          ifneq ($(VAR6),value6)
            ifeq ($(VAR7),value7)
	          @echo "Deeply nested VAR7 check"
            else
	          @echo "VAR7 else branch"
            endif
          else
	        @echo "VAR6 else branch"
          endif
        else
	      @echo "VAR5 else branch"
        endif
      endif
    else
	  @echo "VAR3 else branch"
    endif
  else
	@echo "VAR2 else branch"
  endif
else
	@echo "VAR1 else branch"
endif
