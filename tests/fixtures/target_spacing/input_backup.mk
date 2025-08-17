# Test target definition spacing
.PHONY: all target1 target2 empty-target standalone dep1 dep2 dep3 dep4

all:target1 target2
	@echo "All targets"

target1  :   dep1   dep2   
	echo "Target 1"

target2:dep3 dep4
	echo "Target 2"

# Empty target
empty-target :
	

# Target with no dependencies
standalone:
	echo "Standalone"

# Phony dependencies (added to resolve the error)
dep1:
	echo "Processing dep1"
dep2:
	echo "Processing dep2"
dep3:
	echo "Processing dep3"
dep4:
	echo "Processing dep4" 