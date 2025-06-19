# Test target definition spacing
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