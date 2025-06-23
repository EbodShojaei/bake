# -*- mode: makefile -*-
#This header comment has no space
   # with multiple lines
#and inconsistent spacing
#   and various indentation levels

#Variable with inline comment
CC = gcc#Default compiler
CFLAGS = -Wall -Wextra   #Compiler flags with trailing spaces

#Target with comment spacing issues
all: build test#Build and test everything

#Comments mixed with code
build: #Build the project
	$(CC) $(CFLAGS) -o main main.c#Compile main
	#This comment has no space
	# This comment has weird indentation

#Commented out code
#OLD_CFLAGS=-O2 -g
#OLD_TARGET=old_main

test: #Test target
	./main --test#Run tests

#Multi-line comment block
################################
#This is a large comment block
#with multiple lines and
#inconsistent formatting
################################

clean:
	rm -f *.o main#Clean up files
	#Another comment
		#Indented comment

#Comment with trailing spaces
install: #Install target
	cp main /usr/local/bin/#Copy binary

#EOF comment
