ifeq ($(OS),Windows_NT)
win:
	SOME_URL=http://github.com \
		echo windows
else
unix:
	SOME_URL=http://github.com \
		echo unix
endif
