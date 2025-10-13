SRC := a.c b.c
OBJ := $(SRC:.c=.o)

all: $(OBJ)
