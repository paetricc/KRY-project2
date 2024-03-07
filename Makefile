#####################################
# Autor: Tomas Bartu                #
# Email: xbartu11@stud.fit.vutbr.cz #
# Datum: 5.3.2024                   #
#####################################

EXECUTABLE=kry
CC=gcc
CFLAGS=-fsanitize=address -fsanitize=leak -g -Wall -pedantic -Wextra


all: $(EXECUTABLE)

$(EXECUTABLE): $(EXECUTABLE).o
	$(CC) $(CFLAGS) -o $@ $^

$(EXECUTABLE).o: $(EXECUTABLE).c
	$(CC) $(CFLAGS) -c $^

run: $(EXECUTABLE)
	./$(EXECUTABLE)

clean:
	rm -f *.o $(EXECUTABLE)