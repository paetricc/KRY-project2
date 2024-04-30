#####################################
# Autor: Tomas Bartu                #
# Email: xbartu11@stud.fit.vutbr.cz #
# Datum: 5.3.2024                   #
#####################################

LOGIN=230653
EXECUTABLE=kry
CC=gcc
CFLAGS=-fsanitize=address -fsanitize=leak -Wall -pedantic -Wextra

all: $(EXECUTABLE)

$(EXECUTABLE): $(EXECUTABLE).o
	$(CC) $(CFLAGS) -o $@ $^

$(EXECUTABLE).o: $(EXECUTABLE).c
	$(CC) $(CFLAGS) -c $^

run: $(EXECUTABLE)
	./$(EXECUTABLE)

zip:
	zip $(LOGIN).zip README.md Makefile $(EXECUTABLE).c $(EXECUTABLE).h

clean:
	rm -f *.o $(EXECUTABLE)
