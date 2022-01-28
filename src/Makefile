SRC := $(wildcard *.c)
CFLAGS := -I../include -O3

.PHONY: test
test: $(SRC) 
	$(CC) $(CFLAGS) $^ -o rocca.test && ./rocca.test
	$(CC) $(CFLAGS) -maes -arch x86_64 $^ -o rocca.test && ./rocca.test
