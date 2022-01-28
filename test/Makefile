SRC := $(wildcard ../src/*.c)
CFLAGS := -I../include -O2

.PHONY: test
test: $(SRC) test.c
	$(CC) $(CFLAGS) $^ -o rocca.test && ./rocca.test
	$(CC) $(CFLAGS) -maes -arch x86_64 $^ -o rocca.test && ./rocca.test
