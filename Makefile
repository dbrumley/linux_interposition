all:
	gcc -shared -I. -ldl -fPIC interpose.c -o libinterpose.so
	gcc -g -ggdb test.c -o test
clean:
	rm libinterpose.so test
