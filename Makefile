all:
	cc main.c -lbsm -o watchfs

clean:
	rm -f watchfs