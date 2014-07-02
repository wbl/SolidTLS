VPATH =../src/crypto:../src/util:../test/crypto:../test/util
CC = clang
IOPTS = -I../src/crypto -I../src/util

%.o : %.c
	$(CC) $(IOPTS) -c $< -o $@
% : %.o
	$(CC) $(IOPTS) $^ -o $@

all: md5test
md5test : md5.o buf.o md5test.o