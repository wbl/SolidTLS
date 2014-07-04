VPATH =../src/crypto:../src/util:../test/crypto:../test/util
CC = clang
IOPTS = -I../src/crypto -I../src/util
CCOPTS = -Wall -Werror -pedantic
%.o : %.c
	$(CC) $(CCOPTS) $(IOPTS) -c $< -o $@
% : %.o
	$(CC) $(CCOPTS) $(IOPTS) $^ -o $@

all: md5test sha1test
md5test : md5.o buf.o md5test.o
sha1test: sha1.o buf.o sha1test.o