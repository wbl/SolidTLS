VPATH =../src/crypto:../src/util:../test/crypto:../test/util
CC = clang
IOPTS = -I../src/crypto -I../src/util
CCOPTS = -Wall -Werror -pedantic -Wextra -O3
%.o : %.c
	$(CC) $(CCOPTS) $(IOPTS) -c $< -o $@
% : %.o
	$(CC) $(CCOPTS) $(IOPTS) $^ -o $@

all: md5test sha1test sha256test sha384test sha512test
md5test : md5.o buf.o md5test.o
sha1test: sha1.o buf.o sha1test.o
sha256test: sha256.o buf.o sha256test.o
sha384test: sha64.o buf.o sha384test.o
sha512test: sha64.o buf.o sha512test.o