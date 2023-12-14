IDIR=src/include
CFBHDR=$(wildcard $(IDIR)/*.h)
CC=g++
CFLAGS=-I$(IDIR) -std=c++17 -Wall
LDFLAGS=-L/opt/homebrew/opt/openssl@3/lib -lz -lssl -lcrypto # Linker flags, add -lz for zlib

ODIR=out
OBJ=$(ODIR)/cfb.o $(ODIR)/decrypt.o

$(ODIR)/%.o: samples/cfb/%.cpp $(CFBHDR)
	mkdir -p $(ODIR)
	$(CC) -c -o $@ $< $(CFLAGS)

all: out/ieot out/cfb

out/ieot: samples/IEOpenedTabParser/openedtab.cpp samples/IEOpenedTabParser/IEOpenedTabParser.h $(CFBHDR)
	mkdir -p out
	$(CC) -o $@ $< $(CFLAGS)

#out/cfb: samples/cfb/cfb.cpp samples/cfb/decrypt.cpp $(CFBHDR)
#	mkdir -p out
#	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)
out/cfb: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean

clean:
	rm -rf $(ODIR)
