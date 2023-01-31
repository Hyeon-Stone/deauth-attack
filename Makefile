LDLIBS= -lpcap

all: deauth-attack

parse.o: parse.h parse.cpp


deauth-attack: main.o parse.o hdr.h
	$(LINK.cc) -w $^ $(LOADLIBES) $(LDLIBS) -o $@
	rm -f *.o
clean:
	rm -f deauth-attack *.o

