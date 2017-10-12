include Make.rules

all: libpqc.so

libpqc.so: r3d-shared.o r3d_modes-shared.o
	$(LL) -shared -fPIC -o $@ $^

clean:
	rm -rf *.o *.so
