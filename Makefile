#libpqc Makefile
#Copyright (C) 2017 Gabriel Nathan Maiberger

#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU Lesser General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.

#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU Lesser General Public License for more details.

#You should have received a copy of the GNU Lesser General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.

include Make.rules

all: libpqc.so deb

libpqc.so: r3d-shared.o r3d_modes-shared.o sidh-shared.o sha3-shared.o pbkdf2-shared.o tcp_steg-shared.o
	$(LL) -shared -fPIC -lm -lpthread -o $@ $^

libpqc-java.so: r3d-shared.o r3d_modes-shared.o sidh-shared.o sha3-shared.o pbkdf2-shared.o tcp_steg-shared.o java-shared.o
	$(LL) -shared -fPIC -lm -lpthread -o $@ $^

deb:
	mkdir -p package/usr/
	mkdir -p package/usr/include
	mkdir -p package/usr/include/libpqc
	mkdir -p package/usr/lib/
	mkdir -p package/usr/lib/x86_64-linux-gnu
	mkdir -p package/usr/share/
	mkdir -p package/usr/share/man/
	mkdir -p package/usr/share/man/man3/
	cp *.so package/usr/lib/x86_64-linux-gnu/
	cp include/*.h package/usr/include/libpqc/
	cp manpages/*.3 package/usr/share/man/man3/
	gzip -f package/usr/share/man/man3/*.3
	chmod -R 755 package
	dpkg-deb -b package libpqc.deb

clean: clean-build clean-deb

clean-build:
	rm -r *.o *.so

clean-deb:
	rm -r *.deb package/usr/
