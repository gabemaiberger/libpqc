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
	$(LL) -shared -fPIC -o $@ $^

deb:
	mkdir package/usr/
	mkdir package/usr/include
	mkdir package/usr/include/libpqc
	mkdir package/usr/lib/
	mkdir package/usr/lib/x86_64-linux-gnu
	mkdir package/usr/share/
	mkdir package/usr/share/man/
	mkdir package/usr/share/man/man3/
	cp libpqc.so package/usr/lib/x86_64-linux-gnu/
	cp $(INCDIR)*.h package/usr/include/libpqc/
	cp manpages/*.3 package/usr/share/man/man3/
	gzip package/usr/share/man/man3/*.3
	chmod -R 755 package
	dpkg-deb -b package libpqc.deb

clean: clean-build clean-deb

clean-build:
	rm -r *.o *.so

clean-deb:
	rm -r *.deb package/usr/
