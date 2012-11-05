#	LICENSING
#
#       This file is part of WireBrush for Spam project (WB4Spam).
#
#       WB4Spam: An ANSI C is an open source, highly extensible, high performance and
#       multithread spam filtering platform. It takes concepts from SpamAssassin project
#       improving distinct issues.
#
#       Copyright (C) 2010, by Sing Research Group (http://sing.ei.uvigo.es)
#
#       Wirebrush for Spam is free software; you can redistribute it and/or
#       modify it under the terms of the GNU Lesser General Public License as
#       published by the Free Software Foundation; either version 3 of the
#       License, or (at your option) any later version.
#
#       Wirebrush for Spam is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser
#       General Public License for more details.
#
#       You should have received a copy of the GNU Lesser General Public License
#       along with this program.  If not, see <http://www.gnu.org/licenses/>.

CC=cc -fPIC -O3 -g
CFLAGS=-c -Wall
OPTSLIB=-I/usr/include -I../../cpluff/include -I../../database -I../core -I../eml_structure_parser -I../..
LIBS=-L../../cpluff/lib -L/usr/lib -L/lib -L../core -L../../database -L../.. -L../eml_structure_parser -llearn_axl -lm -ldb -lfileutils -lpthread

all: axl

axl: axl_plugin.o
	$(CC) -O3 -g -shared -W1,-soname,libaxl_plugin.so.0 axl_plugin.o -o libaxl_plugin.so.0 $(OPTSLIB) $(LIBS)
	ln -sf libaxl_plugin.so.0 libaxl_plugin.so
	ln -sf libaxl_plugin.so.0 libaxl_plugin.so.1

axl_plugin.o:
	$(CC) $(CFLAGS) -g -c axl_plugin.c $(OPTSLIB) $(LIBS) -o axl_plugin.o

clean :
	rm *.o *.so *.so.?
