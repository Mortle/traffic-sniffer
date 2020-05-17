PKGCONFIG = $(shell which pkg-config)
TARGET = prog
LIBS = -lm -lpcap $(shell $(PKGCONFIG) --libs gtk+-3.0)
CC = gcc
CFLAGS = -g -Wall $(shell $(PKGCONFIG) --cflags gtk+-3.0)

.PHONY: default all clean

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -Wall $(LIBS) -o $@

clean:
	-rm -f *.o
	-rm -f $(TARGET)
