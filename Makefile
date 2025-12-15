CC = gcc
CFLAGS = -Wall -Wextra -std=c99
TARGET = backup_manager
SOURCE = backup_manager.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)
