
CC       := gcc
TARGET   := test_pdeathsig_thread
SOURCE   := test_pdeathsig_thread.c

CFLAGS   := -Wall -Wextra -g -ggdb -pthread
LDFLAGS  := -pthread

.PHONY: all clean run debug

# Default target
all: $(TARGET)

# Build executable
$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(SOURCE) -o $@ $(LDFLAGS)

# Run test
run: $(TARGET)
	./$(TARGET)

# Debug build
debug: CFLAGS := -Wall -Wextra -O0 -g3 -pthread
debug: clean $(TARGET)

# Clean generated files
clean:
	rm -f $(TARGET) *.o core core.*

