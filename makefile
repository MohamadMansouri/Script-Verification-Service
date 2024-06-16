CC = gcc
CFLAGS = -Wall -Wextra -Iinc

SRC_PATH = src
BUILD_PATH = build
LIBS = -lssl -lcrypto

SRC = $(wildcard $(SRC_PATH)/*.c)
OBJ = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRC))

TARGET = server

all: $(TARGET)


$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ) $(LIBS)

$(BUILD_PATH)/%.o: $(SRC_DIR)/%.c | $(BUILD_PATH)
	$(CC) $(CFLAGS)  -c $< -o $@

$(BUILD_PATH):
	mkdir -p $(BUILD_PATH)

clean:
	rm -f $(TARGET)