CC       = gcc
CXX      = g++
CFLAGS   = -Wall -O2
CXXFLAGS = -Wall -O2 -std=c++17
LDFLAGS  = -lpthread

C_SOURCES   = core/raw_socket.c
CPP_SOURCES = scanner/Scanner.cpp scanner/BannerGrabber.cpp scanner/ThreadPool.cpp main.cpp
C_OBJECTS   = $(C_SOURCES:.c=.o)
CPP_OBJECTS = $(CPP_SOURCES:.cpp=.o)
TARGET      = scanner_main

all: $(TARGET)
	@echo "Build complete! Binary: ./$(TARGET)"

$(TARGET): $(C_OBJECTS) $(CPP_OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	find . -name "*.o" -delete
	rm -f $(TARGET)
	@echo "Cleaned up."

.PHONY: all clean