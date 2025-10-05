CXX = g++
CXXFLAGS = -std=c++11 -Wall -O2
LIBS = -lcryptopp
TARGET = cipher
SRC = cipher.cpp

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: clean
