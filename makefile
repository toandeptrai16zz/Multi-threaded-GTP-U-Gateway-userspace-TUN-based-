CXX      ?= g++
CXXFLAGS ?= -std=c++11 -Wall -Wextra -Wuninitialized -g -O2

all: gateway test_gtpu

gateway: gateway.cpp gtpu_encap.cpp gtpu_encap.h
	$(CXX) $(CXXFLAGS) gateway.cpp gtpu_encap.cpp -o gateway

# Test chay voi AddressSanitizer + UBSan, khong can root
test_gtpu: test_gtpu.cpp gtpu_encap.cpp gtpu_encap.h
	$(CXX) $(CXXFLAGS) -O0 -fsanitize=address,undefined test_gtpu.cpp gtpu_encap.cpp -o test_gtpu

test: test_gtpu
	./test_gtpu

clean:
	rm -f gateway test_gtpu

.PHONY: all test clean