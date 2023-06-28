CXX = g++ -fPIC
NETLIBS= -pthread

all: myhttpd

myhttpd : myhttpd.o
	$(CXX) -o $@ $@.o $(NETLIBS)