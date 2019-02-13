CFLAGS += -g
ifeq ($(V), 1)
CFLAGS += -DWLDB_LOG_STDIO
endif
GTEST_DIR = googletest/googletest
LIBGTEST = libgtest.a
INCLUDES = -isystem $(GTEST_DIR)/include -I$(GTEST_DIR)
ALL_TESTS = $(patsubst %.test.cpp,%,$(wildcard *.test.cpp))

WLDB_DIR = ../src
WLDB_SOURCES = $(WLDB_DIR)/wldb.c
WLDB_CFLAGS = -I../include

all: $(ALL_TESTS)

$(LIBGTEST):
	$(CXX) -std=c++11 $(INCLUDES) -pthread \
	    $(CFLAGS) -c $(GTEST_DIR)/src/gtest-all.cc
	$(AR) -rv $@ gtest-all.o

%.test: %.test.cpp $(WLDB_SOURCES) $(LIBGTEST)
	$(CXX) -std=c++11 $(INCLUDES) $(CFLAGS) $(WLDB_CFLAGS) \
	    $(shell grep "^//CFLAGS:" $< |cut -d: -f 2) \
	    -o $@ $< $(WLDB_SOURCES) \
	    gtest-main.cpp $(LIBGTEST)

%: %.test
ifneq ($(TEST_FILTER),)
	./$< --gtest_filter=$(TEST_FILTER)
else
	./$<
endif


clean:
	$(RM) -r *.dSYM *.a *.o *.test
