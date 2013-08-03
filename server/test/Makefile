all: ffbuffer_test helper_test

ffbuffer_test: ffbuffer_test.cpp ../ffbuffer.cpp ../ffbuffer.h
	g++ -O2 ffbuffer_test.cpp ../ffbuffer.cpp -o ffbuffer_test

helper_test: helper_test.cpp ../helper.cpp ../helper.h
	g++ -O2 helper_test.cpp ../helper.cpp -o helper_test

clean:
	rm -f ffbuffer_test helper_test
