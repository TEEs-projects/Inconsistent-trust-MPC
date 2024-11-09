#include <string>
#include <iostream>
#ifdef NTEE
#include <ctime>
#endif
using namespace std;

void log_info(string msg) {
#ifdef NTEE
	time_t now = time(NULL);
	tm *p_tm = localtime(&now);
	printf("INFO %d:%d:%d: %s\n", p_tm->tm_hour, p_tm->tm_min, p_tm->tm_sec, msg.c_str());
#endif
}
