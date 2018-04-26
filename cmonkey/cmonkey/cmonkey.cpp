#include <iostream>
#include "include\curl\curl.h"

#define UNIQUEID "00"

void sendEmail(const std::string& text, const std::string& jobid = "", const std::string* attachmment = nullptr, bool checkin = false) {
	std::string sub_header = UNIQUEID;
	if (!jobid.empty())
		sub_header = std::string("dmp:") + UNIQUEID + ":" + jobid;
	else if (checkin)
		sub_header = std::string("hereiam:") + UNIQUEID;
	
}

int main() {
	std::cout << "Hello world!";
	std::cin.ignore();
	return 0;
}