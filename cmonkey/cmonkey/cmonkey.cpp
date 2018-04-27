#include <iostream>
#include "include\curl\curl.h"
#include "SystemInfo.h"

#define UNIQUEID SystemInfo::Instance().UniqueID()

void sendEmail(const std::string& text, const std::string& jobid = "", const std::string* attachmment = nullptr, bool checkin = false) {
	std::string sub_header = UNIQUEID;
	if (!jobid.empty())
		sub_header = std::string("dmp:") + UNIQUEID + ":" + jobid;
	else if (checkin)
		sub_header = std::string("hereiam:") + UNIQUEID;
	
}

int main() {
	std::cout << SystemInfo::Instance().UniqueID();
	std::cin.ignore();
	return 0;
}