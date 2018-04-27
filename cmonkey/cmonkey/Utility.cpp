#include <string>
#include <vector>
#include <sstream>
#include <iterator>
#include "Utility.h"


std::string Utility::Join(const std::vector<std::string>& elements, const char& separator)
{
	switch (elements.size())
	{
	case 0:
		return "";
	case 1:
		return elements[0];
	default:
		std::ostringstream os;
		std::vector<std::string>::const_iterator it = elements.begin();
		while (it != elements.end() - 1)
		{
			os << *it << separator;
			++it;
		}
		os << *elements.rbegin();
		return os.str();
	}
}

Utility::Utility()
{
}


Utility::~Utility()
{
}
