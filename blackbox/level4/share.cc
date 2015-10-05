#include <iostream>
#include <fstream>
#include <string>


std::string strreplace(const char *msg, const char *replace, const char *with)
{
	std::string ret;

	while(*msg) {
		if(strncmp(msg, replace, strlen(replace)) == 0) {
			ret += with;

			// Skip all in msg until we have another match
			msg++;
			for(unsigned int i = 1; i < strlen(replace) && *msg; i++) {
				if(strncmp(msg, replace, strlen(replace)) == 0)
					break;
				msg++;
			}

			continue;
		} else
			ret += *msg;
		msg++;
	}

	return ret;
}

int main(int argc, char **argv)
{
	if(argc < 2) {
		std::cout << "This program allows you to read files from my shared files. See /usr/share/level5 for my shared files. Simply use the path relative to my shared files to read a file!" << std::endl;
		std::cout << "Example: " << argv[0] << " lyrics/foreverautumn" << std::endl;
		return 1;
	}

	std::string start_path = "/usr/share/level5/";
	std::string relative_path = "";
	char *ptr;

	ptr = argv[1];
	while(*ptr == '/' || *ptr == '.')
		ptr++;

	relative_path = strreplace(ptr, "/../", "");
	relative_path = strreplace(relative_path.c_str(), "/./", "");

	std::string realpath = start_path + relative_path;

	std::cout << "Contents of " << realpath << ":" << std::endl;

	std::ifstream file(realpath.c_str(), std::ios::in);
	if(!file.is_open()) {
		std::cerr << "Unable to open file" << std::endl;
		return 1;
	}

	std::string cline;

	while(!file.eof()) {
		std::getline(file, cline);
		std::cout << cline << std::endl;
	}

	return 0;
}