#include <iostream>
#include <string>

int main(int main, char **argv)
{
	std::string command;
	std::string program;

	std::cout << "Enter the name of the program: ";
	std::cin >> program;

	for(unsigned int i = 0; i < program.length(); i++) {
		if(strchr(";^&|><", program[i]) != NULL) {
			std::cout << "Fatal error" << std::endl;
			return 1;
		}
	}


	// Execute the command to list the programs
	command = "/bin/ps |grep ";
	command += program;
	system(command.c_str());

	return 0;
}