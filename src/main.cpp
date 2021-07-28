#include "elf2dll.hpp"

int main(int argc, const char* argv[])
{
	if (argc < 3)
	{
		cerr << "Usage: " << argv[0] << " <input-elf> <output-dll>" << endl;
		return 1;
	}

	dino_dll dll;
	return dll.build(argv[1], argv[2]);
}
