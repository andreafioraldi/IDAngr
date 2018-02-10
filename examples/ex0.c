#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

void foobar(int a, int b) {
	int x = 1, y = 0;
	if (a != 0) {
		y = 3+x;
		if (b == 0)
			x = 2*(a+b);
	}
	assert(x-y != 0);
}

int main(int argc, char * argv[]) {
	
	if (argc != 3)
		return 1;

	int a = atoi(argv[1]);
	int b = atoi(argv[2]);
	foobar(a, b);
	//printf("%d %d\n", a, b);
	return 0;
}
