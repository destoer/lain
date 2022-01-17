#include <lib.h>
#include <net.h>
#include <stack.h>

// unity build
#include <lib.cpp>
#include <net.cpp>
#include <linux.cpp>
#include <eth.cpp>
#include <ctx.cpp>

int main()
{
	puts("starting...");


	// first thing is to get a tap device to write our data into
	Ctx ctx;
	init_tap(ctx);


	// dunno what this should look like yet
	for(;;)
	{
		handle_packets(ctx);
	}
}
