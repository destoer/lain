#include <lib.h>
#include <net.h>
#include <stack.h>

// unity build
#include <lib.cpp>
#include <net.cpp>
#include <linux.cpp>
#include <eth.cpp>
#include <ip.cpp>
#include <ctx.cpp>

int main()
{
	puts("starting...");


	// first thing is to get a tap device to write our data into
	Ctx ctx;
	init_tap(ctx);


	build_arp_request(ctx.packet.data(),0x0A000001,ctx.mac,ctx.ip);

	s32 size = write_packet(ctx,ETH_HDR_SIZE + ARP_HDR_SIZE);

	if(size < 0)
	{
		perror_panic("could not write to tun");
	}	

	// dunno what this should look like yet
	for(;;)
	{
		handle_packets(ctx);
	}
}
