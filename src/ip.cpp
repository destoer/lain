

void handle_ip_packet(Ctx &ctx, u32 size)
{
    puts("ip packet");

    const u8* pkt = &ctx.packet[ETH_HDR_SIZE];

    dump_buf(pkt,size);    
}