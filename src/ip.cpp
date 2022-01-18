

void print_ip_packet(u8 version, u8 ihl,u8 dscp, u8 ecn, u16 len, u16 ident, u8 flags, u16 fragment_offset,
    u8 ttl, u8 proto, u16 checksum, u32 sip, u32 dip)
{
    printf("version %d\n",version);
    printf("ihl %d\n",ihl);
    printf("dscp %02x\n",dscp);
    printf("ecn %02x\n",ecn);
    printf("len %d\n",len);
    printf("ident %04x\n",ident);
    printf("flags %d\n",flags);
    printf("fragment offset %04x\n",fragment_offset);
    printf("ttl %d\n",ttl);
    printf("proto %02x\n",proto);
    printf("checksum %04x\n",checksum);
    printf("source ip:"); print_ip(sip);
    printf("dest ip:"); print_ip(dip);
}

void handle_ip_packet(Ctx &ctx, u32 size)
{
    UNUSED(size);

    puts("ip packet");

    const u8* pkt = &ctx.packet[ETH_HDR_SIZE];

    dump_buf(ctx.packet.data(),size);

    const u8 version = pkt[0] >> 4;
    const u8 ihl = pkt[0] & 0xf; 
    const u8 dscp = pkt[1] >> 2;
    const u8 ecn = pkt[1] & 0b11;
    const auto len = read_host<u16>(pkt,2);
    const auto ident = read_host<u16>(pkt,4);
    const u8 flags = read_host<u16>(pkt,6) >> 13;
    const u16 fragment_offset = read_host<u16>(pkt,6) & 0b1111111111111;
    const u8 ttl = pkt[8];
    const u8 proto = pkt[9];
    const u16 checksum = read_host<u16>(pkt,10);
    const u32 sip = read_host<u32>(pkt,12);
    const u32 dip = read_host<u32>(pkt,16);


    if(version != 4)
    {
        printf("unknown ip version %d\n",version);
        return;
    }

    print_ip_packet(version,ihl,dscp,ecn,len,ident,flags,fragment_offset,ttl,proto,checksum,sip,dip);


    const u16 checksum_actual = csum(pkt);
    printf("computed checksum: %04x\n",checksum_actual);

    // invalid checksum
    if(checksum_actual != checksum)
    {
        // TODO: this needs to actually be handled 
        printf("checksum %04x does not match %04x\n",checksum_actual,checksum);
        return;
    }

    switch(proto)
    {
        default: printf("unknown ip proto %02x\n",proto); break;
    }
}