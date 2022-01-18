

// https://datatracker.ietf.org/doc/html/rfc792
void print_icmp_hdr(u8 type, u8 code, u16 checksum)
{
    puts("icmp hdr:");
    printf("type %02x\n",type);
    printf("code %02x\n",code);
    printf("checksum %04x\n",checksum);
}


void print_echo_req(u16 ident, u16 seq)
{
    printf("echo req:\n");
    printf("ident: %04x\n",ident);
    printf("seq: %04x\n",seq);
}

// TODO: probably need more options but this is fine for now
void build_ip_packet(u8 *buf,u16 len, u8 proto, u32 dip, u32 sip)
{
    // ipv4,IHL 5
    buf[0]  = (4 << 4) | 5;
    // ecn,dscp default
    buf[1] = 0;
    write_network<u16>(buf,2,len);

    // ignore ident for now
    write_network<u16>(buf,4,0);

    // ignore flags + frag offset
    write_network<u16>(buf,6,0);

    // some default ttl for now
    buf[8] = 32;

    buf[9] = proto;

    write_network<u32>(buf,12,sip);
    write_network<u32>(buf,16,dip);

    const u16 checksum = csum(buf,IP_HDR_SIZE,10);
    write_network<u16>(buf,10,checksum);
}


void build_icmp_packet(u8 *buf,u32 ip_len,const u8 *dmac,const u8 *smac,u32 dip, u32 sip,u8 type, u8 code)
{
    build_eth_packet(buf,dmac,smac,PROTO_IP);
    buf += ETH_HDR_SIZE;

    build_ip_packet(buf,ip_len,IP_PROTO_ICMP,dip,sip);
    buf += IP_HDR_SIZE;

    buf[0] = type;
    buf[1] = code;
}


// TODO: this needs to be split into a build_icmp helper
void handle_echo_req(Ctx &ctx,IpPacket &ip_packet,const u8* buf, u32 size)
{
    // want to go up to the ident
    const u8 *pkt = &buf[ICMP_OFFSET + 4];
    const u16 ident = read_host<u16>(pkt,0);
    const u16 seq = read_host<u16>(pkt,2);

    print_echo_req(ident,seq);

    const auto &eth_hdr = ip_packet.eth_hdr;
    const auto &ip_hdr = ip_packet.ip_hdr;
    build_icmp_packet(&ctx.packet[0],size - ETH_HDR_SIZE,eth_hdr.smac,eth_hdr.dmac,ip_hdr.sip,ip_hdr.dip,ICMP_TYPE_REPLY,0);

    // write out echo req specific data
    u8 *echo_pkt = &ctx.packet[ICMP_OFFSET];

    write_network<u16>(echo_pkt,4,ident);
    write_network<u16>(echo_pkt,6,seq);


    const u16 checksum = csum(echo_pkt,size - ICMP_OFFSET,2);
    write_network<u16>(echo_pkt,2,checksum);

    //dump_buf(&ctx.packet[0],size);
    write_packet(ctx,size);
}

void handle_icmp_packet(Ctx &ctx,IpPacket &ip_packet,const u8* buf, u32 size)
{
    const u8 *pkt = &buf[ICMP_OFFSET];
    const u32 icmp_size = size - ICMP_OFFSET;

    const u8 type = pkt[0];
    const u8 code = pkt[1];
    const u16 checksum = read_host<u16>(pkt,2);

    print_icmp_hdr(type,code,checksum);

    // this csum needs to include data which we dont parse atm
    const u16 checksum_actual = csum(pkt,icmp_size,2);
    printf("computed checksum %04x\n",checksum_actual);

    // invalid checksum
    // TODO: this is busted
    if(checksum_actual != checksum)
    {
        // TODO: this needs to actually be handled 
        printf("checksum %04x does not match %04x\n",checksum_actual,checksum);
        return;
    }



    switch(type)
    {
        case ICMP_TYPE_ECHO:
        {
            handle_echo_req(ctx,ip_packet,buf,size);
            break;
        }

        default: printf("unhandled icmp type %02x\n",type); break;
    }

}


void parse_ip_packet(const u8 *pkt,IpHdr &hdr)
{
    hdr.version = pkt[0] >> 4;
    hdr.ihl = pkt[0] & 0xf; 
    hdr.dscp = pkt[1] >> 2;
    hdr.ecn = pkt[1] & 0b11;
    hdr.len = read_host<u16>(pkt,2);
    hdr.ident = read_host<u16>(pkt,4);
    hdr.flags = read_host<u16>(pkt,6) >> 13;
    hdr.fragment_offset = read_host<u16>(pkt,6) & 0b1111111111111;
    hdr.ttl = pkt[8];
    hdr.proto = pkt[9];
    hdr.checksum = read_host<u16>(pkt,10);
    hdr.sip = read_host<u32>(pkt,12);
    hdr.dip = read_host<u32>(pkt,16);
}

void print_ip_packet(const IpHdr &hdr)
{
    puts("ip header:");
    printf("version %d\n",hdr.version);
    printf("ihl %d\n",hdr.ihl);
    printf("dscp %02x\n",hdr.dscp);
    printf("ecn %02x\n",hdr.ecn);
    printf("len %d\n",hdr.len);
    printf("ident %04x\n",hdr.ident);
    printf("flags %d\n",hdr.flags);
    printf("fragment offset %04x\n",hdr.fragment_offset);
    printf("ttl %d\n",hdr.ttl);
    printf("proto %02x\n",hdr.proto);
    printf("checksum %04x\n",hdr.checksum);
    printf("source ip "); print_ip(hdr.sip);
    printf("dest ip "); print_ip(hdr.dip);
}



void handle_ip_packet(Ctx &ctx,EthHdr eth_hdr,const u8 *buf,u32 size)
{
    UNUSED(size);

    puts("ip packet");

    const u8* pkt = &buf[ETH_HDR_SIZE];

    IpHdr hdr; 
    parse_ip_packet(pkt,hdr);



    if(hdr.version != 4)
    {
        printf("unknown ip version %d\n",hdr.version);
        return;
    }

    print_ip_packet(hdr);


    const u16 checksum_actual = csum(pkt,IP_HDR_SIZE,10);
    printf("computed checksum: %04x\n",checksum_actual);

    // invalid checksum
    if(checksum_actual != hdr.checksum)
    {
        // TODO: this needs to actually be handled 
        printf("checksum %04x does not match %04x\n",checksum_actual,hdr.checksum);
        return;
    }

    IpPacket ip_packet;
    ip_packet.eth_hdr = eth_hdr;
    ip_packet.ip_hdr = hdr;

    switch(hdr.proto)
    {
        case IP_PROTO_ICMP:
        {
            handle_icmp_packet(ctx,ip_packet,buf,size);
            break;
        }

        default: printf("unknown ip proto %02x\n",hdr.proto); break;
    }
}