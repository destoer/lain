void print_eth_header(const EthHdr &hdr)
{
    puts("dst mac:");
    print_mac(hdr.dmac);

    puts("src mac:");
    print_mac(hdr.smac);

    printf("type: %04x\n",hdr.type);
}

void print_arp_packet(u16 htype, u16 ptype, u8 hlen, u8 plen, u16 opcode, const u8 *smac, u32 sip, const u8 *dmac, u32 dip)
{
    printf("htype: %04x\n",htype);
    printf("ptype: %04x\n",ptype);
    printf("hlen: %02x\n",hlen);
    printf("plen: %02x\n",plen);
    printf("opcode: %04x\n",opcode);
    printf("source mac: "); print_mac(smac);
    printf("source ip: "); print_ip(sip);
    printf("dest mac: "); print_mac(dmac);
    printf("dest ip: "); print_ip(dip);    
}


void build_eth_packet(u8 *buf,const u8 *dmac, const u8 *smac, u16 type)
{
    memcpy(&buf[0],dmac,MAC_SIZE);
    memcpy(&buf[MAC_SIZE],smac,MAC_SIZE);
    write_network<u16>(buf,12,type);
}

void build_arp_packet(u8 *buf,u16 htype, u16 ptype, u8 hlen, u8 plen, u16 opcode, const u8 *smac, u32 sip, const u8 *dmac, u32 dip)
{
    write_network(buf,0,htype);
    write_network(buf,2,ptype);
    buf[4] = hlen;
    buf[5] = plen;
    write_network(buf,6,opcode);
    memcpy(&buf[8],smac,MAC_SIZE);
    write_network(buf,14,sip);
    memcpy(&buf[18],dmac,MAC_SIZE);
    write_network(buf,24,dip);
}

void build_arp_reply(u8 *buf,const u8 *dmac,u32 dip, const u8 *smac, u32 sip)
{
    // write eth header
    build_eth_packet(buf,dmac,smac,PROTO_ARP);

    // write arp header
    build_arp_packet(&buf[ETH_HDR_SIZE],HTYPE_ETH,PTYPE_IP,MAC_SIZE,IP_SIZE,ARP_REPLY,smac,sip,dmac,dip);
}

void build_arp_request(u8 *buf,u32 dip, const u8 *smac,  u32 sip)
{
    // ask everyone
    u8 dmac[MAC_SIZE];
    fill_byte(dmac,0Xff,sizeof(dmac));

    // write eth header
    build_eth_packet(buf,dmac,smac,PROTO_ARP);

    zero_mem(dmac,sizeof(dmac));

    // write arp header
    build_arp_packet(&buf[ETH_HDR_SIZE],HTYPE_ETH,PTYPE_IP,MAC_SIZE,IP_SIZE,ARP_REQ,smac,sip,dmac,dip);
}


void handle_arp_packet(Ctx &ctx)
{
    //puts("arp packet");


    // print out the arp packet
    const u8 *arp_req = &ctx.packet[ETH_HDR_SIZE];

    const auto htype = read_host<u16>(arp_req,0);
    const auto ptype = read_host<u16>(arp_req,2);
    const u8 hlen = arp_req[4];
    const u8 plen = arp_req[5];
    const u16 opcode = read_host<u16>(arp_req,6);
    u8 smac[MAC_SIZE]; read_mac(smac,arp_req,8);
    const u32 sip = read_host<u32>(arp_req,14);
    u8 dmac[MAC_SIZE]; read_mac(dmac,arp_req,18);
    const u32 dip = read_host<u32>(arp_req,24);

    UNUSED(htype); UNUSED(ptype); UNUSED(hlen); UNUSED(plen); UNUSED(opcode); 
    UNUSED(opcode);UNUSED(smac); UNUSED(sip); UNUSED(dmac); UNUSED(dip);

    // dont handle this atm
    if(ptype != PTYPE_IP)
    {
        printf("non ip arp packet ignored");
    }

    //print_arp_packet(htype,ptype,hlen,plen,opcode,smac,sip,dmac,dip);

    if(opcode == ARP_REQ)
    {
/*    
        printf("replying to arp req from:\n"); 
        print_ip(sip); print_mac(smac);
        printf("reply:\n");
        print_ip(ctx.ip); print_mac(ctx.mac);
*/  

        build_arp_reply(ctx.packet.data(),smac,sip,ctx.mac,ctx.ip);
        //build_arp_reply(ctx.packet.data(),smac,sip,ctx.mac,dip);

        //dump_buf(ctx.packet.data(),ETH_HDR_SIZE + ARP_HDR_SIZE);

        s32 size = write_packet(ctx,ETH_HDR_SIZE + ARP_HDR_SIZE);


        if(size < 0)
        {
            perror_panic("could not write to tun");
        }

    }

    // this is a reply and we aint interested in these atm
    else
    {
        printf("arp reply!");
        exit(1);
    }
}

void parse_eth_header(const u8 *buf,EthHdr &hdr)
{
    // rip hdr
    read_mac(hdr.smac,buf,0);
    read_mac(hdr.dmac,buf,6);
    hdr.type = read_host<u16>(buf,12);
}

void handle_eth_header(Ctx &ctx, u32 size)
{
    EthHdr hdr;
    parse_eth_header(ctx.packet.data(),hdr);

    // okay what protocol are we dealing with
    switch(hdr.type)
    {
        case PROTO_ARP:
        {
            //print_eth_header(hdr);
            handle_arp_packet(ctx);
            break;
        }

        case PTYPE_IP:
        {
            handle_ip_packet(ctx,size);
            break;
        }

        default: 
        {
            printf("unhandled eth req %04x\n",hdr.type);
            break;
        }
    }
}