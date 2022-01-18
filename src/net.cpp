

void print_mac(const u8 *mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
        mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void read_mac(u8 *buf,const std::vector<u8> &packet, u32 offset)
{
    memcpy(buf,&packet[offset],MAC_SIZE);
}

void read_mac(u8 *buf, const u8 *packet, u32 offset)
{
    memcpy(buf,&packet[offset],MAC_SIZE);
}

void print_ip(u32 ip)
{
    const u8 *buf = (u8*)&ip;

    printf("%d.%d.%d.%d\n",buf[3],buf[2],buf[1],buf[0]);
}

// TODO: this wont handle a odd len
u16 csum(const u8 *buf, u32 len,u32 ignore)
{
    if(len & 1)
    {
        assert(false);
    }

    u16 v = 0;

    for(u32 i = 0; i < len; i += 2)
    {
        // ignore the csum allready there
        if(i == ignore)
        {
            continue;
        }

        u16 x = read_host<u16>(buf,i);

        u32 carry = (u32(v) + u32(x)) > 0xffff;

        v += x;
        v += carry;
    }

    return ~v;
}