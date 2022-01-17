

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