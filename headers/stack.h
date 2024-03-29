
struct Ctx
{
    s32 tap_fd;
    u8 mac[MAC_SIZE];
    u32 ip;

    std::vector<u8> packet;
};

s32 read_packet(Ctx &ctx, u32 len);
s32 write_packet(Ctx &ctx, u32 len);

void handle_ip_packet(Ctx &ctx,EthHdr eth_hdr,const u8 *buf,u32 size);