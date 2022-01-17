void init_tap(Ctx &ctx)
{
    read_tap_hwinfo(ctx);

    ctx.packet.resize(MAX_PACKET_SIZE);
    ctx.tap_fd = tap_alloc();

    if(!ctx.tap_fd)
    {
        perror_panic("could not get tap");
    }



    printf("tap mac:\n");
    print_mac(ctx.mac);
}


s32 read_packet(Ctx &ctx, u32 len)
{
    return tap_read(ctx.packet.data(),len,ctx.tap_fd);
}

s32 write_packet(Ctx &ctx, u32 len)
{
    return tap_write(ctx.packet.data(),len,ctx.tap_fd);
}


void handle_packet(Ctx &ctx, u32 size)
{
    handle_eth_header(ctx, size);
}

void dump_packet(Ctx &ctx, u32 size)
{
    printf("tap read %x\n",size);

    printf("packet\n");
    dump_buf(&ctx.packet[0],size);
    putchar('\n');    
}

// for now just blindly read packets
void handle_packets(Ctx &ctx)
{
    s32 size = read_packet(ctx,ctx.packet.size());

    if(size < 0)
    {
        perror_panic("could not read from tap");
    }

    //dump_packet(ctx,size);

    handle_packet(ctx,size);
}