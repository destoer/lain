
// taken from https://www.saminiir.com/lets-code-tcp-ip-stack-1-ethernet-arp/#tuntap-devices
s32 tap_alloc()
{
    char dev[IFNAMSIZ] = "tun6996";

    struct ifreq ifr;
    s32 fd, err;

    if ( (fd = open("/dev/net/tun",O_RDWR)) < 0)
    {
        perror_panic("cannot open tap");
    }

    memset(&ifr,0,sizeof(ifr));

    // we want a raw tap
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    if(*dev)
    {
        strncpy(ifr.ifr_name,dev,IFNAMSIZ);
    }

    if( (err = ioctl(fd,TUNSETIFF,(void*)&ifr)) < 0)
    {
        close(fd);
        perror_panic("cannot open tap");
    }

    strcpy(dev,ifr.ifr_name);
    printf("opened tap %s:%d\n",dev,fd);
    return fd;
}

// this may be overkill idk

// https://man7.org/linux/man-pages/man7/packet.7.html
// https://man7.org/linux/man-pages/man3/getifaddrs.3.html

void read_tap_hwinfo(Ctx &ctx)
{
    struct ifaddrs *ifaddr;

    if(getifaddrs(&ifaddr) == -1)
    {
        perror_panic("getifaddrs failed");
    }

    
    for(struct ifaddrs *cur = ifaddr; cur != NULL; cur = cur->ifa_next)
    {
        // ignore the loopback interface
        if(strcmp(cur->ifa_name,"tun6996") != 0)
        {
            continue;
        }

        
       


        switch(cur->ifa_addr->sa_family)
        {
            case AF_PACKET:
            {
                printf("name %s\n",cur->ifa_name);
                
                // read our the host macc
                struct sockaddr_ll *sll = (struct sockaddr_ll*)cur->ifa_addr;
            
                // if the family is AF_PACKET then the sockaddr_ll struct will have what we want
                memcpy(ctx.mac,sll->sll_addr,MAC_SIZE);
                break;    
            }

            case AF_INET:
            {
                // read out the host ip
                struct sockaddr_in *sin = (struct sockaddr_in*)cur->ifa_addr;
                // we are just doing our remote address as + 1 to a local for now to make life easy...
                // https://unix.stackexchange.com/questions/588938/how-to-relay-traffic-from-tun-to-internet
                // think about the best way to hook this up

                ctx.ip = bswap(sin->sin_addr.s_addr) + 1;
                printf("ip %08x\n",ctx.ip);
                break;
            }

            default: break;
        }

    }

    freeifaddrs(ifaddr);
}

s32 tap_read(u8 *buf,u32 len,s32 fd)
{
    return read(fd,buf,len);
}

s32 tap_write(const u8* buf,u32 len, s32 fd)
{
    return write(fd,buf,len);
}