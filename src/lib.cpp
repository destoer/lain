
void dump_buf(const u8 *buf, u32 len)
{
    for(u32 i = 0; i < len; i++)
    {
        if(i % 16 == 0 && i != 0)
        {
            putchar('\n');
        }

        printf("%02x ",buf[i]);
    }

    putchar('\n');

}