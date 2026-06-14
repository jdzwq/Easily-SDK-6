
#include <xdk.h>
#include <xdu.h>
/*
void test_blut()
{
    if_blut_t if_blut = { 0 };
    
    xdu_impl_blut(&if_blut);

	if_socket_t if_sock = { 0 };

	xdk_impl_socket(&if_sock);

	(*if_sock.pf_socket_startup)();

    int n = (*if_blut.pf_enum_blut)(NULL, MAX_LONG);

    dev_blt_t* pdb = (dev_blt_t*)calloc(n, sizeof(dev_blt_t));

    (*if_blut.pf_enum_blut)(pdb, n);

    async_t asy = {0};
    asy.type = ASYNC_BLOCK;
    asy.timo = INFINITE;

    byte_t ch[1];
    for(int i = 0;i<n;i++)
    {
        printf("%s %s %s %s \n", pdb[i].addr, pdb[i].name, pdb[i].major_class, pdb[i].minor_class);

        res_file_t fd = (*if_blut.pf_blut_open)(pdb[i].addr, 0, 0);
        if(fd != INVALID_FILE)
        {
            (*if_blut.pf_blut_read)(fd, &ch, 1, &asy);
            (*if_blut.pf_blut_close)(fd);
        }
    }

    free(pdb);

	(*if_sock.pf_socket_cleanup)();
}
*/

#ifdef _OS_WINDOWS
#pragma comment( linker, "/subsystem:windows /entry:mainCRTStartup" )
#endif

int main(int argc, const char * argv[]) {

    xdk_process_init(XDK_APARTMENT_PROCESS);

	//test_blut();

    xdk_process_uninit();

    return 0;
}
