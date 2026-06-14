#include <xdk.h>
#include <xdg.h>
#include <xdu.h>


int main(int argc, const char * argv[]) {

    xdk_process_init(XDK_APARTMENT_PROCESS);

    xdu_process_init();

	test_wayland();

    xdu_process_uninit();
    
    xdk_process_uninit();

    return 0;
}
