
#include <xdk.h>

#ifdef _OS_WINDOWS
#include <conio.h>
#endif





int main(int argc, char* argv[])
{
	xdk_process_init(XDK_APARTMENT_PROCESS);

	//ac_tableself_test();

	//bina_treeself_test();

	//trie_treeself_test();

	//hash_tableself_test();

	//dict_tableself_test();

	//words_tableself_test();

	//string_tableself_test();

	//file_tableself_test();

	//bplus_tree_self_test();

	bplus_tree_self_test();

	xdk_process_uninit();

	return 0;
}

