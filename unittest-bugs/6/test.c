/* commit 8f6cff98477edbcd8ae4976734ba7edd07bdd244 */

/*
 * This test is about the wrong variable type declaration.
 */

#include "../fs.h"

typedef long long s64;

volatile struct inode ip;

int diRead(struct inode *ip)
{

#ifdef __PATCH__
	unsigned long pageno;
#else
	unsigned int pageno;
#endif

	s64 blkno = 1024;

	pageno = blkno >> 2;

	return 0;
}

int main(int argc, char *argv[])
{
	int v;
	v = diRead(&ip);
	return 0;
}
