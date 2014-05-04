#include "global.h"
#ifdef MD4
#define	MDXFinal	MD4Final
#define	MDXInit		MD4Init
#define	MDXUpdate	MD4Update
#define	MDX_CTX		MD4_CTX
#include "md4.h"
#endif
#ifdef MD5
#define	MDXFinal	MD5Final
#define	MDXInit		MD5Init
#define	MDXUpdate	MD5Update
#define	MDX_CTX		MD5_CTX
#include "md5.h"
#endif
