// SPDX-License-Identifier: MIT
#ifdef PROC
#undef PROC
#endif

#ifdef AT
#undef AT
#endif

#ifdef FH
#undef FH
#endif

#ifdef nfsd3_attrstatres
#undef nfsd3_attrstatres
#endif

#ifdef nfsd3_voidres
#undef nfsd3_voidres
#endif

#ifdef nfsd3_voidargs
#undef nfsd3_voidargs
#endif

#define NFSDBG_FACILITY NFSDBG_PNFS_LD
#define NFSDDBG_FACILITY NFSDDBG_PNFS
#define NLMDBG_FACILITY NLMDBG_XDR

#ifndef __NFSD_FFS__
  struct nfsd3_voidargs { int dummy; };
#define __NFSD_FFS__
#endif
