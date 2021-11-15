// SPDX-License-Identifier: MIT
#ifndef ____FSS_H__
#define ____FSS_H__

#undef BUG
#undef BUG_ON
extern void BUG();
#define BUG_ON(condition) do { if (unlikely(condition)) BUG(); } while (0)

#endif /* ____FSS_H__ */
