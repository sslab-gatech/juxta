/* nommu.c: mmu-less memory info files
 *
 * Copyright (C) 2004 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/mman.h>
#include <linux/proc_fs.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/smp.h>
#include <linux/seq_file.h>
#include <linux/hugetlb.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/tlb.h>
#include <asm/div64.h>
#include "internal.h"

/*
 * display a single region to a sequenced file
 */
static int nommu_region_show(struct seq_file *m, struct vm_region *region)
{
	unsigned long ino = 0;
	struct file *file;
	dev_t dev = 0;
	int flags;

	flags = region->vm_flags;
	file = region->vm_file;

	if (file) {
		struct inode *inode = file_inode(region->vm_file);
		dev = inode->i_sb->s_dev;
		ino = inode->i_ino;
	}

	seq_setwidth(m, 25 + sizeof(void *) * 6 - 1);
	seq_printf(m,
		   "%08lx-%08lx %c%c%c%c %08llx %02x:%02x %lu ",
		   region->vm_start,
		   region->vm_end,
		   flags & VM_READ ? 'r' : '-',
		   flags & VM_WRITE ? 'w' : '-',
		   flags & VM_EXEC ? 'x' : '-',
		   flags & VM_MAYSHARE ? flags & VM_SHARED ? 'S' : 's' : 'p',
		   ((loff_t)region->vm_pgoff) << PAGE_SHIFT,
		   MAJOR(dev), MINOR(dev), ino);

	if (file) {
		seq_pad(m, ' ');
		seq_path(m, &file->f_path, "");
	}

	seq_putc(m, '\n');
	return 0;
}

/*
 * display a list of all the REGIONs the kernel knows about
 * - nommu kernels have a single flat list
 */
static int nommu_region_list_show(struct seq_file *m, void *_p)
{
	struct rb_node *p = _p;

	return nommu_region_show(m, rb_entry(p, struct vm_region, vm_rb));
}

static void *nommu_region_list_start(struct seq_file *m, loff_t *_pos)
{
	struct rb_node *p;
	loff_t pos = *_pos;

	down_read(&nommu_region_sem);

	for (p = rb_first(&nommu_region_tree); p; p = rb_next(p))
		if (pos-- == 0)
			return p;
	return NULL;
}

static void nommu_region_list_stop(struct seq_file *m, void *v)
{
	up_read(&nommu_region_sem);
}

static void *nommu_region_list_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;
	return rb_next((struct rb_node *) v);
}

static const struct seq_operations proc_nommu_region_list_seqop = {
	.start	= nommu_region_list_start,
	.next	= nommu_region_list_next,
	.stop	= nommu_region_list_stop,
	.show	= nommu_region_list_show
};

static int proc_nommu_region_list_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &proc_nommu_region_list_seqop);
}

static const struct file_operations proc_nommu_region_list_operations = {
	.open    = proc_nommu_region_list_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

static int __init proc_nommu_init(void)
{
	proc_create("maps", S_IRUGO, NULL, &proc_nommu_region_list_operations);
	return 0;
}

fs_initcall(proc_nommu_init);
/************************************************************/
/* ../linux-3.17/fs/proc/nommu.c */
/************************************************************/
// #include <linux/mm.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
// #include <linux/seq_file.h>
// #include "internal.h"

/*
 * Logic: we've got two memory sums for each process, "shared", and
 * "non-shared". Shared memory may get counted more than once, for
 * each process that owns it. Non-shared memory is counted
 * accurately.
 */
void task_mem(struct seq_file *m, struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	struct vm_region *region;
	struct rb_node *p;
	unsigned long bytes = 0, sbytes = 0, slack = 0, size;

	down_read(&mm->mmap_sem);
	for (p = rb_first(&mm->mm_rb); p; p = rb_next(p)) {
		vma = rb_entry(p, struct vm_area_struct, vm_rb);

		bytes += kobjsize(vma);

		region = vma->vm_region;
		if (region) {
			size = kobjsize(region);
			size += region->vm_end - region->vm_start;
		} else {
			size = vma->vm_end - vma->vm_start;
		}

		if (atomic_read(&mm->mm_count) > 1 ||
		    vma->vm_flags & VM_MAYSHARE) {
			sbytes += size;
		} else {
			bytes += size;
			if (region)
				slack = region->vm_end - vma->vm_end;
		}
	}

	if (atomic_read(&mm->mm_count) > 1)
		sbytes += kobjsize(mm);
	else
		bytes += kobjsize(mm);

	if (current->fs && current->fs->users > 1)
		sbytes += kobjsize(current->fs);
	else
		bytes += kobjsize(current->fs);

	if (current->files && atomic_read(&current->files->count) > 1)
		sbytes += kobjsize(current->files);
	else
		bytes += kobjsize(current->files);

	if (current->sighand && atomic_read(&current->sighand->count) > 1)
		sbytes += kobjsize(current->sighand);
	else
		bytes += kobjsize(current->sighand);

	bytes += kobjsize(current); /* includes kernel stack */

	seq_printf(m,
		"Mem:\t%8lu bytes\n"
		"Slack:\t%8lu bytes\n"
		"Shared:\t%8lu bytes\n",
		bytes, slack, sbytes);

	up_read(&mm->mmap_sem);
}

unsigned long task_vsize(struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	struct rb_node *p;
	unsigned long vsize = 0;

	down_read(&mm->mmap_sem);
	for (p = rb_first(&mm->mm_rb); p; p = rb_next(p)) {
		vma = rb_entry(p, struct vm_area_struct, vm_rb);
		vsize += vma->vm_end - vma->vm_start;
	}
	up_read(&mm->mmap_sem);
	return vsize;
}

unsigned long task_statm(struct mm_struct *mm,
			 unsigned long *shared, unsigned long *text,
			 unsigned long *data, unsigned long *resident)
{
	struct vm_area_struct *vma;
	struct vm_region *region;
	struct rb_node *p;
	unsigned long size = kobjsize(mm);

	down_read(&mm->mmap_sem);
	for (p = rb_first(&mm->mm_rb); p; p = rb_next(p)) {
		vma = rb_entry(p, struct vm_area_struct, vm_rb);
		size += kobjsize(vma);
		region = vma->vm_region;
		if (region) {
			size += kobjsize(region);
			size += region->vm_end - region->vm_start;
		}
	}

	*text = (PAGE_ALIGN(mm->end_code) - (mm->start_code & PAGE_MASK))
		>> PAGE_SHIFT;
	*data = (PAGE_ALIGN(mm->start_stack) - (mm->start_data & PAGE_MASK))
		>> PAGE_SHIFT;
	up_read(&mm->mmap_sem);
	size >>= PAGE_SHIFT;
	size += *text + *data;
	*resident = size;
	return size;
}

/*
 * display a single VMA to a sequenced file
 */
static int nommu_vma_show(struct seq_file *m, struct vm_area_struct *vma,
			  int is_pid)
{
	struct mm_struct *mm = vma->vm_mm;
	struct proc_maps_private *priv = m->private;
	unsigned long ino = 0;
	struct file *file;
	dev_t dev = 0;
	int flags;
	unsigned long long pgoff = 0;

	flags = vma->vm_flags;
	file = vma->vm_file;

	if (file) {
		struct inode *inode = file_inode(vma->vm_file);
		dev = inode->i_sb->s_dev;
		ino = inode->i_ino;
		pgoff = (loff_t)vma->vm_pgoff << PAGE_SHIFT;
	}

	seq_setwidth(m, 25 + sizeof(void *) * 6 - 1);
	seq_printf(m,
		   "%08lx-%08lx %c%c%c%c %08llx %02x:%02x %lu ",
		   vma->vm_start,
		   vma->vm_end,
		   flags & VM_READ ? 'r' : '-',
		   flags & VM_WRITE ? 'w' : '-',
		   flags & VM_EXEC ? 'x' : '-',
		   flags & VM_MAYSHARE ? flags & VM_SHARED ? 'S' : 's' : 'p',
		   pgoff,
		   MAJOR(dev), MINOR(dev), ino);

	if (file) {
		seq_pad(m, ' ');
		seq_path(m, &file->f_path, "");
	} else if (mm) {
		pid_t tid = vm_is_stack(priv->task, vma, is_pid);

		if (tid != 0) {
			seq_pad(m, ' ');
			/*
			 * Thread stack in /proc/PID/task/TID/maps or
			 * the main process stack.
			 */
			if (!is_pid || (vma->vm_start <= mm->start_stack &&
			    vma->vm_end >= mm->start_stack))
				seq_printf(m, "[stack]");
			else
				seq_printf(m, "[stack:%d]", tid);
		}
	}

	seq_putc(m, '\n');
	return 0;
}

/*
 * display mapping lines for a particular process's /proc/pid/maps
 */
static int show_map(struct seq_file *m, void *_p, int is_pid)
{
	struct rb_node *p = _p;

	return nommu_vma_show(m, rb_entry(p, struct vm_area_struct, vm_rb),
			      is_pid);
}

static int show_pid_map(struct seq_file *m, void *_p)
{
	return show_map(m, _p, 1);
}

static int show_tid_map(struct seq_file *m, void *_p)
{
	return show_map(m, _p, 0);
}

static void *m_start(struct seq_file *m, loff_t *pos)
{
	struct proc_maps_private *priv = m->private;
	struct mm_struct *mm;
	struct rb_node *p;
	loff_t n = *pos;

	/* pin the task and mm whilst we play with them */
	priv->task = get_pid_task(priv->pid, PIDTYPE_PID);
	if (!priv->task)
		return ERR_PTR(-ESRCH);

	mm = mm_access(priv->task, PTRACE_MODE_READ);
	if (!mm || IS_ERR(mm)) {
		put_task_struct(priv->task);
		priv->task = NULL;
		return mm;
	}
	down_read(&mm->mmap_sem);

	/* start from the Nth VMA */
	for (p = rb_first(&mm->mm_rb); p; p = rb_next(p))
		if (n-- == 0)
			return p;
	return NULL;
}

static void m_stop(struct seq_file *m, void *_vml)
{
	struct proc_maps_private *priv = m->private;

	if (priv->task) {
		struct mm_struct *mm = priv->task->mm;
		up_read(&mm->mmap_sem);
		mmput(mm);
		put_task_struct(priv->task);
	}
}

static void *m_next(struct seq_file *m, void *_p, loff_t *pos)
{
	struct rb_node *p = _p;

	(*pos)++;
	return p ? rb_next(p) : NULL;
}

static const struct seq_operations proc_pid_maps_ops = {
	.start	= m_start,
	.next	= m_next,
	.stop	= m_stop,
	.show	= show_pid_map
};

static const struct seq_operations proc_tid_maps_ops = {
	.start	= m_start,
	.next	= m_next,
	.stop	= m_stop,
	.show	= show_tid_map
};

static int maps_open(struct inode *inode, struct file *file,
		     const struct seq_operations *ops)
{
	struct proc_maps_private *priv;
	int ret = -ENOMEM;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (priv) {
		priv->pid = proc_pid(inode);
		ret = seq_open(file, ops);
		if (!ret) {
			struct seq_file *m = file->private_data;
			m->private = priv;
		} else {
			kfree(priv);
		}
	}
	return ret;
}

static int pid_maps_open(struct inode *inode, struct file *file)
{
	return maps_open(inode, file, &proc_pid_maps_ops);
}

static int tid_maps_open(struct inode *inode, struct file *file)
{
	return maps_open(inode, file, &proc_tid_maps_ops);
}

const struct file_operations proc_pid_maps_operations = {
	.open		= pid_maps_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release_private,
};

const struct file_operations proc_tid_maps_operations = {
	.open		= tid_maps_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release_private,
};
/************************************************************/
/* ../linux-3.17/fs/proc/task_nommu.c */
/************************************************************/
// #include <linux/mm.h>
#include <linux/vmacache.h>
// #include <linux/hugetlb.h>
#include <linux/huge_mm.h>
// #include <linux/mount.h>
// #include <linux/seq_file.h>
#include <linux/highmem.h>
// #include <linux/ptrace.h>
// #include <linux/slab.h>
// #include <linux/pagemap.h>
#include <linux/mempolicy.h>
#include <linux/rmap.h>
// #include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/mmu_notifier.h>

#include <asm/elf.h>
// #include <asm/uaccess.h>
#include <asm/tlbflush.h>
// #include "internal.h"

void task_mem(struct seq_file *m, struct mm_struct *mm)
{
	unsigned long data, text, lib, swap;
	unsigned long hiwater_vm, total_vm, hiwater_rss, total_rss;

	/*
	 * Note: to minimize their overhead, mm maintains hiwater_vm and
	 * hiwater_rss only when about to *lower* total_vm or rss.  Any
	 * collector of these hiwater stats must therefore get total_vm
	 * and rss too, which will usually be the higher.  Barriers? not
	 * worth the effort, such snapshots can always be inconsistent.
	 */
	hiwater_vm = total_vm = mm->total_vm;
	if (hiwater_vm < mm->hiwater_vm)
		hiwater_vm = mm->hiwater_vm;
	hiwater_rss = total_rss = get_mm_rss(mm);
	if (hiwater_rss < mm->hiwater_rss)
		hiwater_rss = mm->hiwater_rss;

	data = mm->total_vm - mm->shared_vm - mm->stack_vm;
	text = (PAGE_ALIGN(mm->end_code) - (mm->start_code & PAGE_MASK)) >> 10;
	lib = (mm->exec_vm << (PAGE_SHIFT-10)) - text;
	swap = get_mm_counter(mm, MM_SWAPENTS);
	seq_printf(m,
		"VmPeak:\t%8lu kB\n"
		"VmSize:\t%8lu kB\n"
		"VmLck:\t%8lu kB\n"
		"VmPin:\t%8lu kB\n"
		"VmHWM:\t%8lu kB\n"
		"VmRSS:\t%8lu kB\n"
		"VmData:\t%8lu kB\n"
		"VmStk:\t%8lu kB\n"
		"VmExe:\t%8lu kB\n"
		"VmLib:\t%8lu kB\n"
		"VmPTE:\t%8lu kB\n"
		"VmSwap:\t%8lu kB\n",
		hiwater_vm << (PAGE_SHIFT-10),
		total_vm << (PAGE_SHIFT-10),
		mm->locked_vm << (PAGE_SHIFT-10),
		mm->pinned_vm << (PAGE_SHIFT-10),
		hiwater_rss << (PAGE_SHIFT-10),
		total_rss << (PAGE_SHIFT-10),
		data << (PAGE_SHIFT-10),
		mm->stack_vm << (PAGE_SHIFT-10), text, lib,
		(PTRS_PER_PTE * sizeof(pte_t) *
		 atomic_long_read(&mm->nr_ptes)) >> 10,
		swap << (PAGE_SHIFT-10));
}

unsigned long task_vsize(struct mm_struct *mm)
{
	return PAGE_SIZE * mm->total_vm;
}

unsigned long task_statm(struct mm_struct *mm,
			 unsigned long *shared, unsigned long *text,
			 unsigned long *data, unsigned long *resident)
{
	*shared = get_mm_counter(mm, MM_FILEPAGES);
	*text = (PAGE_ALIGN(mm->end_code) - (mm->start_code & PAGE_MASK))
								>> PAGE_SHIFT;
	*data = mm->total_vm - mm->shared_vm;
	*resident = *shared + get_mm_counter(mm, MM_ANONPAGES);
	return mm->total_vm;
}

#ifdef CONFIG_NUMA
/*
 * These functions are for numa_maps but called in generic **maps seq_file
 * ->start(), ->stop() ops.
 *
 * numa_maps scans all vmas under mmap_sem and checks their mempolicy.
 * Each mempolicy object is controlled by reference counting. The problem here
 * is how to avoid accessing dead mempolicy object.
 *
 * Because we're holding mmap_sem while reading seq_file, it's safe to access
 * each vma's mempolicy, no vma objects will never drop refs to mempolicy.
 *
 * A task's mempolicy (task->mempolicy) has different behavior. task->mempolicy
 * is set and replaced under mmap_sem but unrefed and cleared under task_lock().
 * So, without task_lock(), we cannot trust get_vma_policy() because we cannot
 * gurantee the task never exits under us. But taking task_lock() around
 * get_vma_plicy() causes lock order problem.
 *
 * To access task->mempolicy without lock, we hold a reference count of an
 * object pointed by task->mempolicy and remember it. This will guarantee
 * that task->mempolicy points to an alive object or NULL in numa_maps accesses.
 */
static void hold_task_mempolicy(struct proc_maps_private *priv)
{
	struct task_struct *task = priv->task;

	task_lock(task);
	priv->task_mempolicy = task->mempolicy;
	mpol_get(priv->task_mempolicy);
	task_unlock(task);
}
static void release_task_mempolicy(struct proc_maps_private *priv)
{
	mpol_put(priv->task_mempolicy);
}
#else
static void hold_task_mempolicy(struct proc_maps_private *priv)
{
}
static void release_task_mempolicy(struct proc_maps_private *priv)
{
}
#endif

static void vma_stop(struct proc_maps_private *priv, struct vm_area_struct *vma)
{
	if (vma && vma != priv->tail_vma) {
		struct mm_struct *mm = vma->vm_mm;
		release_task_mempolicy(priv);
		up_read(&mm->mmap_sem);
		mmput(mm);
	}
}

static void *m_start_task_mmu_c(struct seq_file *m, loff_t *pos)
{
	struct proc_maps_private *priv = m->private;
	unsigned long last_addr = m->version;
	struct mm_struct *mm;
	struct vm_area_struct *vma, *tail_vma = NULL;
	loff_t l = *pos;

	/* Clear the per syscall fields in priv */
	priv->task = NULL;
	priv->tail_vma = NULL;

	/*
	 * We remember last_addr rather than next_addr to hit with
	 * vmacache most of the time. We have zero last_addr at
	 * the beginning and also after lseek. We will have -1 last_addr
	 * after the end of the vmas.
	 */

	if (last_addr == -1UL)
		return NULL;

	priv->task = get_pid_task(priv->pid, PIDTYPE_PID);
	if (!priv->task)
		return ERR_PTR(-ESRCH);

	mm = mm_access(priv->task, PTRACE_MODE_READ);
	if (!mm || IS_ERR(mm))
		return mm;
	down_read(&mm->mmap_sem);

	tail_vma = get_gate_vma(priv->task->mm);
	priv->tail_vma = tail_vma;
	hold_task_mempolicy(priv);
	/* Start with last addr hint */
	vma = find_vma(mm, last_addr);
	if (last_addr && vma) {
		vma = vma->vm_next;
		goto out;
	}

	/*
	 * Check the vma index is within the range and do
	 * sequential scan until m_index.
	 */
	vma = NULL;
	if ((unsigned long)l < mm->map_count) {
		vma = mm->mmap;
		while (l-- && vma)
			vma = vma->vm_next;
		goto out;
	}

	if (l != mm->map_count)
		tail_vma = NULL; /* After gate vma */

out:
	if (vma)
		return vma;

	release_task_mempolicy(priv);
	/* End of vmas has been reached */
	m->version = (tail_vma != NULL)? 0: -1UL;
	up_read(&mm->mmap_sem);
	mmput(mm);
	return tail_vma;
}

static void *m_next_task_mmu_c(struct seq_file *m, void *v, loff_t *pos)
{
	struct proc_maps_private *priv = m->private;
	struct vm_area_struct *vma = v;
	struct vm_area_struct *tail_vma = priv->tail_vma;

	(*pos)++;
	if (vma && (vma != tail_vma) && vma->vm_next)
		return vma->vm_next;
	vma_stop(priv, vma);
	return (vma != tail_vma)? tail_vma: NULL;
}

static void m_stop_task_mmu_c(struct seq_file *m, void *v)
{
	struct proc_maps_private *priv = m->private;
	struct vm_area_struct *vma = v;

	if (!IS_ERR(vma))
		vma_stop(priv, vma);
	if (priv->task)
		put_task_struct(priv->task);
}

static int do_maps_open(struct inode *inode, struct file *file,
			const struct seq_operations *ops)
{
	struct proc_maps_private *priv;
	int ret = -ENOMEM;
	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (priv) {
		priv->pid = proc_pid(inode);
		ret = seq_open(file, ops);
		if (!ret) {
			struct seq_file *m = file->private_data;
			m->private = priv;
		} else {
			kfree(priv);
		}
	}
	return ret;
}

static void
show_map_vma(struct seq_file *m, struct vm_area_struct *vma, int is_pid)
{
	struct mm_struct *mm = vma->vm_mm;
	struct file *file = vma->vm_file;
	struct proc_maps_private *priv = m->private;
	struct task_struct *task = priv->task;
	vm_flags_t flags = vma->vm_flags;
	unsigned long ino = 0;
	unsigned long long pgoff = 0;
	unsigned long start, end;
	dev_t dev = 0;
	const char *name = NULL;

	if (file) {
		struct inode *inode = file_inode(vma->vm_file);
		dev = inode->i_sb->s_dev;
		ino = inode->i_ino;
		pgoff = ((loff_t)vma->vm_pgoff) << PAGE_SHIFT;
	}

	/* We don't show the stack guard page in /proc/maps */
	start = vma->vm_start;
	if (stack_guard_page_start(vma, start))
		start += PAGE_SIZE;
	end = vma->vm_end;
	if (stack_guard_page_end(vma, end))
		end -= PAGE_SIZE;

	seq_setwidth(m, 25 + sizeof(void *) * 6 - 1);
	seq_printf(m, "%08lx-%08lx %c%c%c%c %08llx %02x:%02x %lu ",
			start,
			end,
			flags & VM_READ ? 'r' : '-',
			flags & VM_WRITE ? 'w' : '-',
			flags & VM_EXEC ? 'x' : '-',
			flags & VM_MAYSHARE ? 's' : 'p',
			pgoff,
			MAJOR(dev), MINOR(dev), ino);

	/*
	 * Print the dentry name for named mappings, and a
	 * special [heap] marker for the heap:
	 */
	if (file) {
		seq_pad(m, ' ');
		seq_path(m, &file->f_path, "\n");
		goto done;
	}

	if (vma->vm_ops && vma->vm_ops->name) {
		name = vma->vm_ops->name(vma);
		if (name)
			goto done;
	}

	name = arch_vma_name(vma);
	if (!name) {
		pid_t tid;

		if (!mm) {
			name = "[vdso]";
			goto done;
		}

		if (vma->vm_start <= mm->brk &&
		    vma->vm_end >= mm->start_brk) {
			name = "[heap]";
			goto done;
		}

		tid = vm_is_stack(task, vma, is_pid);

		if (tid != 0) {
			/*
			 * Thread stack in /proc/PID/task/TID/maps or
			 * the main process stack.
			 */
			if (!is_pid || (vma->vm_start <= mm->start_stack &&
			    vma->vm_end >= mm->start_stack)) {
				name = "[stack]";
			} else {
				/* Thread stack in /proc/PID/maps */
				seq_pad(m, ' ');
				seq_printf(m, "[stack:%d]", tid);
			}
		}
	}

done:
	if (name) {
		seq_pad(m, ' ');
		seq_puts(m, name);
	}
	seq_putc(m, '\n');
}

static int show_map_task_mmu_c(struct seq_file *m, void *v, int is_pid)
{
	struct vm_area_struct *vma = v;
	struct proc_maps_private *priv = m->private;
	struct task_struct *task = priv->task;

	show_map_vma(m, vma, is_pid);

	if (m->count < m->size)  /* vma is copied successfully */
		m->version = (vma != get_gate_vma(task->mm))
			? vma->vm_start : 0;
	return 0;
}

static int show_pid_map_task_mmu_c(struct seq_file *m, void *v)
{
	return show_map_task_mmu_c(m, v, 1);
}

static int show_tid_map_task_mmu_c(struct seq_file *m, void *v)
{
	return show_map_task_mmu_c(m, v, 0);
}

static const struct seq_operations proc_pid_maps_op = {
	.start	= m_start_task_mmu_c,
	.next	= m_next_task_mmu_c,
	.stop	= m_stop_task_mmu_c,
	.show	= show_pid_map_task_mmu_c
};

static const struct seq_operations proc_tid_maps_op = {
	.start	= m_start_task_mmu_c,
	.next	= m_next_task_mmu_c,
	.stop	= m_stop_task_mmu_c,
	.show	= show_tid_map_task_mmu_c
};

static int pid_maps_open_task_mmu_c(struct inode *inode, struct file *file)
{
	return do_maps_open(inode, file, &proc_pid_maps_op);
}

static int tid_maps_open_task_mmu_c(struct inode *inode, struct file *file)
{
	return do_maps_open(inode, file, &proc_tid_maps_op);
}

const struct file_operations proc_pid_maps_operations = {
	.open		= pid_maps_open_task_mmu_c,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release_private,
};

const struct file_operations proc_tid_maps_operations = {
	.open		= tid_maps_open_task_mmu_c,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release_private,
};

/*
 * Proportional Set Size(PSS): my share of RSS.
 *
 * PSS of a process is the count of pages it has in memory, where each
 * page is divided by the number of processes sharing it.  So if a
 * process has 1000 pages all to itself, and 1000 shared with one other
 * process, its PSS will be 1500.
 *
 * To keep (accumulated) division errors low, we adopt a 64bit
 * fixed-point pss counter to minimize division errors. So (pss >>
 * PSS_SHIFT) would be the real byte count.
 *
 * A shift of 12 before division means (assuming 4K page size):
 * 	- 1M 3-user-pages add up to 8KB errors;
 * 	- supports mapcount up to 2^24, or 16M;
 * 	- supports PSS up to 2^52 bytes, or 4PB.
 */
#define PSS_SHIFT 12

#ifdef CONFIG_PROC_PAGE_MONITOR
struct mem_size_stats {
	struct vm_area_struct *vma;
	unsigned long resident;
	unsigned long shared_clean;
	unsigned long shared_dirty;
	unsigned long private_clean;
	unsigned long private_dirty;
	unsigned long referenced;
	unsigned long anonymous;
	unsigned long anonymous_thp;
	unsigned long swap;
	unsigned long nonlinear;
	u64 pss;
};


static void smaps_pte_entry(pte_t ptent, unsigned long addr,
		unsigned long ptent_size, struct mm_walk *walk)
{
	struct mem_size_stats *mss = walk->private;
	struct vm_area_struct *vma = mss->vma;
	pgoff_t pgoff = linear_page_index(vma, addr);
	struct page *page = NULL;
	int mapcount;

	if (pte_present(ptent)) {
		page = vm_normal_page(vma, addr, ptent);
	} else if (is_swap_pte(ptent)) {
		swp_entry_t swpent = pte_to_swp_entry(ptent);

		if (!non_swap_entry(swpent))
			mss->swap += ptent_size;
		else if (is_migration_entry(swpent))
			page = migration_entry_to_page(swpent);
	} else if (pte_file(ptent)) {
		if (pte_to_pgoff(ptent) != pgoff)
			mss->nonlinear += ptent_size;
	}

	if (!page)
		return;

	if (PageAnon(page))
		mss->anonymous += ptent_size;

	if (page->index != pgoff)
		mss->nonlinear += ptent_size;

	mss->resident += ptent_size;
	/* Accumulate the size in pages that have been accessed. */
	if (pte_young(ptent) || PageReferenced(page))
		mss->referenced += ptent_size;
	mapcount = page_mapcount(page);
	if (mapcount >= 2) {
		if (pte_dirty(ptent) || PageDirty(page))
			mss->shared_dirty += ptent_size;
		else
			mss->shared_clean += ptent_size;
		mss->pss += (ptent_size << PSS_SHIFT) / mapcount;
	} else {
		if (pte_dirty(ptent) || PageDirty(page))
			mss->private_dirty += ptent_size;
		else
			mss->private_clean += ptent_size;
		mss->pss += (ptent_size << PSS_SHIFT);
	}
}

static int smaps_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end,
			   struct mm_walk *walk)
{
	struct mem_size_stats *mss = walk->private;
	struct vm_area_struct *vma = mss->vma;
	pte_t *pte;
	spinlock_t *ptl;

	if (pmd_trans_huge_lock(pmd, vma, &ptl) == 1) {
		smaps_pte_entry(*(pte_t *)pmd, addr, HPAGE_PMD_SIZE, walk);
		spin_unlock(ptl);
		mss->anonymous_thp += HPAGE_PMD_SIZE;
		return 0;
	}

	if (pmd_trans_unstable(pmd))
		return 0;
	/*
	 * The mmap_sem held all the way back in m_start() is what
	 * keeps khugepaged out of here and from collapsing things
	 * in here.
	 */
	pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);
	for (; addr != end; pte++, addr += PAGE_SIZE)
		smaps_pte_entry(*pte, addr, PAGE_SIZE, walk);
	pte_unmap_unlock(pte - 1, ptl);
	cond_resched();
	return 0;
}

static void show_smap_vma_flags(struct seq_file *m, struct vm_area_struct *vma)
{
	/*
	 * Don't forget to update Documentation/ on changes.
	 */
	static const char mnemonics[BITS_PER_LONG][2] = {
		/*
		 * In case if we meet a flag we don't know about.
		 */
		[0 ... (BITS_PER_LONG-1)] = "??",

		[ilog2(VM_READ)]	= "rd",
		[ilog2(VM_WRITE)]	= "wr",
		[ilog2(VM_EXEC)]	= "ex",
		[ilog2(VM_SHARED)]	= "sh",
		[ilog2(VM_MAYREAD)]	= "mr",
		[ilog2(VM_MAYWRITE)]	= "mw",
		[ilog2(VM_MAYEXEC)]	= "me",
		[ilog2(VM_MAYSHARE)]	= "ms",
		[ilog2(VM_GROWSDOWN)]	= "gd",
		[ilog2(VM_PFNMAP)]	= "pf",
		[ilog2(VM_DENYWRITE)]	= "dw",
		[ilog2(VM_LOCKED)]	= "lo",
		[ilog2(VM_IO)]		= "io",
		[ilog2(VM_SEQ_READ)]	= "sr",
		[ilog2(VM_RAND_READ)]	= "rr",
		[ilog2(VM_DONTCOPY)]	= "dc",
		[ilog2(VM_DONTEXPAND)]	= "de",
		[ilog2(VM_ACCOUNT)]	= "ac",
		[ilog2(VM_NORESERVE)]	= "nr",
		[ilog2(VM_HUGETLB)]	= "ht",
		[ilog2(VM_NONLINEAR)]	= "nl",
		[ilog2(VM_ARCH_1)]	= "ar",
		[ilog2(VM_DONTDUMP)]	= "dd",
#ifdef CONFIG_MEM_SOFT_DIRTY
		[ilog2(VM_SOFTDIRTY)]	= "sd",
#endif
		[ilog2(VM_MIXEDMAP)]	= "mm",
		[ilog2(VM_HUGEPAGE)]	= "hg",
		[ilog2(VM_NOHUGEPAGE)]	= "nh",
		[ilog2(VM_MERGEABLE)]	= "mg",
	};
	size_t i;

	seq_puts(m, "VmFlags: ");
	for (i = 0; i < BITS_PER_LONG; i++) {
		if (vma->vm_flags & (1UL << i)) {
			seq_printf(m, "%c%c ",
				   mnemonics[i][0], mnemonics[i][1]);
		}
	}
	seq_putc(m, '\n');
}

static int show_smap(struct seq_file *m, void *v, int is_pid)
{
	struct proc_maps_private *priv = m->private;
	struct task_struct *task = priv->task;
	struct vm_area_struct *vma = v;
	struct mem_size_stats mss;
	struct mm_walk smaps_walk = {
		.pmd_entry = smaps_pte_range,
		.mm = vma->vm_mm,
		.private = &mss,
	};

	memset(&mss, 0, sizeof mss);
	mss.vma = vma;
	/* mmap_sem is held in m_start */
	if (vma->vm_mm && !is_vm_hugetlb_page(vma))
		walk_page_range(vma->vm_start, vma->vm_end, &smaps_walk);

	show_map_vma(m, vma, is_pid);

	seq_printf(m,
		   "Size:           %8lu kB\n"
		   "Rss:            %8lu kB\n"
		   "Pss:            %8lu kB\n"
		   "Shared_Clean:   %8lu kB\n"
		   "Shared_Dirty:   %8lu kB\n"
		   "Private_Clean:  %8lu kB\n"
		   "Private_Dirty:  %8lu kB\n"
		   "Referenced:     %8lu kB\n"
		   "Anonymous:      %8lu kB\n"
		   "AnonHugePages:  %8lu kB\n"
		   "Swap:           %8lu kB\n"
		   "KernelPageSize: %8lu kB\n"
		   "MMUPageSize:    %8lu kB\n"
		   "Locked:         %8lu kB\n",
		   (vma->vm_end - vma->vm_start) >> 10,
		   mss.resident >> 10,
		   (unsigned long)(mss.pss >> (10 + PSS_SHIFT)),
		   mss.shared_clean  >> 10,
		   mss.shared_dirty  >> 10,
		   mss.private_clean >> 10,
		   mss.private_dirty >> 10,
		   mss.referenced >> 10,
		   mss.anonymous >> 10,
		   mss.anonymous_thp >> 10,
		   mss.swap >> 10,
		   vma_kernel_pagesize(vma) >> 10,
		   vma_mmu_pagesize(vma) >> 10,
		   (vma->vm_flags & VM_LOCKED) ?
			(unsigned long)(mss.pss >> (10 + PSS_SHIFT)) : 0);

	if (vma->vm_flags & VM_NONLINEAR)
		seq_printf(m, "Nonlinear:      %8lu kB\n",
				mss.nonlinear >> 10);

	show_smap_vma_flags(m, vma);

	if (m->count < m->size)  /* vma is copied successfully */
		m->version = (vma != get_gate_vma(task->mm))
			? vma->vm_start : 0;
	return 0;
}

static int show_pid_smap(struct seq_file *m, void *v)
{
	return show_smap(m, v, 1);
}

static int show_tid_smap(struct seq_file *m, void *v)
{
	return show_smap(m, v, 0);
}

static const struct seq_operations proc_pid_smaps_op = {
	.start	= m_start_task_mmu_c,
	.next	= m_next_task_mmu_c,
	.stop	= m_stop_task_mmu_c,
	.show	= show_pid_smap
};

static const struct seq_operations proc_tid_smaps_op = {
	.start	= m_start_task_mmu_c,
	.next	= m_next_task_mmu_c,
	.stop	= m_stop_task_mmu_c,
	.show	= show_tid_smap
};

static int pid_smaps_open(struct inode *inode, struct file *file)
{
	return do_maps_open(inode, file, &proc_pid_smaps_op);
}

static int tid_smaps_open(struct inode *inode, struct file *file)
{
	return do_maps_open(inode, file, &proc_tid_smaps_op);
}

const struct file_operations proc_pid_smaps_operations = {
	.open		= pid_smaps_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release_private,
};

const struct file_operations proc_tid_smaps_operations = {
	.open		= tid_smaps_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release_private,
};

/*
 * We do not want to have constant page-shift bits sitting in
 * pagemap entries and are about to reuse them some time soon.
 *
 * Here's the "migration strategy":
 * 1. when the system boots these bits remain what they are,
 *    but a warning about future change is printed in log;
 * 2. once anyone clears soft-dirty bits via clear_refs file,
 *    these flag is set to denote, that user is aware of the
 *    new API and those page-shift bits change their meaning.
 *    The respective warning is printed in dmesg;
 * 3. In a couple of releases we will remove all the mentions
 *    of page-shift in pagemap entries.
 */

static bool soft_dirty_cleared __read_mostly;

enum clear_refs_types {
	CLEAR_REFS_ALL = 1,
	CLEAR_REFS_ANON,
	CLEAR_REFS_MAPPED,
	CLEAR_REFS_SOFT_DIRTY,
	CLEAR_REFS_LAST,
};

struct clear_refs_private {
	struct vm_area_struct *vma;
	enum clear_refs_types type;
};

static inline void clear_soft_dirty(struct vm_area_struct *vma,
		unsigned long addr, pte_t *pte)
{
#ifdef CONFIG_MEM_SOFT_DIRTY
	/*
	 * The soft-dirty tracker uses #PF-s to catch writes
	 * to pages, so write-protect the pte as well. See the
	 * Documentation/vm/soft-dirty.txt for full description
	 * of how soft-dirty works.
	 */
	pte_t ptent = *pte;

	if (pte_present(ptent)) {
		ptent = pte_wrprotect(ptent);
		ptent = pte_clear_flags(ptent, _PAGE_SOFT_DIRTY);
	} else if (is_swap_pte(ptent)) {
		ptent = pte_swp_clear_soft_dirty(ptent);
	} else if (pte_file(ptent)) {
		ptent = pte_file_clear_soft_dirty(ptent);
	}

	set_pte_at(vma->vm_mm, addr, pte, ptent);
#endif
}

static int clear_refs_pte_range(pmd_t *pmd, unsigned long addr,
				unsigned long end, struct mm_walk *walk)
{
	struct clear_refs_private *cp = walk->private;
	struct vm_area_struct *vma = cp->vma;
	pte_t *pte, ptent;
	spinlock_t *ptl;
	struct page *page;

	split_huge_page_pmd(vma, addr, pmd);
	if (pmd_trans_unstable(pmd))
		return 0;

	pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);
	for (; addr != end; pte++, addr += PAGE_SIZE) {
		ptent = *pte;

		if (cp->type == CLEAR_REFS_SOFT_DIRTY) {
			clear_soft_dirty(vma, addr, pte);
			continue;
		}

		if (!pte_present(ptent))
			continue;

		page = vm_normal_page(vma, addr, ptent);
		if (!page)
			continue;

		/* Clear accessed and referenced bits. */
		ptep_test_and_clear_young(vma, addr, pte);
		ClearPageReferenced(page);
	}
	pte_unmap_unlock(pte - 1, ptl);
	cond_resched();
	return 0;
}

static ssize_t clear_refs_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	struct task_struct *task;
	char buffer[PROC_NUMBUF];
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	enum clear_refs_types type;
	int itype;
	int rv;

	memset(buffer, 0, sizeof(buffer));
	if (count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;
	if (copy_from_user(buffer, buf, count))
		return -EFAULT;
	rv = kstrtoint(strstrip(buffer), 10, &itype);
	if (rv < 0)
		return rv;
	type = (enum clear_refs_types)itype;
	if (type < CLEAR_REFS_ALL || type >= CLEAR_REFS_LAST)
		return -EINVAL;

	if (type == CLEAR_REFS_SOFT_DIRTY) {
		soft_dirty_cleared = true;
		pr_warn_once("The pagemap bits 55-60 has changed their meaning!"
			     " See the linux/Documentation/vm/pagemap.txt for "
			     "details.\n");
	}

	task = get_proc_task(file_inode(file));
	if (!task)
		return -ESRCH;
	mm = get_task_mm(task);
	if (mm) {
		struct clear_refs_private cp = {
			.type = type,
		};
		struct mm_walk clear_refs_walk = {
			.pmd_entry = clear_refs_pte_range,
			.mm = mm,
			.private = &cp,
		};
		down_read(&mm->mmap_sem);
		if (type == CLEAR_REFS_SOFT_DIRTY)
			mmu_notifier_invalidate_range_start(mm, 0, -1);
		for (vma = mm->mmap; vma; vma = vma->vm_next) {
			cp.vma = vma;
			if (is_vm_hugetlb_page(vma))
				continue;
			/*
			 * Writing 1 to /proc/pid/clear_refs affects all pages.
			 *
			 * Writing 2 to /proc/pid/clear_refs only affects
			 * Anonymous pages.
			 *
			 * Writing 3 to /proc/pid/clear_refs only affects file
			 * mapped pages.
			 *
			 * Writing 4 to /proc/pid/clear_refs affects all pages.
			 */
			if (type == CLEAR_REFS_ANON && vma->vm_file)
				continue;
			if (type == CLEAR_REFS_MAPPED && !vma->vm_file)
				continue;
			if (type == CLEAR_REFS_SOFT_DIRTY) {
				if (vma->vm_flags & VM_SOFTDIRTY)
					vma->vm_flags &= ~VM_SOFTDIRTY;
			}
			walk_page_range(vma->vm_start, vma->vm_end,
					&clear_refs_walk);
		}
		if (type == CLEAR_REFS_SOFT_DIRTY)
			mmu_notifier_invalidate_range_end(mm, 0, -1);
		flush_tlb_mm(mm);
		up_read(&mm->mmap_sem);
		mmput(mm);
	}
	put_task_struct(task);

	return count;
}

const struct file_operations proc_clear_refs_operations = {
	.write		= clear_refs_write,
	.llseek		= noop_llseek,
};

typedef struct {
	u64 pme;
} pagemap_entry_t;

struct pagemapread {
	int pos, len;		/* units: PM_ENTRY_BYTES, not bytes */
	pagemap_entry_t *buffer;
	bool v2;
};

#define PAGEMAP_WALK_SIZE	(PMD_SIZE)
#define PAGEMAP_WALK_MASK	(PMD_MASK)

#define PM_ENTRY_BYTES      sizeof(pagemap_entry_t)
#define PM_STATUS_BITS      3
#define PM_STATUS_OFFSET    (64 - PM_STATUS_BITS)
#define PM_STATUS_MASK      (((1LL << PM_STATUS_BITS) - 1) << PM_STATUS_OFFSET)
#define PM_STATUS(nr)       (((nr) << PM_STATUS_OFFSET) & PM_STATUS_MASK)
#define PM_PSHIFT_BITS      6
#define PM_PSHIFT_OFFSET    (PM_STATUS_OFFSET - PM_PSHIFT_BITS)
#define PM_PSHIFT_MASK      (((1LL << PM_PSHIFT_BITS) - 1) << PM_PSHIFT_OFFSET)
#define __PM_PSHIFT(x)      (((u64) (x) << PM_PSHIFT_OFFSET) & PM_PSHIFT_MASK)
#define PM_PFRAME_MASK      ((1LL << PM_PSHIFT_OFFSET) - 1)
#define PM_PFRAME(x)        ((x) & PM_PFRAME_MASK)
/* in "new" pagemap pshift bits are occupied with more status bits */
#define PM_STATUS2(v2, x)   (__PM_PSHIFT(v2 ? x : PAGE_SHIFT))

#define __PM_SOFT_DIRTY      (1LL)
#define PM_PRESENT          PM_STATUS(4LL)
#define PM_SWAP             PM_STATUS(2LL)
#define PM_FILE             PM_STATUS(1LL)
#define PM_NOT_PRESENT(v2)  PM_STATUS2(v2, 0)
#define PM_END_OF_BUFFER    1

static inline pagemap_entry_t make_pme(u64 val)
{
	return (pagemap_entry_t) { .pme = val };
}

static int add_to_pagemap(unsigned long addr, pagemap_entry_t *pme,
			  struct pagemapread *pm)
{
	pm->buffer[pm->pos++] = *pme;
	if (pm->pos >= pm->len)
		return PM_END_OF_BUFFER;
	return 0;
}

static int pagemap_pte_hole(unsigned long start, unsigned long end,
				struct mm_walk *walk)
{
	struct pagemapread *pm = walk->private;
	unsigned long addr = start;
	int err = 0;

	while (addr < end) {
		struct vm_area_struct *vma = find_vma(walk->mm, addr);
		pagemap_entry_t pme = make_pme(PM_NOT_PRESENT(pm->v2));
		unsigned long vm_end;

		if (!vma) {
			vm_end = end;
		} else {
			vm_end = min(end, vma->vm_end);
			if (vma->vm_flags & VM_SOFTDIRTY)
				pme.pme |= PM_STATUS2(pm->v2, __PM_SOFT_DIRTY);
		}

		for (; addr < vm_end; addr += PAGE_SIZE) {
			err = add_to_pagemap(addr, &pme, pm);
			if (err)
				goto out;
		}
	}

out:
	return err;
}

static void pte_to_pagemap_entry(pagemap_entry_t *pme, struct pagemapread *pm,
		struct vm_area_struct *vma, unsigned long addr, pte_t pte)
{
	u64 frame, flags;
	struct page *page = NULL;
	int flags2 = 0;

	if (pte_present(pte)) {
		frame = pte_pfn(pte);
		flags = PM_PRESENT;
		page = vm_normal_page(vma, addr, pte);
		if (pte_soft_dirty(pte))
			flags2 |= __PM_SOFT_DIRTY;
	} else if (is_swap_pte(pte)) {
		swp_entry_t entry;
		if (pte_swp_soft_dirty(pte))
			flags2 |= __PM_SOFT_DIRTY;
		entry = pte_to_swp_entry(pte);
		frame = swp_type(entry) |
			(swp_offset(entry) << MAX_SWAPFILES_SHIFT);
		flags = PM_SWAP;
		if (is_migration_entry(entry))
			page = migration_entry_to_page(entry);
	} else {
		if (vma->vm_flags & VM_SOFTDIRTY)
			flags2 |= __PM_SOFT_DIRTY;
		*pme = make_pme(PM_NOT_PRESENT(pm->v2) | PM_STATUS2(pm->v2, flags2));
		return;
	}

	if (page && !PageAnon(page))
		flags |= PM_FILE;
	if ((vma->vm_flags & VM_SOFTDIRTY))
		flags2 |= __PM_SOFT_DIRTY;

	*pme = make_pme(PM_PFRAME(frame) | PM_STATUS2(pm->v2, flags2) | flags);
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static void thp_pmd_to_pagemap_entry(pagemap_entry_t *pme, struct pagemapread *pm,
		pmd_t pmd, int offset, int pmd_flags2)
{
	/*
	 * Currently pmd for thp is always present because thp can not be
	 * swapped-out, migrated, or HWPOISONed (split in such cases instead.)
	 * This if-check is just to prepare for future implementation.
	 */
	if (pmd_present(pmd))
		*pme = make_pme(PM_PFRAME(pmd_pfn(pmd) + offset)
				| PM_STATUS2(pm->v2, pmd_flags2) | PM_PRESENT);
	else
		*pme = make_pme(PM_NOT_PRESENT(pm->v2) | PM_STATUS2(pm->v2, pmd_flags2));
}
#else
static inline void thp_pmd_to_pagemap_entry(pagemap_entry_t *pme, struct pagemapread *pm,
		pmd_t pmd, int offset, int pmd_flags2)
{
}
#endif

static int pagemap_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end,
			     struct mm_walk *walk)
{
	struct vm_area_struct *vma;
	struct pagemapread *pm = walk->private;
	spinlock_t *ptl;
	pte_t *pte;
	int err = 0;
	pagemap_entry_t pme = make_pme(PM_NOT_PRESENT(pm->v2));

	/* find the first VMA at or above 'addr' */
	vma = find_vma(walk->mm, addr);
	if (vma && pmd_trans_huge_lock(pmd, vma, &ptl) == 1) {
		int pmd_flags2;

		if ((vma->vm_flags & VM_SOFTDIRTY) || pmd_soft_dirty(*pmd))
			pmd_flags2 = __PM_SOFT_DIRTY;
		else
			pmd_flags2 = 0;

		for (; addr != end; addr += PAGE_SIZE) {
			unsigned long offset;

			offset = (addr & ~PAGEMAP_WALK_MASK) >>
					PAGE_SHIFT;
			thp_pmd_to_pagemap_entry(&pme, pm, *pmd, offset, pmd_flags2);
			err = add_to_pagemap(addr, &pme, pm);
			if (err)
				break;
		}
		spin_unlock(ptl);
		return err;
	}

	if (pmd_trans_unstable(pmd))
		return 0;
	for (; addr != end; addr += PAGE_SIZE) {
		int flags2;

		/* check to see if we've left 'vma' behind
		 * and need a new, higher one */
		if (vma && (addr >= vma->vm_end)) {
			vma = find_vma(walk->mm, addr);
			if (vma && (vma->vm_flags & VM_SOFTDIRTY))
				flags2 = __PM_SOFT_DIRTY;
			else
				flags2 = 0;
			pme = make_pme(PM_NOT_PRESENT(pm->v2) | PM_STATUS2(pm->v2, flags2));
		}

		/* check that 'vma' actually covers this address,
		 * and that it isn't a huge page vma */
		if (vma && (vma->vm_start <= addr) &&
		    !is_vm_hugetlb_page(vma)) {
			pte = pte_offset_map(pmd, addr);
			pte_to_pagemap_entry(&pme, pm, vma, addr, *pte);
			/* unmap before userspace copy */
			pte_unmap(pte);
		}
		err = add_to_pagemap(addr, &pme, pm);
		if (err)
			return err;
	}

	cond_resched();

	return err;
}

#ifdef CONFIG_HUGETLB_PAGE
static void huge_pte_to_pagemap_entry(pagemap_entry_t *pme, struct pagemapread *pm,
					pte_t pte, int offset, int flags2)
{
	if (pte_present(pte))
		*pme = make_pme(PM_PFRAME(pte_pfn(pte) + offset)	|
				PM_STATUS2(pm->v2, flags2)		|
				PM_PRESENT);
	else
		*pme = make_pme(PM_NOT_PRESENT(pm->v2)			|
				PM_STATUS2(pm->v2, flags2));
}

/* This function walks within one hugetlb entry in the single call */
static int pagemap_hugetlb_range(pte_t *pte, unsigned long hmask,
				 unsigned long addr, unsigned long end,
				 struct mm_walk *walk)
{
	struct pagemapread *pm = walk->private;
	struct vm_area_struct *vma;
	int err = 0;
	int flags2;
	pagemap_entry_t pme;

	vma = find_vma(walk->mm, addr);
	WARN_ON_ONCE(!vma);

	if (vma && (vma->vm_flags & VM_SOFTDIRTY))
		flags2 = __PM_SOFT_DIRTY;
	else
		flags2 = 0;

	for (; addr != end; addr += PAGE_SIZE) {
		int offset = (addr & ~hmask) >> PAGE_SHIFT;
		huge_pte_to_pagemap_entry(&pme, pm, *pte, offset, flags2);
		err = add_to_pagemap(addr, &pme, pm);
		if (err)
			return err;
	}

	cond_resched();

	return err;
}
#endif /* HUGETLB_PAGE */

/*
 * /proc/pid/pagemap - an array mapping virtual pages to pfns
 *
 * For each page in the address space, this file contains one 64-bit entry
 * consisting of the following:
 *
 * Bits 0-54  page frame number (PFN) if present
 * Bits 0-4   swap type if swapped
 * Bits 5-54  swap offset if swapped
 * Bits 55-60 page shift (page size = 1<<page shift)
 * Bit  61    page is file-page or shared-anon
 * Bit  62    page swapped
 * Bit  63    page present
 *
 * If the page is not present but in swap, then the PFN contains an
 * encoding of the swap file number and the page's offset into the
 * swap. Unmapped pages return a null PFN. This allows determining
 * precisely which pages are mapped (or in swap) and comparing mapped
 * pages between processes.
 *
 * Efficient users of this interface will use /proc/pid/maps to
 * determine which areas of memory are actually mapped and llseek to
 * skip over unmapped regions.
 */
static ssize_t pagemap_read(struct file *file, char __user *buf,
			    size_t count, loff_t *ppos)
{
	struct task_struct *task = get_proc_task(file_inode(file));
	struct mm_struct *mm;
	struct pagemapread pm;
	int ret = -ESRCH;
	struct mm_walk pagemap_walk = {};
	unsigned long src;
	unsigned long svpfn;
	unsigned long start_vaddr;
	unsigned long end_vaddr;
	int copied = 0;

	if (!task)
		goto out;

	ret = -EINVAL;
	/* file position must be aligned */
	if ((*ppos % PM_ENTRY_BYTES) || (count % PM_ENTRY_BYTES))
		goto out_task;

	ret = 0;
	if (!count)
		goto out_task;

	pm.v2 = soft_dirty_cleared;
	pm.len = (PAGEMAP_WALK_SIZE >> PAGE_SHIFT);
	pm.buffer = kmalloc(pm.len * PM_ENTRY_BYTES, GFP_TEMPORARY);
	ret = -ENOMEM;
	if (!pm.buffer)
		goto out_task;

	mm = mm_access(task, PTRACE_MODE_READ);
	ret = PTR_ERR(mm);
	if (!mm || IS_ERR(mm))
		goto out_free;

	pagemap_walk.pmd_entry = pagemap_pte_range;
	pagemap_walk.pte_hole = pagemap_pte_hole;
#ifdef CONFIG_HUGETLB_PAGE
	pagemap_walk.hugetlb_entry = pagemap_hugetlb_range;
#endif
	pagemap_walk.mm = mm;
	pagemap_walk.private = &pm;

	src = *ppos;
	svpfn = src / PM_ENTRY_BYTES;
	start_vaddr = svpfn << PAGE_SHIFT;
	end_vaddr = TASK_SIZE_OF(task);

	/* watch out for wraparound */
	if (svpfn > TASK_SIZE_OF(task) >> PAGE_SHIFT)
		start_vaddr = end_vaddr;

	/*
	 * The odds are that this will stop walking way
	 * before end_vaddr, because the length of the
	 * user buffer is tracked in "pm", and the walk
	 * will stop when we hit the end of the buffer.
	 */
	ret = 0;
	while (count && (start_vaddr < end_vaddr)) {
		int len;
		unsigned long end;

		pm.pos = 0;
		end = (start_vaddr + PAGEMAP_WALK_SIZE) & PAGEMAP_WALK_MASK;
		/* overflow ? */
		if (end < start_vaddr || end > end_vaddr)
			end = end_vaddr;
		down_read(&mm->mmap_sem);
		ret = walk_page_range(start_vaddr, end, &pagemap_walk);
		up_read(&mm->mmap_sem);
		start_vaddr = end;

		len = min(count, PM_ENTRY_BYTES * pm.pos);
		if (copy_to_user(buf, pm.buffer, len)) {
			ret = -EFAULT;
			goto out_mm;
		}
		copied += len;
		buf += len;
		count -= len;
	}
	*ppos += copied;
	if (!ret || ret == PM_END_OF_BUFFER)
		ret = copied;

out_mm:
	mmput(mm);
out_free:
	kfree(pm.buffer);
out_task:
	put_task_struct(task);
out:
	return ret;
}

static int pagemap_open(struct inode *inode, struct file *file)
{
	pr_warn_once("Bits 55-60 of /proc/PID/pagemap entries are about "
			"to stop being page-shift some time soon. See the "
			"linux/Documentation/vm/pagemap.txt for details.\n");
	return 0;
}

const struct file_operations proc_pagemap_operations = {
	.llseek		= mem_lseek, /* borrow this */
	.read		= pagemap_read,
	.open		= pagemap_open,
};
#endif /* CONFIG_PROC_PAGE_MONITOR */

#ifdef CONFIG_NUMA

struct numa_maps {
	struct vm_area_struct *vma;
	unsigned long pages;
	unsigned long anon;
	unsigned long active;
	unsigned long writeback;
	unsigned long mapcount_max;
	unsigned long dirty;
	unsigned long swapcache;
	unsigned long node[MAX_NUMNODES];
};

struct numa_maps_private {
	struct proc_maps_private proc_maps;
	struct numa_maps md;
};

static void gather_stats(struct page *page, struct numa_maps *md, int pte_dirty,
			unsigned long nr_pages)
{
	int count = page_mapcount(page);

	md->pages += nr_pages;
	if (pte_dirty || PageDirty(page))
		md->dirty += nr_pages;

	if (PageSwapCache(page))
		md->swapcache += nr_pages;

	if (PageActive(page) || PageUnevictable(page))
		md->active += nr_pages;

	if (PageWriteback(page))
		md->writeback += nr_pages;

	if (PageAnon(page))
		md->anon += nr_pages;

	if (count > md->mapcount_max)
		md->mapcount_max = count;

	md->node[page_to_nid(page)] += nr_pages;
}

static struct page *can_gather_numa_stats(pte_t pte, struct vm_area_struct *vma,
		unsigned long addr)
{
	struct page *page;
	int nid;

	if (!pte_present(pte))
		return NULL;

	page = vm_normal_page(vma, addr, pte);
	if (!page)
		return NULL;

	if (PageReserved(page))
		return NULL;

	nid = page_to_nid(page);
	if (!node_isset(nid, node_states[N_MEMORY]))
		return NULL;

	return page;
}

static int gather_pte_stats(pmd_t *pmd, unsigned long addr,
		unsigned long end, struct mm_walk *walk)
{
	struct numa_maps *md;
	spinlock_t *ptl;
	pte_t *orig_pte;
	pte_t *pte;

	md = walk->private;

	if (pmd_trans_huge_lock(pmd, md->vma, &ptl) == 1) {
		pte_t huge_pte = *(pte_t *)pmd;
		struct page *page;

		page = can_gather_numa_stats(huge_pte, md->vma, addr);
		if (page)
			gather_stats(page, md, pte_dirty(huge_pte),
				     HPAGE_PMD_SIZE/PAGE_SIZE);
		spin_unlock(ptl);
		return 0;
	}

	if (pmd_trans_unstable(pmd))
		return 0;
	orig_pte = pte = pte_offset_map_lock(walk->mm, pmd, addr, &ptl);
	do {
		struct page *page = can_gather_numa_stats(*pte, md->vma, addr);
		if (!page)
			continue;
		gather_stats(page, md, pte_dirty(*pte), 1);

	} while (pte++, addr += PAGE_SIZE, addr != end);
	pte_unmap_unlock(orig_pte, ptl);
	return 0;
}
#ifdef CONFIG_HUGETLB_PAGE
static int gather_hugetbl_stats(pte_t *pte, unsigned long hmask,
		unsigned long addr, unsigned long end, struct mm_walk *walk)
{
	struct numa_maps *md;
	struct page *page;

	if (!pte_present(*pte))
		return 0;

	page = pte_page(*pte);
	if (!page)
		return 0;

	md = walk->private;
	gather_stats(page, md, pte_dirty(*pte), 1);
	return 0;
}

#else
static int gather_hugetbl_stats(pte_t *pte, unsigned long hmask,
		unsigned long addr, unsigned long end, struct mm_walk *walk)
{
	return 0;
}
#endif

/*
 * Display pages allocated per node and memory policy via /proc.
 */
static int show_numa_map(struct seq_file *m, void *v, int is_pid)
{
	struct numa_maps_private *numa_priv = m->private;
	struct proc_maps_private *proc_priv = &numa_priv->proc_maps;
	struct vm_area_struct *vma = v;
	struct numa_maps *md = &numa_priv->md;
	struct file *file = vma->vm_file;
	struct task_struct *task = proc_priv->task;
	struct mm_struct *mm = vma->vm_mm;
	struct mm_walk walk = {};
	struct mempolicy *pol;
	char buffer[64];
	int nid;

	if (!mm)
		return 0;

	/* Ensure we start with an empty set of numa_maps statistics. */
	memset(md, 0, sizeof(*md));

	md->vma = vma;

	walk.hugetlb_entry = gather_hugetbl_stats;
	walk.pmd_entry = gather_pte_stats;
	walk.private = md;
	walk.mm = mm;

	pol = get_vma_policy(task, vma, vma->vm_start);
	mpol_to_str(buffer, sizeof(buffer), pol);
	mpol_cond_put(pol);

	seq_printf(m, "%08lx %s", vma->vm_start, buffer);

	if (file) {
		seq_puts(m, " file=");
		seq_path(m, &file->f_path, "\n\t= ");
	} else if (vma->vm_start <= mm->brk && vma->vm_end >= mm->start_brk) {
		seq_puts(m, " heap");
	} else {
		pid_t tid = vm_is_stack(task, vma, is_pid);
		if (tid != 0) {
			/*
			 * Thread stack in /proc/PID/task/TID/maps or
			 * the main process stack.
			 */
			if (!is_pid || (vma->vm_start <= mm->start_stack &&
			    vma->vm_end >= mm->start_stack))
				seq_puts(m, " stack");
			else
				seq_printf(m, " stack:%d", tid);
		}
	}

	if (is_vm_hugetlb_page(vma))
		seq_puts(m, " huge");

	walk_page_range(vma->vm_start, vma->vm_end, &walk);

	if (!md->pages)
		goto out;

	if (md->anon)
		seq_printf(m, " anon=%lu", md->anon);

	if (md->dirty)
		seq_printf(m, " dirty=%lu", md->dirty);

	if (md->pages != md->anon && md->pages != md->dirty)
		seq_printf(m, " mapped=%lu", md->pages);

	if (md->mapcount_max > 1)
		seq_printf(m, " mapmax=%lu", md->mapcount_max);

	if (md->swapcache)
		seq_printf(m, " swapcache=%lu", md->swapcache);

	if (md->active < md->pages && !is_vm_hugetlb_page(vma))
		seq_printf(m, " active=%lu", md->active);

	if (md->writeback)
		seq_printf(m, " writeback=%lu", md->writeback);

	for_each_node_state(nid, N_MEMORY)
		if (md->node[nid])
			seq_printf(m, " N%d=%lu", nid, md->node[nid]);
out:
	seq_putc(m, '\n');

	if (m->count < m->size)
		m->version = (vma != proc_priv->tail_vma) ? vma->vm_start : 0;
	return 0;
}

static int show_pid_numa_map(struct seq_file *m, void *v)
{
	return show_numa_map(m, v, 1);
}

static int show_tid_numa_map(struct seq_file *m, void *v)
{
	return show_numa_map(m, v, 0);
}

static const struct seq_operations proc_pid_numa_maps_op = {
	.start  = m_start_task_mmu_c,
	.next   = m_next_task_mmu_c,
	.stop   = m_stop_task_mmu_c,
	.show   = show_pid_numa_map,
};

static const struct seq_operations proc_tid_numa_maps_op = {
	.start  = m_start_task_mmu_c,
	.next   = m_next_task_mmu_c,
	.stop   = m_stop_task_mmu_c,
	.show   = show_tid_numa_map,
};

static int numa_maps_open(struct inode *inode, struct file *file,
			  const struct seq_operations *ops)
{
	struct numa_maps_private *priv;
	int ret = -ENOMEM;
	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (priv) {
		priv->proc_maps.pid = proc_pid(inode);
		ret = seq_open(file, ops);
		if (!ret) {
			struct seq_file *m = file->private_data;
			m->private = priv;
		} else {
			kfree(priv);
		}
	}
	return ret;
}

static int pid_numa_maps_open(struct inode *inode, struct file *file)
{
	return numa_maps_open(inode, file, &proc_pid_numa_maps_op);
}

static int tid_numa_maps_open(struct inode *inode, struct file *file)
{
	return numa_maps_open(inode, file, &proc_tid_numa_maps_op);
}

const struct file_operations proc_pid_numa_maps_operations = {
	.open		= pid_numa_maps_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release_private,
};

const struct file_operations proc_tid_numa_maps_operations = {
	.open		= tid_numa_maps_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release_private,
};
#endif /* CONFIG_NUMA */
/************************************************************/
/* ../linux-3.17/fs/proc/task_mmu.c */
/************************************************************/
/*
 *  linux/fs/proc/inode.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

// #include <linux/time.h>
// #include <linux/proc_fs.h>
// #include <linux/kernel.h>
#include <linux/pid_namespace.h>
// #include <linux/mm.h>
// #include <linux/string.h>
#include <linux/stat.h>
#include <linux/completion.h>
#include <linux/poll.h>
#include <linux/printk.h>
// #include <linux/file.h>
#include <linux/limits.h>
// #include <linux/init.h>
// #include <linux/module.h>
#include <linux/sysctl.h>
// #include <linux/seq_file.h>
// #include <linux/slab.h>
// #include <linux/mount.h>
#include <linux/magic.h>

// #include <asm/uaccess.h>

// #include "internal.h"

static void proc_evict_inode(struct inode *inode)
{
	struct proc_dir_entry *de;
	struct ctl_table_header *head;
	const struct proc_ns_operations *ns_ops;
	void *ns;

	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);

	/* Stop tracking associated processes */
	put_pid(PROC_I(inode)->pid);

	/* Let go of any associated proc directory entry */
	de = PROC_I(inode)->pde;
	if (de)
		pde_put(de);
	head = PROC_I(inode)->sysctl;
	if (head) {
		RCU_INIT_POINTER(PROC_I(inode)->sysctl, NULL);
		sysctl_head_put(head);
	}
	/* Release any associated namespace */
	ns_ops = PROC_I(inode)->ns.ns_ops;
	ns = PROC_I(inode)->ns.ns;
	if (ns_ops && ns)
		ns_ops->put(ns);
}

static struct kmem_cache * proc_inode_cachep;

static struct inode *proc_alloc_inode(struct super_block *sb)
{
	struct proc_inode *ei;
	struct inode *inode;

	ei = (struct proc_inode *)kmem_cache_alloc(proc_inode_cachep, GFP_KERNEL);
	if (!ei)
		return NULL;
	ei->pid = NULL;
	ei->fd = 0;
	ei->op.proc_get_link = NULL;
	ei->pde = NULL;
	ei->sysctl = NULL;
	ei->sysctl_entry = NULL;
	ei->ns.ns = NULL;
	ei->ns.ns_ops = NULL;
	inode = &ei->vfs_inode;
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
	return inode;
}

static void proc_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(proc_inode_cachep, PROC_I(inode));
}

static void proc_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, proc_i_callback);
}

static void init_once(void *foo)
{
	struct proc_inode *ei = (struct proc_inode *) foo;

	inode_init_once(&ei->vfs_inode);
}

void __init proc_init_inodecache(void)
{
	proc_inode_cachep = kmem_cache_create("proc_inode_cache",
					     sizeof(struct proc_inode),
					     0, (SLAB_RECLAIM_ACCOUNT|
						SLAB_MEM_SPREAD|SLAB_PANIC),
					     init_once);
}

static int proc_show_options(struct seq_file *seq, struct dentry *root)
{
	struct super_block *sb = root->d_sb;
	struct pid_namespace *pid = sb->s_fs_info;

	if (!gid_eq(pid->pid_gid, GLOBAL_ROOT_GID))
		seq_printf(seq, ",gid=%u", from_kgid_munged(&init_user_ns, pid->pid_gid));
	if (pid->hide_pid != 0)
		seq_printf(seq, ",hidepid=%u", pid->hide_pid);

	return 0;
}

static const struct super_operations proc_sops = {
	.alloc_inode	= proc_alloc_inode,
	.destroy_inode	= proc_destroy_inode,
	.drop_inode	= generic_delete_inode,
	.evict_inode	= proc_evict_inode,
	.statfs		= simple_statfs,
	.remount_fs	= proc_remount,
	.show_options	= proc_show_options,
};

enum {BIAS = -1U<<31};

static inline int use_pde(struct proc_dir_entry *pde)
{
	return atomic_inc_unless_negative(&pde->in_use);
}

static void unuse_pde(struct proc_dir_entry *pde)
{
	if (atomic_dec_return(&pde->in_use) == BIAS)
		complete(pde->pde_unload_completion);
}

/* pde is locked */
static void close_pdeo(struct proc_dir_entry *pde, struct pde_opener *pdeo)
{
	if (pdeo->closing) {
		/* somebody else is doing that, just wait */
		DECLARE_COMPLETION_ONSTACK(c);
		pdeo->c = &c;
		spin_unlock(&pde->pde_unload_lock);
		wait_for_completion(&c);
		spin_lock(&pde->pde_unload_lock);
	} else {
		struct file *file;
		pdeo->closing = 1;
		spin_unlock(&pde->pde_unload_lock);
		file = pdeo->file;
		pde->proc_fops->release(file_inode(file), file);
		spin_lock(&pde->pde_unload_lock);
		list_del_init(&pdeo->lh);
		if (pdeo->c)
			complete(pdeo->c);
		kfree(pdeo);
	}
}

void proc_entry_rundown(struct proc_dir_entry *de)
{
	DECLARE_COMPLETION_ONSTACK(c);
	/* Wait until all existing callers into module are done. */
	de->pde_unload_completion = &c;
	if (atomic_add_return(BIAS, &de->in_use) != BIAS)
		wait_for_completion(&c);

	spin_lock(&de->pde_unload_lock);
	while (!list_empty(&de->pde_openers)) {
		struct pde_opener *pdeo;
		pdeo = list_first_entry(&de->pde_openers, struct pde_opener, lh);
		close_pdeo(de, pdeo);
	}
	spin_unlock(&de->pde_unload_lock);
}

static loff_t proc_reg_llseek(struct file *file, loff_t offset, int whence)
{
	struct proc_dir_entry *pde = PDE(file_inode(file));
	loff_t rv = -EINVAL;
	if (use_pde(pde)) {
		loff_t (*llseek)(struct file *, loff_t, int);
		llseek = pde->proc_fops->llseek;
		if (!llseek)
			llseek = default_llseek;
		rv = llseek(file, offset, whence);
		unuse_pde(pde);
	}
	return rv;
}

static ssize_t proc_reg_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	ssize_t (*read)(struct file *, char __user *, size_t, loff_t *);
	struct proc_dir_entry *pde = PDE(file_inode(file));
	ssize_t rv = -EIO;
	if (use_pde(pde)) {
		read = pde->proc_fops->read;
		if (read)
			rv = read(file, buf, count, ppos);
		unuse_pde(pde);
	}
	return rv;
}

static ssize_t proc_reg_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	ssize_t (*write)(struct file *, const char __user *, size_t, loff_t *);
	struct proc_dir_entry *pde = PDE(file_inode(file));
	ssize_t rv = -EIO;
	if (use_pde(pde)) {
		write = pde->proc_fops->write;
		if (write)
			rv = write(file, buf, count, ppos);
		unuse_pde(pde);
	}
	return rv;
}

static unsigned int proc_reg_poll(struct file *file, struct poll_table_struct *pts)
{
	struct proc_dir_entry *pde = PDE(file_inode(file));
	unsigned int rv = DEFAULT_POLLMASK;
	unsigned int (*poll)(struct file *, struct poll_table_struct *);
	if (use_pde(pde)) {
		poll = pde->proc_fops->poll;
		if (poll)
			rv = poll(file, pts);
		unuse_pde(pde);
	}
	return rv;
}

static long proc_reg_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct proc_dir_entry *pde = PDE(file_inode(file));
	long rv = -ENOTTY;
	long (*ioctl)(struct file *, unsigned int, unsigned long);
	if (use_pde(pde)) {
		ioctl = pde->proc_fops->unlocked_ioctl;
		if (ioctl)
			rv = ioctl(file, cmd, arg);
		unuse_pde(pde);
	}
	return rv;
}

#ifdef CONFIG_COMPAT
static long proc_reg_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct proc_dir_entry *pde = PDE(file_inode(file));
	long rv = -ENOTTY;
	long (*compat_ioctl)(struct file *, unsigned int, unsigned long);
	if (use_pde(pde)) {
		compat_ioctl = pde->proc_fops->compat_ioctl;
		if (compat_ioctl)
			rv = compat_ioctl(file, cmd, arg);
		unuse_pde(pde);
	}
	return rv;
}
#endif

static int proc_reg_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct proc_dir_entry *pde = PDE(file_inode(file));
	int rv = -EIO;
	int (*mmap)(struct file *, struct vm_area_struct *);
	if (use_pde(pde)) {
		mmap = pde->proc_fops->mmap;
		if (mmap)
			rv = mmap(file, vma);
		unuse_pde(pde);
	}
	return rv;
}

static unsigned long
proc_reg_get_unmapped_area(struct file *file, unsigned long orig_addr,
			   unsigned long len, unsigned long pgoff,
			   unsigned long flags)
{
	struct proc_dir_entry *pde = PDE(file_inode(file));
	unsigned long rv = -EIO;

	if (use_pde(pde)) {
		typeof(proc_reg_get_unmapped_area) *get_area;

		get_area = pde->proc_fops->get_unmapped_area;
#ifdef CONFIG_MMU
		if (!get_area)
			get_area = current->mm->get_unmapped_area;
#endif

		if (get_area)
			rv = get_area(file, orig_addr, len, pgoff, flags);
		else
			rv = orig_addr;
		unuse_pde(pde);
	}
	return rv;
}

static int proc_reg_open(struct inode *inode, struct file *file)
{
	struct proc_dir_entry *pde = PDE(inode);
	int rv = 0;
	int (*open)(struct inode *, struct file *);
	int (*release)(struct inode *, struct file *);
	struct pde_opener *pdeo;

	/*
	 * What for, you ask? Well, we can have open, rmmod, remove_proc_entry
	 * sequence. ->release won't be called because ->proc_fops will be
	 * cleared. Depending on complexity of ->release, consequences vary.
	 *
	 * We can't wait for mercy when close will be done for real, it's
	 * deadlockable: rmmod foo </proc/foo . So, we're going to do ->release
	 * by hand in remove_proc_entry(). For this, save opener's credentials
	 * for later.
	 */
	pdeo = kzalloc(sizeof(struct pde_opener), GFP_KERNEL);
	if (!pdeo)
		return -ENOMEM;

	if (!use_pde(pde)) {
		kfree(pdeo);
		return -ENOENT;
	}
	open = pde->proc_fops->open;
	release = pde->proc_fops->release;

	if (open)
		rv = open(inode, file);

	if (rv == 0 && release) {
		/* To know what to release. */
		pdeo->file = file;
		/* Strictly for "too late" ->release in proc_reg_release(). */
		spin_lock(&pde->pde_unload_lock);
		list_add(&pdeo->lh, &pde->pde_openers);
		spin_unlock(&pde->pde_unload_lock);
	} else
		kfree(pdeo);

	unuse_pde(pde);
	return rv;
}

static int proc_reg_release(struct inode *inode, struct file *file)
{
	struct proc_dir_entry *pde = PDE(inode);
	struct pde_opener *pdeo;
	spin_lock(&pde->pde_unload_lock);
	list_for_each_entry(pdeo, &pde->pde_openers, lh) {
		if (pdeo->file == file) {
			close_pdeo(pde, pdeo);
			break;
		}
	}
	spin_unlock(&pde->pde_unload_lock);
	return 0;
}

static const struct file_operations proc_reg_file_ops = {
	.llseek		= proc_reg_llseek,
	.read		= proc_reg_read,
	.write		= proc_reg_write,
	.poll		= proc_reg_poll,
	.unlocked_ioctl	= proc_reg_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= proc_reg_compat_ioctl,
#endif
	.mmap		= proc_reg_mmap,
	.get_unmapped_area = proc_reg_get_unmapped_area,
	.open		= proc_reg_open,
	.release	= proc_reg_release,
};

#ifdef CONFIG_COMPAT
static const struct file_operations proc_reg_file_ops_no_compat = {
	.llseek		= proc_reg_llseek,
	.read		= proc_reg_read,
	.write		= proc_reg_write,
	.poll		= proc_reg_poll,
	.unlocked_ioctl	= proc_reg_unlocked_ioctl,
	.mmap		= proc_reg_mmap,
	.get_unmapped_area = proc_reg_get_unmapped_area,
	.open		= proc_reg_open,
	.release	= proc_reg_release,
};
#endif

struct inode *proc_get_inode(struct super_block *sb, struct proc_dir_entry *de)
{
	struct inode *inode = new_inode_pseudo(sb);

	if (inode) {
		inode->i_ino = de->low_ino;
		inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
		PROC_I(inode)->pde = de;

		if (de->mode) {
			inode->i_mode = de->mode;
			inode->i_uid = de->uid;
			inode->i_gid = de->gid;
		}
		if (de->size)
			inode->i_size = de->size;
		if (de->nlink)
			set_nlink(inode, de->nlink);
		WARN_ON(!de->proc_iops);
		inode->i_op = de->proc_iops;
		if (de->proc_fops) {
			if (S_ISREG(inode->i_mode)) {
#ifdef CONFIG_COMPAT
				if (!de->proc_fops->compat_ioctl)
					inode->i_fop =
						&proc_reg_file_ops_no_compat;
				else
#endif
					inode->i_fop = &proc_reg_file_ops;
			} else {
				inode->i_fop = de->proc_fops;
			}
		}
	} else
	       pde_put(de);
	return inode;
}

int proc_fill_super(struct super_block *s)
{
	struct inode *root_inode;
	int ret;

	s->s_flags |= MS_NODIRATIME | MS_NOSUID | MS_NOEXEC;
	s->s_blocksize = 1024;
	s->s_blocksize_bits = 10;
	s->s_magic = PROC_SUPER_MAGIC;
	s->s_op = &proc_sops;
	s->s_time_gran = 1;

	pde_get(&proc_root);
	root_inode = proc_get_inode(s, &proc_root);
	if (!root_inode) {
		pr_err("proc_fill_super: get root inode failed\n");
		return -ENOMEM;
	}

	s->s_root = d_make_root(root_inode);
	if (!s->s_root) {
		pr_err("proc_fill_super: allocate dentry failed\n");
		return -ENOMEM;
	}

	ret = proc_setup_self(s);
	if (ret) {
		return ret;
	}
	return proc_setup_thread_self(s);
}
/************************************************************/
/* ../linux-3.17/fs/proc/inode.c */
/************************************************************/
/*
 *  linux/fs/proc/root.c
 *
 *  Copyright (C) 1991, 1992 Linus Torvalds
 *
 *  proc root directory handling functions
 */

// #include <asm/uaccess.h>

// #include <linux/errno.h>
// #include <linux/time.h>
// #include <linux/proc_fs.h>
// #include <linux/stat.h>
// #include <linux/init.h>
#include <linux/sched.h>
// #include <linux/module.h>
#include <linux/bitops.h>
#include <linux/user_namespace.h>
// #include <linux/mount.h>
// #include <linux/pid_namespace.h>
#include <linux/parser.h>

// #include "internal.h"

static int proc_test_super(struct super_block *sb, void *data)
{
	return sb->s_fs_info == data;
}

static int proc_set_super(struct super_block *sb, void *data)
{
	int err = set_anon_super(sb, NULL);
	if (!err) {
		struct pid_namespace *ns = (struct pid_namespace *)data;
		sb->s_fs_info = get_pid_ns(ns);
	}
	return err;
}

enum {
	Opt_gid, Opt_hidepid, Opt_err,
};

static const match_table_t tokens = {
	{Opt_hidepid, "hidepid=%u"},
	{Opt_gid, "gid=%u"},
	{Opt_err, NULL},
};

static int proc_parse_options(char *options, struct pid_namespace *pid)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int option;

	if (!options)
		return 1;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;
		if (!*p)
			continue;

		args[0].to = args[0].from = NULL;
		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_gid:
			if (match_int(&args[0], &option))
				return 0;
			pid->pid_gid = make_kgid(current_user_ns(), option);
			break;
		case Opt_hidepid:
			if (match_int(&args[0], &option))
				return 0;
			if (option < 0 || option > 2) {
				pr_err("proc: hidepid value must be between 0 and 2.\n");
				return 0;
			}
			pid->hide_pid = option;
			break;
		default:
			pr_err("proc: unrecognized mount option \"%s\" "
			       "or missing value\n", p);
			return 0;
		}
	}

	return 1;
}

int proc_remount(struct super_block *sb, int *flags, char *data)
{
	struct pid_namespace *pid = sb->s_fs_info;

	sync_filesystem(sb);
	return !proc_parse_options(data, pid);
}

static struct dentry *proc_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	int err;
	struct super_block *sb;
	struct pid_namespace *ns;
	char *options;

	if (flags & MS_KERNMOUNT) {
		ns = (struct pid_namespace *)data;
		options = NULL;
	} else {
		ns = task_active_pid_ns(current);
		options = data;

		if (!capable(CAP_SYS_ADMIN) && !fs_fully_visible(fs_type))
			return ERR_PTR(-EPERM);

		/* Does the mounter have privilege over the pid namespace? */
		if (!ns_capable(ns->user_ns, CAP_SYS_ADMIN))
			return ERR_PTR(-EPERM);
	}

	sb = sget(fs_type, proc_test_super, proc_set_super, flags, ns);
	if (IS_ERR(sb))
		return ERR_CAST(sb);

	if (!proc_parse_options(options, ns)) {
		deactivate_locked_super(sb);
		return ERR_PTR(-EINVAL);
	}

	if (!sb->s_root) {
		err = proc_fill_super(sb);
		if (err) {
			deactivate_locked_super(sb);
			return ERR_PTR(err);
		}

		sb->s_flags |= MS_ACTIVE;
	}

	return dget(sb->s_root);
}

static void proc_kill_sb(struct super_block *sb)
{
	struct pid_namespace *ns;

	ns = (struct pid_namespace *)sb->s_fs_info;
	if (ns->proc_self)
		dput(ns->proc_self);
	if (ns->proc_thread_self)
		dput(ns->proc_thread_self);
	kill_anon_super(sb);
	put_pid_ns(ns);
}

static struct file_system_type proc_fs_type = {
	.name		= "proc",
	.mount		= proc_mount,
	.kill_sb	= proc_kill_sb,
	.fs_flags	= FS_USERNS_MOUNT,
};

void __init proc_root_init(void)
{
	int err;

	proc_init_inodecache();
	err = register_filesystem(&proc_fs_type);
	if (err)
		return;

	proc_self_init();
	proc_thread_self_init();
	proc_symlink("mounts", NULL, "self/mounts");

	proc_net_init();

#ifdef CONFIG_SYSVIPC
	proc_mkdir("sysvipc", NULL);
#endif
	proc_mkdir("fs", NULL);
	proc_mkdir("driver", NULL);
	proc_mkdir("fs/nfsd", NULL); /* somewhere for the nfsd filesystem to be mounted */
#if defined(CONFIG_SUN_OPENPROMFS) || defined(CONFIG_SUN_OPENPROMFS_MODULE)
	/* just give it a mountpoint */
	proc_mkdir("openprom", NULL);
#endif
	proc_tty_init();
	proc_mkdir("bus", NULL);
	proc_sys_init();
}

static int proc_root_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat
)
{
	generic_fillattr(dentry->d_inode, stat);
	stat->nlink = proc_root.nlink + nr_processes();
	return 0;
}

static struct dentry *proc_root_lookup(struct inode * dir, struct dentry * dentry, unsigned int flags)
{
	if (!proc_pid_lookup(dir, dentry, flags))
		return NULL;

	return proc_lookup(dir, dentry, flags);
}

static int proc_root_readdir(struct file *file, struct dir_context *ctx)
{
	if (ctx->pos < FIRST_PROCESS_ENTRY) {
		int error = proc_readdir(file, ctx);
		if (unlikely(error <= 0))
			return error;
		ctx->pos = FIRST_PROCESS_ENTRY;
	}

	return proc_pid_readdir(file, ctx);
}

/*
 * The root /proc directory is special, as it has the
 * <pid> directories. Thus we don't use the generic
 * directory handling functions for that..
 */
static const struct file_operations proc_root_operations = {
	.read		 = generic_read_dir,
	.iterate	 = proc_root_readdir,
	.llseek		= default_llseek,
};

/*
 * proc root can do almost nothing..
 */
static const struct inode_operations proc_root_inode_operations = {
	.lookup		= proc_root_lookup,
	.getattr	= proc_root_getattr,
};

/*
 * This is the root "inode" in the /proc tree..
 */
struct proc_dir_entry proc_root = {
	.low_ino	= PROC_ROOT_INO,
	.namelen	= 5,
	.mode		= S_IFDIR | S_IRUGO | S_IXUGO,
	.nlink		= 2,
	.count		= ATOMIC_INIT(1),
	.proc_iops	= &proc_root_inode_operations,
	.proc_fops	= &proc_root_operations,
	.parent		= &proc_root,
	.name		= "/proc",
};

int pid_ns_prepare_proc(struct pid_namespace *ns)
{
	struct vfsmount *mnt;

	mnt = kern_mount_data(&proc_fs_type, ns);
	if (IS_ERR(mnt))
		return PTR_ERR(mnt);

	ns->proc_mnt = mnt;
	return 0;
}

void pid_ns_release_proc(struct pid_namespace *ns)
{
	kern_unmount(ns->proc_mnt);
}
/************************************************************/
/* ../linux-3.17/fs/proc/root.c */
/************************************************************/
/*
 *  linux/fs/proc/base.c
 *
 *  Copyright (C) 1991, 1992 Linus Torvalds
 *
 *  proc base directory handling functions
 *
 *  1999, Al Viro. Rewritten. Now it covers the whole per-process part.
 *  Instead of using magical inumbers to determine the kind of object
 *  we allocate and fill in-core inodes upon lookup. They don't even
 *  go into icache. We cache the reference to task_struct upon lookup too.
 *  Eventually it should become a filesystem in its own. We don't use the
 *  rest of procfs anymore.
 *
 *
 *  Changelog:
 *  17-Jan-2005
 *  Allan Bezerra
 *  Bruna Moreira <bruna.moreira@indt.org.br>
 *  Edjard Mota <edjard.mota@indt.org.br>
 *  Ilias Biris <ilias.biris@indt.org.br>
 *  Mauricio Lin <mauricio.lin@indt.org.br>
 *
 *  Embedded Linux Lab - 10LE Instituto Nokia de Tecnologia - INdT
 *
 *  A new process specific entry (smaps) included in /proc. It shows the
 *  size of rss for each memory area. The maps entry lacks information
 *  about physical memory size (rss) for each mapped file, i.e.,
 *  rss information for executables and library files.
 *  This additional information is useful for any tools that need to know
 *  about physical memory consumption for a process specific library.
 *
 *  Changelog:
 *  21-Feb-2005
 *  Embedded Linux Lab - 10LE Instituto Nokia de Tecnologia - INdT
 *  Pud inclusion in the page table walking.
 *
 *  ChangeLog:
 *  10-Mar-2005
 *  10LE Instituto Nokia de Tecnologia - INdT:
 *  A better way to walks through the page table as suggested by Hugh Dickins.
 *
 *  Simo Piiroinen <simo.piiroinen@nokia.com>:
 *  Smaps information related to shared, private, clean and dirty pages.
 *
 *  Paul Mundt <paul.mundt@nokia.com>:
 *  Overall revision about smaps.
 */

// #include <asm/uaccess.h>

// #include <linux/errno.h>
// #include <linux/time.h>
// #include <linux/proc_fs.h>
// #include <linux/stat.h>
#include <linux/task_io_accounting_ops.h>
// #include <linux/init.h>
#include <linux/capability.h>
// #include <linux/file.h>
// #include <linux/fdtable.h>
// #include <linux/string.h>
// #include <linux/seq_file.h>
#include <linux/namei.h>
#include <linux/mnt_namespace.h>
// #include <linux/mm.h>
// #include <linux/swap.h>
#include <linux/rcupdate.h>
#include <linux/kallsyms.h>
#include <linux/stacktrace.h>
#include <linux/resource.h>
// #include <linux/module.h>
// #include <linux/mount.h>
#include <linux/security.h>
// #include <linux/ptrace.h>
#include <linux/tracehook.h>
// #include <linux/printk.h>
#include <linux/cgroup.h>
#include <linux/cpuset.h>
#include <linux/audit.h>
// #include <linux/poll.h>
#include <linux/nsproxy.h>
#include <linux/oom.h>
#include <linux/elf.h>
// #include <linux/pid_namespace.h>
// #include <linux/user_namespace.h>
// #include <linux/fs_struct.h>
// #include <linux/slab.h>
#include <linux/flex_array.h>
#include <linux/posix-timers.h>
#ifdef CONFIG_HARDWALL
#include <asm/hardwall.h>
#endif
#include <trace/events/oom.h>
// #include "internal.h"
#include "fd.h"

/* NOTE:
 *	Implementing inode permission operations in /proc is almost
 *	certainly an error.  Permission checks need to happen during
 *	each system call not at open time.  The reason is that most of
 *	what we wish to check for permissions in /proc varies at runtime.
 *
 *	The classic example of a problem is opening file descriptors
 *	in /proc for a task before it execs a suid executable.
 */

struct pid_entry {
	const char *name;
	int len;
	umode_t mode;
	const struct inode_operations *iop;
	const struct file_operations *fop;
	union proc_op op;
};

#define NOD(NAME, MODE, IOP, FOP, OP) {			\
	.name = (NAME),					\
	.len  = sizeof(NAME) - 1,			\
	.mode = MODE,					\
	.iop  = IOP,					\
	.fop  = FOP,					\
	.op   = OP,					\
}

#define DIR(NAME, MODE, iops, fops)	\
	NOD(NAME, (S_IFDIR|(MODE)), &iops, &fops, {} )
#define LNK(NAME, get_link)					\
	NOD(NAME, (S_IFLNK|S_IRWXUGO),				\
		&proc_pid_link_inode_operations, NULL,		\
		{ .proc_get_link = get_link } )
#define REG(NAME, MODE, fops)				\
	NOD(NAME, (S_IFREG|(MODE)), NULL, &fops, {})
#define ONE(NAME, MODE, show)				\
	NOD(NAME, (S_IFREG|(MODE)), 			\
		NULL, &proc_single_file_operations,	\
		{ .proc_show = show } )

/*
 * Count the number of hardlinks for the pid_entry table, excluding the .
 * and .. links.
 */
static unsigned int pid_entry_count_dirs(const struct pid_entry *entries,
	unsigned int n)
{
	unsigned int i;
	unsigned int count;

	count = 0;
	for (i = 0; i < n; ++i) {
		if (S_ISDIR(entries[i].mode))
			++count;
	}

	return count;
}

static int get_task_root(struct task_struct *task, struct path *root)
{
	int result = -ENOENT;

	task_lock(task);
	if (task->fs) {
		get_fs_root(task->fs, root);
		result = 0;
	}
	task_unlock(task);
	return result;
}

static int proc_cwd_link(struct dentry *dentry, struct path *path)
{
	struct task_struct *task = get_proc_task(dentry->d_inode);
	int result = -ENOENT;

	if (task) {
		task_lock(task);
		if (task->fs) {
			get_fs_pwd(task->fs, path);
			result = 0;
		}
		task_unlock(task);
		put_task_struct(task);
	}
	return result;
}

static int proc_root_link(struct dentry *dentry, struct path *path)
{
	struct task_struct *task = get_proc_task(dentry->d_inode);
	int result = -ENOENT;

	if (task) {
		result = get_task_root(task, path);
		put_task_struct(task);
	}
	return result;
}

static int proc_pid_cmdline(struct seq_file *m, struct pid_namespace *ns,
			    struct pid *pid, struct task_struct *task)
{
	/*
	 * Rely on struct seq_operations::show() being called once
	 * per internal buffer allocation. See single_open(), traverse().
	 */
	BUG_ON(m->size < PAGE_SIZE);
	m->count += get_cmdline(task, m->buf, PAGE_SIZE);
	return 0;
}

static int proc_pid_auxv(struct seq_file *m, struct pid_namespace *ns,
			 struct pid *pid, struct task_struct *task)
{
	struct mm_struct *mm = mm_access(task, PTRACE_MODE_READ);
	if (mm && !IS_ERR(mm)) {
		unsigned int nwords = 0;
		do {
			nwords += 2;
		} while (mm->saved_auxv[nwords - 2] != 0); /* AT_NULL */
		seq_write(m, mm->saved_auxv, nwords * sizeof(mm->saved_auxv[0]));
		mmput(mm);
		return 0;
	} else
		return PTR_ERR(mm);
}


#ifdef CONFIG_KALLSYMS
/*
 * Provides a wchan file via kallsyms in a proper one-value-per-file format.
 * Returns the resolved symbol.  If that fails, simply return the address.
 */
static int proc_pid_wchan(struct seq_file *m, struct pid_namespace *ns,
			  struct pid *pid, struct task_struct *task)
{
	unsigned long wchan;
	char symname[KSYM_NAME_LEN];

	wchan = get_wchan(task);

	if (lookup_symbol_name(wchan, symname) < 0)
		if (!ptrace_may_access(task, PTRACE_MODE_READ))
			return 0;
		else
			return seq_printf(m, "%lu", wchan);
	else
		return seq_printf(m, "%s", symname);
}
#endif /* CONFIG_KALLSYMS */

static int lock_trace(struct task_struct *task)
{
	int err = mutex_lock_killable(&task->signal->cred_guard_mutex);
	if (err)
		return err;
	if (!ptrace_may_access(task, PTRACE_MODE_ATTACH)) {
		mutex_unlock(&task->signal->cred_guard_mutex);
		return -EPERM;
	}
	return 0;
}

static void unlock_trace(struct task_struct *task)
{
	mutex_unlock(&task->signal->cred_guard_mutex);
}

#ifdef CONFIG_STACKTRACE

#define MAX_STACK_TRACE_DEPTH	64

static int proc_pid_stack(struct seq_file *m, struct pid_namespace *ns,
			  struct pid *pid, struct task_struct *task)
{
	struct stack_trace trace;
	unsigned long *entries;
	int err;
	int i;

	entries = kmalloc(MAX_STACK_TRACE_DEPTH * sizeof(*entries), GFP_KERNEL);
	if (!entries)
		return -ENOMEM;

	trace.nr_entries	= 0;
	trace.max_entries	= MAX_STACK_TRACE_DEPTH;
	trace.entries		= entries;
	trace.skip		= 0;

	err = lock_trace(task);
	if (!err) {
		save_stack_trace_tsk(task, &trace);

		for (i = 0; i < trace.nr_entries; i++) {
			seq_printf(m, "[<%pK>] %pS\n",
				   (void *)entries[i], (void *)entries[i]);
		}
		unlock_trace(task);
	}
	kfree(entries);

	return err;
}
#endif

#ifdef CONFIG_SCHEDSTATS
/*
 * Provides /proc/PID/schedstat
 */
static int proc_pid_schedstat(struct seq_file *m, struct pid_namespace *ns,
			      struct pid *pid, struct task_struct *task)
{
	return seq_printf(m, "%llu %llu %lu\n",
			(unsigned long long)task->se.sum_exec_runtime,
			(unsigned long long)task->sched_info.run_delay,
			task->sched_info.pcount);
}
#endif

#ifdef CONFIG_LATENCYTOP
static int lstats_show_proc(struct seq_file *m, void *v)
{
	int i;
	struct inode *inode = m->private;
	struct task_struct *task = get_proc_task(inode);

	if (!task)
		return -ESRCH;
	seq_puts(m, "Latency Top version : v0.1\n");
	for (i = 0; i < 32; i++) {
		struct latency_record *lr = &task->latency_record[i];
		if (lr->backtrace[0]) {
			int q;
			seq_printf(m, "%i %li %li",
				   lr->count, lr->time, lr->max);
			for (q = 0; q < LT_BACKTRACEDEPTH; q++) {
				unsigned long bt = lr->backtrace[q];
				if (!bt)
					break;
				if (bt == ULONG_MAX)
					break;
				seq_printf(m, " %ps", (void *)bt);
			}
			seq_putc(m, '\n');
		}

	}
	put_task_struct(task);
	return 0;
}

static int lstats_open(struct inode *inode, struct file *file)
{
	return single_open(file, lstats_show_proc, inode);
}

static ssize_t lstats_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *offs)
{
	struct task_struct *task = get_proc_task(file_inode(file));

	if (!task)
		return -ESRCH;
	clear_all_latency_tracing(task);
	put_task_struct(task);

	return count;
}

static const struct file_operations proc_lstats_operations = {
	.open		= lstats_open,
	.read		= seq_read,
	.write		= lstats_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

#endif

#ifdef CONFIG_CGROUPS
static int cgroup_open(struct inode *inode, struct file *file)
{
	struct pid *pid = PROC_I(inode)->pid;
	return single_open(file, proc_cgroup_show, pid);
}

static const struct file_operations proc_cgroup_operations = {
	.open		= cgroup_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif

#ifdef CONFIG_PROC_PID_CPUSET

static int cpuset_open(struct inode *inode, struct file *file)
{
	struct pid *pid = PROC_I(inode)->pid;
	return single_open(file, proc_cpuset_show, pid);
}

static const struct file_operations proc_cpuset_operations = {
	.open		= cpuset_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif

static int proc_oom_score(struct seq_file *m, struct pid_namespace *ns,
			  struct pid *pid, struct task_struct *task)
{
	unsigned long totalpages = totalram_pages + total_swap_pages;
	unsigned long points = 0;

	read_lock(&tasklist_lock);
	if (pid_alive(task))
		points = oom_badness(task, NULL, NULL, totalpages) *
						1000 / totalpages;
	read_unlock(&tasklist_lock);
	return seq_printf(m, "%lu\n", points);
}

struct limit_names {
	const char *name;
	const char *unit;
};

static const struct limit_names lnames[RLIM_NLIMITS] = {
	[RLIMIT_CPU] = {"Max cpu time", "seconds"},
	[RLIMIT_FSIZE] = {"Max file size", "bytes"},
	[RLIMIT_DATA] = {"Max data size", "bytes"},
	[RLIMIT_STACK] = {"Max stack size", "bytes"},
	[RLIMIT_CORE] = {"Max core file size", "bytes"},
	[RLIMIT_RSS] = {"Max resident set", "bytes"},
	[RLIMIT_NPROC] = {"Max processes", "processes"},
	[RLIMIT_NOFILE] = {"Max open files", "files"},
	[RLIMIT_MEMLOCK] = {"Max locked memory", "bytes"},
	[RLIMIT_AS] = {"Max address space", "bytes"},
	[RLIMIT_LOCKS] = {"Max file locks", "locks"},
	[RLIMIT_SIGPENDING] = {"Max pending signals", "signals"},
	[RLIMIT_MSGQUEUE] = {"Max msgqueue size", "bytes"},
	[RLIMIT_NICE] = {"Max nice priority", NULL},
	[RLIMIT_RTPRIO] = {"Max realtime priority", NULL},
	[RLIMIT_RTTIME] = {"Max realtime timeout", "us"},
};

/* Display limits for a process */
static int proc_pid_limits(struct seq_file *m, struct pid_namespace *ns,
			   struct pid *pid, struct task_struct *task)
{
	unsigned int i;
	unsigned long flags;

	struct rlimit rlim[RLIM_NLIMITS];

	if (!lock_task_sighand(task, &flags))
		return 0;
	memcpy(rlim, task->signal->rlim, sizeof(struct rlimit) * RLIM_NLIMITS);
	unlock_task_sighand(task, &flags);

	/*
	 * print the file header
	 */
       seq_printf(m, "%-25s %-20s %-20s %-10s\n",
			"Limit", "Soft Limit", "Hard Limit", "Units");

	for (i = 0; i < RLIM_NLIMITS; i++) {
		if (rlim[i].rlim_cur == RLIM_INFINITY)
			seq_printf(m, "%-25s %-20s ",
					 lnames[i].name, "unlimited");
		else
			seq_printf(m, "%-25s %-20lu ",
					 lnames[i].name, rlim[i].rlim_cur);

		if (rlim[i].rlim_max == RLIM_INFINITY)
			seq_printf(m, "%-20s ", "unlimited");
		else
			seq_printf(m, "%-20lu ", rlim[i].rlim_max);

		if (lnames[i].unit)
			seq_printf(m, "%-10s\n", lnames[i].unit);
		else
			seq_putc(m, '\n');
	}

	return 0;
}

#ifdef CONFIG_HAVE_ARCH_TRACEHOOK
static int proc_pid_syscall(struct seq_file *m, struct pid_namespace *ns,
			    struct pid *pid, struct task_struct *task)
{
	long nr;
	unsigned long args[6], sp, pc;
	int res = lock_trace(task);
	if (res)
		return res;

	if (task_current_syscall(task, &nr, args, 6, &sp, &pc))
		seq_puts(m, "running\n");
	else if (nr < 0)
		seq_printf(m, "%ld 0x%lx 0x%lx\n", nr, sp, pc);
	else
		seq_printf(m,
		       "%ld 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx\n",
		       nr,
		       args[0], args[1], args[2], args[3], args[4], args[5],
		       sp, pc);
	unlock_trace(task);
	return res;
}
#endif /* CONFIG_HAVE_ARCH_TRACEHOOK */

/************************************************************************/
/*                       Here the fs part begins                        */
/************************************************************************/

/* permission checks */
static int proc_fd_access_allowed(struct inode *inode)
{
	struct task_struct *task;
	int allowed = 0;
	/* Allow access to a task's file descriptors if it is us or we
	 * may use ptrace attach to the process and find out that
	 * information.
	 */
	task = get_proc_task(inode);
	if (task) {
		allowed = ptrace_may_access(task, PTRACE_MODE_READ);
		put_task_struct(task);
	}
	return allowed;
}

int proc_setattr(struct dentry *dentry, struct iattr *attr)
{
	int error;
	struct inode *inode = dentry->d_inode;

	if (attr->ia_valid & ATTR_MODE)
		return -EPERM;

	error = inode_change_ok(inode, attr);
	if (error)
		return error;

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);
	return 0;
}

/*
 * May current process learn task's sched/cmdline info (for hide_pid_min=1)
 * or euid/egid (for hide_pid_min=2)?
 */
static bool has_pid_permissions(struct pid_namespace *pid,
				 struct task_struct *task,
				 int hide_pid_min)
{
	if (pid->hide_pid < hide_pid_min)
		return true;
	if (in_group_p(pid->pid_gid))
		return true;
	return ptrace_may_access(task, PTRACE_MODE_READ);
}


static int proc_pid_permission(struct inode *inode, int mask)
{
	struct pid_namespace *pid = inode->i_sb->s_fs_info;
	struct task_struct *task;
	bool has_perms;

	task = get_proc_task(inode);
	if (!task)
		return -ESRCH;
	has_perms = has_pid_permissions(pid, task, 1);
	put_task_struct(task);

	if (!has_perms) {
		if (pid->hide_pid == 2) {
			/*
			 * Let's make getdents(), stat(), and open()
			 * consistent with each other.  If a process
			 * may not stat() a file, it shouldn't be seen
			 * in procfs at all.
			 */
			return -ENOENT;
		}

		return -EPERM;
	}
	return generic_permission(inode, mask);
}



static const struct inode_operations proc_def_inode_operations = {
	.setattr	= proc_setattr,
};

static int proc_single_show(struct seq_file *m, void *v)
{
	struct inode *inode = m->private;
	struct pid_namespace *ns;
	struct pid *pid;
	struct task_struct *task;
	int ret;

	ns = inode->i_sb->s_fs_info;
	pid = proc_pid(inode);
	task = get_pid_task(pid, PIDTYPE_PID);
	if (!task)
		return -ESRCH;

	ret = PROC_I(inode)->op.proc_show(m, ns, pid, task);

	put_task_struct(task);
	return ret;
}

static int proc_single_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, proc_single_show, inode);
}

static const struct file_operations proc_single_file_operations = {
	.open		= proc_single_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __mem_open(struct inode *inode, struct file *file, unsigned int mode)
{
	struct task_struct *task = get_proc_task(file_inode(file));
	struct mm_struct *mm;

	if (!task)
		return -ESRCH;

	mm = mm_access(task, mode);
	put_task_struct(task);

	if (IS_ERR(mm))
		return PTR_ERR(mm);

	if (mm) {
		/* ensure this mm_struct can't be freed */
		atomic_inc(&mm->mm_count);
		/* but do not pin its memory */
		mmput(mm);
	}

	file->private_data = mm;

	return 0;
}

static int mem_open(struct inode *inode, struct file *file)
{
	int ret = __mem_open(inode, file, PTRACE_MODE_ATTACH);

	/* OK to pass negative loff_t, we can catch out-of-range */
	file->f_mode |= FMODE_UNSIGNED_OFFSET;

	return ret;
}

static ssize_t mem_rw(struct file *file, char __user *buf,
			size_t count, loff_t *ppos, int write)
{
	struct mm_struct *mm = file->private_data;
	unsigned long addr = *ppos;
	ssize_t copied;
	char *page;

	if (!mm)
		return 0;

	page = (char *)__get_free_page(GFP_TEMPORARY);
	if (!page)
		return -ENOMEM;

	copied = 0;
	if (!atomic_inc_not_zero(&mm->mm_users))
		goto free;

	while (count > 0) {
		int this_len = min_t(int, count, PAGE_SIZE);

		if (write && copy_from_user(page, buf, this_len)) {
			copied = -EFAULT;
			break;
		}

		this_len = access_remote_vm(mm, addr, page, this_len, write);
		if (!this_len) {
			if (!copied)
				copied = -EIO;
			break;
		}

		if (!write && copy_to_user(buf, page, this_len)) {
			copied = -EFAULT;
			break;
		}

		buf += this_len;
		addr += this_len;
		copied += this_len;
		count -= this_len;
	}
	*ppos = addr;

	mmput(mm);
free:
	free_page((unsigned long) page);
	return copied;
}

static ssize_t mem_read(struct file *file, char __user *buf,
			size_t count, loff_t *ppos)
{
	return mem_rw(file, buf, count, ppos, 0);
}

static ssize_t mem_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
	return mem_rw(file, (char __user*)buf, count, ppos, 1);
}

loff_t mem_lseek(struct file *file, loff_t offset, int orig)
{
	switch (orig) {
	case 0:
		file->f_pos = offset;
		break;
	case 1:
		file->f_pos += offset;
		break;
	default:
		return -EINVAL;
	}
	force_successful_syscall_return();
	return file->f_pos;
}

static int mem_release(struct inode *inode, struct file *file)
{
	struct mm_struct *mm = file->private_data;
	if (mm)
		mmdrop(mm);
	return 0;
}

static const struct file_operations proc_mem_operations = {
	.llseek		= mem_lseek,
	.read		= mem_read,
	.write		= mem_write,
	.open		= mem_open,
	.release	= mem_release,
};

static int environ_open(struct inode *inode, struct file *file)
{
	return __mem_open(inode, file, PTRACE_MODE_READ);
}

static ssize_t environ_read(struct file *file, char __user *buf,
			size_t count, loff_t *ppos)
{
	char *page;
	unsigned long src = *ppos;
	int ret = 0;
	struct mm_struct *mm = file->private_data;

	if (!mm)
		return 0;

	page = (char *)__get_free_page(GFP_TEMPORARY);
	if (!page)
		return -ENOMEM;

	ret = 0;
	if (!atomic_inc_not_zero(&mm->mm_users))
		goto free;
	while (count > 0) {
		size_t this_len, max_len;
		int retval;

		if (src >= (mm->env_end - mm->env_start))
			break;

		this_len = mm->env_end - (mm->env_start + src);

		max_len = min_t(size_t, PAGE_SIZE, count);
		this_len = min(max_len, this_len);

		retval = access_remote_vm(mm, (mm->env_start + src),
			page, this_len, 0);

		if (retval <= 0) {
			ret = retval;
			break;
		}

		if (copy_to_user(buf, page, retval)) {
			ret = -EFAULT;
			break;
		}

		ret += retval;
		src += retval;
		buf += retval;
		count -= retval;
	}
	*ppos = src;
	mmput(mm);

free:
	free_page((unsigned long) page);
	return ret;
}

static const struct file_operations proc_environ_operations = {
	.open		= environ_open,
	.read		= environ_read,
	.llseek		= generic_file_llseek,
	.release	= mem_release,
};

static ssize_t oom_adj_read(struct file *file, char __user *buf, size_t count,
			    loff_t *ppos)
{
	struct task_struct *task = get_proc_task(file_inode(file));
	char buffer[PROC_NUMBUF];
	int oom_adj = OOM_ADJUST_MIN;
	size_t len;
	unsigned long flags;

	if (!task)
		return -ESRCH;
	if (lock_task_sighand(task, &flags)) {
		if (task->signal->oom_score_adj == OOM_SCORE_ADJ_MAX)
			oom_adj = OOM_ADJUST_MAX;
		else
			oom_adj = (task->signal->oom_score_adj * -OOM_DISABLE) /
				  OOM_SCORE_ADJ_MAX;
		unlock_task_sighand(task, &flags);
	}
	put_task_struct(task);
	len = snprintf(buffer, sizeof(buffer), "%d\n", oom_adj);
	return simple_read_from_buffer(buf, count, ppos, buffer, len);
}

static ssize_t oom_adj_write(struct file *file, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	struct task_struct *task;
	char buffer[PROC_NUMBUF];
	int oom_adj;
	unsigned long flags;
	int err;

	memset(buffer, 0, sizeof(buffer));
	if (count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;
	if (copy_from_user(buffer, buf, count)) {
		err = -EFAULT;
		goto out;
	}

	err = kstrtoint(strstrip(buffer), 0, &oom_adj);
	if (err)
		goto out;
	if ((oom_adj < OOM_ADJUST_MIN || oom_adj > OOM_ADJUST_MAX) &&
	     oom_adj != OOM_DISABLE) {
		err = -EINVAL;
		goto out;
	}

	task = get_proc_task(file_inode(file));
	if (!task) {
		err = -ESRCH;
		goto out;
	}

	task_lock(task);
	if (!task->mm) {
		err = -EINVAL;
		goto err_task_lock;
	}

	if (!lock_task_sighand(task, &flags)) {
		err = -ESRCH;
		goto err_task_lock;
	}

	/*
	 * Scale /proc/pid/oom_score_adj appropriately ensuring that a maximum
	 * value is always attainable.
	 */
	if (oom_adj == OOM_ADJUST_MAX)
		oom_adj = OOM_SCORE_ADJ_MAX;
	else
		oom_adj = (oom_adj * OOM_SCORE_ADJ_MAX) / -OOM_DISABLE;

	if (oom_adj < task->signal->oom_score_adj &&
	    !capable(CAP_SYS_RESOURCE)) {
		err = -EACCES;
		goto err_sighand;
	}

	/*
	 * /proc/pid/oom_adj is provided for legacy purposes, ask users to use
	 * /proc/pid/oom_score_adj instead.
	 */
	pr_warn_once("%s (%d): /proc/%d/oom_adj is deprecated, please use /proc/%d/oom_score_adj instead.\n",
		  current->comm, task_pid_nr(current), task_pid_nr(task),
		  task_pid_nr(task));

	task->signal->oom_score_adj = oom_adj;
	trace_oom_score_adj_update(task);
err_sighand:
	unlock_task_sighand(task, &flags);
err_task_lock:
	task_unlock(task);
	put_task_struct(task);
out:
	return err < 0 ? err : count;
}

static const struct file_operations proc_oom_adj_operations = {
	.read		= oom_adj_read,
	.write		= oom_adj_write,
	.llseek		= generic_file_llseek,
};

static ssize_t oom_score_adj_read(struct file *file, char __user *buf,
					size_t count, loff_t *ppos)
{
	struct task_struct *task = get_proc_task(file_inode(file));
	char buffer[PROC_NUMBUF];
	short oom_score_adj = OOM_SCORE_ADJ_MIN;
	unsigned long flags;
	size_t len;

	if (!task)
		return -ESRCH;
	if (lock_task_sighand(task, &flags)) {
		oom_score_adj = task->signal->oom_score_adj;
		unlock_task_sighand(task, &flags);
	}
	put_task_struct(task);
	len = snprintf(buffer, sizeof(buffer), "%hd\n", oom_score_adj);
	return simple_read_from_buffer(buf, count, ppos, buffer, len);
}

static ssize_t oom_score_adj_write(struct file *file, const char __user *buf,
					size_t count, loff_t *ppos)
{
	struct task_struct *task;
	char buffer[PROC_NUMBUF];
	unsigned long flags;
	int oom_score_adj;
	int err;

	memset(buffer, 0, sizeof(buffer));
	if (count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;
	if (copy_from_user(buffer, buf, count)) {
		err = -EFAULT;
		goto out;
	}

	err = kstrtoint(strstrip(buffer), 0, &oom_score_adj);
	if (err)
		goto out;
	if (oom_score_adj < OOM_SCORE_ADJ_MIN ||
			oom_score_adj > OOM_SCORE_ADJ_MAX) {
		err = -EINVAL;
		goto out;
	}

	task = get_proc_task(file_inode(file));
	if (!task) {
		err = -ESRCH;
		goto out;
	}

	task_lock(task);
	if (!task->mm) {
		err = -EINVAL;
		goto err_task_lock;
	}

	if (!lock_task_sighand(task, &flags)) {
		err = -ESRCH;
		goto err_task_lock;
	}

	if ((short)oom_score_adj < task->signal->oom_score_adj_min &&
			!capable(CAP_SYS_RESOURCE)) {
		err = -EACCES;
		goto err_sighand;
	}

	task->signal->oom_score_adj = (short)oom_score_adj;
	if (has_capability_noaudit(current, CAP_SYS_RESOURCE))
		task->signal->oom_score_adj_min = (short)oom_score_adj;
	trace_oom_score_adj_update(task);

err_sighand:
	unlock_task_sighand(task, &flags);
err_task_lock:
	task_unlock(task);
	put_task_struct(task);
out:
	return err < 0 ? err : count;
}

static const struct file_operations proc_oom_score_adj_operations = {
	.read		= oom_score_adj_read,
	.write		= oom_score_adj_write,
	.llseek		= default_llseek,
};

#ifdef CONFIG_AUDITSYSCALL
#define TMPBUFLEN 21
static ssize_t proc_loginuid_read(struct file * file, char __user * buf,
				  size_t count, loff_t *ppos)
{
	struct inode * inode = file_inode(file);
	struct task_struct *task = get_proc_task(inode);
	ssize_t length;
	char tmpbuf[TMPBUFLEN];

	if (!task)
		return -ESRCH;
	length = scnprintf(tmpbuf, TMPBUFLEN, "%u",
			   from_kuid(file->f_cred->user_ns,
				     audit_get_loginuid(task)));
	put_task_struct(task);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static ssize_t proc_loginuid_write(struct file * file, const char __user * buf,
				   size_t count, loff_t *ppos)
{
	struct inode * inode = file_inode(file);
	char *page, *tmp;
	ssize_t length;
	uid_t loginuid;
	kuid_t kloginuid;

	rcu_read_lock();
	if (current != pid_task(proc_pid(inode), PIDTYPE_PID)) {
		rcu_read_unlock();
		return -EPERM;
	}
	rcu_read_unlock();

	if (count >= PAGE_SIZE)
		count = PAGE_SIZE - 1;

	if (*ppos != 0) {
		/* No partial writes. */
		return -EINVAL;
	}
	page = (char*)__get_free_page(GFP_TEMPORARY);
	if (!page)
		return -ENOMEM;
	length = -EFAULT;
	if (copy_from_user(page, buf, count))
		goto out_free_page;

	page[count] = '\0';
	loginuid = simple_strtoul(page, &tmp, 10);
	if (tmp == page) {
		length = -EINVAL;
		goto out_free_page;

	}

	/* is userspace tring to explicitly UNSET the loginuid? */
	if (loginuid == AUDIT_UID_UNSET) {
		kloginuid = INVALID_UID;
	} else {
		kloginuid = make_kuid(file->f_cred->user_ns, loginuid);
		if (!uid_valid(kloginuid)) {
			length = -EINVAL;
			goto out_free_page;
		}
	}

	length = audit_set_loginuid(kloginuid);
	if (likely(length == 0))
		length = count;

out_free_page:
	free_page((unsigned long) page);
	return length;
}

static const struct file_operations proc_loginuid_operations = {
	.read		= proc_loginuid_read,
	.write		= proc_loginuid_write,
	.llseek		= generic_file_llseek,
};

static ssize_t proc_sessionid_read(struct file * file, char __user * buf,
				  size_t count, loff_t *ppos)
{
	struct inode * inode = file_inode(file);
	struct task_struct *task = get_proc_task(inode);
	ssize_t length;
	char tmpbuf[TMPBUFLEN];

	if (!task)
		return -ESRCH;
	length = scnprintf(tmpbuf, TMPBUFLEN, "%u",
				audit_get_sessionid(task));
	put_task_struct(task);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static const struct file_operations proc_sessionid_operations = {
	.read		= proc_sessionid_read,
	.llseek		= generic_file_llseek,
};
#endif

#ifdef CONFIG_FAULT_INJECTION
static ssize_t proc_fault_inject_read(struct file * file, char __user * buf,
				      size_t count, loff_t *ppos)
{
	struct task_struct *task = get_proc_task(file_inode(file));
	char buffer[PROC_NUMBUF];
	size_t len;
	int make_it_fail;

	if (!task)
		return -ESRCH;
	make_it_fail = task->make_it_fail;
	put_task_struct(task);

	len = snprintf(buffer, sizeof(buffer), "%i\n", make_it_fail);

	return simple_read_from_buffer(buf, count, ppos, buffer, len);
}

static ssize_t proc_fault_inject_write(struct file * file,
			const char __user * buf, size_t count, loff_t *ppos)
{
	struct task_struct *task;
	char buffer[PROC_NUMBUF], *end;
	int make_it_fail;

	if (!capable(CAP_SYS_RESOURCE))
		return -EPERM;
	memset(buffer, 0, sizeof(buffer));
	if (count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;
	if (copy_from_user(buffer, buf, count))
		return -EFAULT;
	make_it_fail = simple_strtol(strstrip(buffer), &end, 0);
	if (*end)
		return -EINVAL;
	if (make_it_fail < 0 || make_it_fail > 1)
		return -EINVAL;

	task = get_proc_task(file_inode(file));
	if (!task)
		return -ESRCH;
	task->make_it_fail = make_it_fail;
	put_task_struct(task);

	return count;
}

static const struct file_operations proc_fault_inject_operations = {
	.read		= proc_fault_inject_read,
	.write		= proc_fault_inject_write,
	.llseek		= generic_file_llseek,
};
#endif


#ifdef CONFIG_SCHED_DEBUG
/*
 * Print out various scheduling related per-task fields:
 */
static int sched_show(struct seq_file *m, void *v)
{
	struct inode *inode = m->private;
	struct task_struct *p;

	p = get_proc_task(inode);
	if (!p)
		return -ESRCH;
	proc_sched_show_task(p, m);

	put_task_struct(p);

	return 0;
}

static ssize_t
sched_write(struct file *file, const char __user *buf,
	    size_t count, loff_t *offset)
{
	struct inode *inode = file_inode(file);
	struct task_struct *p;

	p = get_proc_task(inode);
	if (!p)
		return -ESRCH;
	proc_sched_set_task(p);

	put_task_struct(p);

	return count;
}

static int sched_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, sched_show, inode);
}

static const struct file_operations proc_pid_sched_operations = {
	.open		= sched_open,
	.read		= seq_read,
	.write		= sched_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

#endif

#ifdef CONFIG_SCHED_AUTOGROUP
/*
 * Print out autogroup related information:
 */
static int sched_autogroup_show(struct seq_file *m, void *v)
{
	struct inode *inode = m->private;
	struct task_struct *p;

	p = get_proc_task(inode);
	if (!p)
		return -ESRCH;
	proc_sched_autogroup_show_task(p, m);

	put_task_struct(p);

	return 0;
}

static ssize_t
sched_autogroup_write(struct file *file, const char __user *buf,
	    size_t count, loff_t *offset)
{
	struct inode *inode = file_inode(file);
	struct task_struct *p;
	char buffer[PROC_NUMBUF];
	int nice;
	int err;

	memset(buffer, 0, sizeof(buffer));
	if (count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;
	if (copy_from_user(buffer, buf, count))
		return -EFAULT;

	err = kstrtoint(strstrip(buffer), 0, &nice);
	if (err < 0)
		return err;

	p = get_proc_task(inode);
	if (!p)
		return -ESRCH;

	err = proc_sched_autogroup_set_nice(p, nice);
	if (err)
		count = err;

	put_task_struct(p);

	return count;
}

static int sched_autogroup_open(struct inode *inode, struct file *filp)
{
	int ret;

	ret = single_open(filp, sched_autogroup_show, NULL);
	if (!ret) {
		struct seq_file *m = filp->private_data;

		m->private = inode;
	}
	return ret;
}

static const struct file_operations proc_pid_sched_autogroup_operations = {
	.open		= sched_autogroup_open,
	.read		= seq_read,
	.write		= sched_autogroup_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

#endif /* CONFIG_SCHED_AUTOGROUP */

static ssize_t comm_write(struct file *file, const char __user *buf,
				size_t count, loff_t *offset)
{
	struct inode *inode = file_inode(file);
	struct task_struct *p;
	char buffer[TASK_COMM_LEN];
	const size_t maxlen = sizeof(buffer) - 1;

	memset(buffer, 0, sizeof(buffer));
	if (copy_from_user(buffer, buf, count > maxlen ? maxlen : count))
		return -EFAULT;

	p = get_proc_task(inode);
	if (!p)
		return -ESRCH;

	if (same_thread_group(current, p))
		set_task_comm(p, buffer);
	else
		count = -EINVAL;

	put_task_struct(p);

	return count;
}

static int comm_show(struct seq_file *m, void *v)
{
	struct inode *inode = m->private;
	struct task_struct *p;

	p = get_proc_task(inode);
	if (!p)
		return -ESRCH;

	task_lock(p);
	seq_printf(m, "%s\n", p->comm);
	task_unlock(p);

	put_task_struct(p);

	return 0;
}

static int comm_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, comm_show, inode);
}

static const struct file_operations proc_pid_set_comm_operations = {
	.open		= comm_open,
	.read		= seq_read,
	.write		= comm_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int proc_exe_link(struct dentry *dentry, struct path *exe_path)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct file *exe_file;

	task = get_proc_task(dentry->d_inode);
	if (!task)
		return -ENOENT;
	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm)
		return -ENOENT;
	exe_file = get_mm_exe_file(mm);
	mmput(mm);
	if (exe_file) {
		*exe_path = exe_file->f_path;
		path_get(&exe_file->f_path);
		fput(exe_file);
		return 0;
	} else
		return -ENOENT;
}

static void *proc_pid_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct inode *inode = dentry->d_inode;
	struct path path;
	int error = -EACCES;

	/* Are we allowed to snoop on the tasks file descriptors? */
	if (!proc_fd_access_allowed(inode))
		goto out;

	error = PROC_I(inode)->op.proc_get_link(dentry, &path);
	if (error)
		goto out;

	nd_jump_link(nd, &path);
	return NULL;
out:
	return ERR_PTR(error);
}

static int do_proc_readlink(struct path *path, char __user *buffer, int buflen)
{
	char *tmp = (char*)__get_free_page(GFP_TEMPORARY);
	char *pathname;
	int len;

	if (!tmp)
		return -ENOMEM;

	pathname = d_path(path, tmp, PAGE_SIZE);
	len = PTR_ERR(pathname);
	if (IS_ERR(pathname))
		goto out;
	len = tmp + PAGE_SIZE - 1 - pathname;

	if (len > buflen)
		len = buflen;
	if (copy_to_user(buffer, pathname, len))
		len = -EFAULT;
 out:
	free_page((unsigned long)tmp);
	return len;
}

static int proc_pid_readlink(struct dentry * dentry, char __user * buffer, int buflen)
{
	int error = -EACCES;
	struct inode *inode = dentry->d_inode;
	struct path path;

	/* Are we allowed to snoop on the tasks file descriptors? */
	if (!proc_fd_access_allowed(inode))
		goto out;

	error = PROC_I(inode)->op.proc_get_link(dentry, &path);
	if (error)
		goto out;

	error = do_proc_readlink(&path, buffer, buflen);
	path_put(&path);
out:
	return error;
}

const struct inode_operations proc_pid_link_inode_operations = {
	.readlink	= proc_pid_readlink,
	.follow_link	= proc_pid_follow_link,
	.setattr	= proc_setattr,
};


/* building an inode */

struct inode *proc_pid_make_inode(struct super_block * sb, struct task_struct *task)
{
	struct inode * inode;
	struct proc_inode *ei;
	const struct cred *cred;

	/* We need a new inode */

	inode = new_inode(sb);
	if (!inode)
		goto out;

	/* Common stuff */
	ei = PROC_I(inode);
	inode->i_ino = get_next_ino();
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
	inode->i_op = &proc_def_inode_operations;

	/*
	 * grab the reference to task.
	 */
	ei->pid = get_task_pid(task, PIDTYPE_PID);
	if (!ei->pid)
		goto out_unlock;

	if (task_dumpable(task)) {
		rcu_read_lock();
		cred = __task_cred(task);
		inode->i_uid = cred->euid;
		inode->i_gid = cred->egid;
		rcu_read_unlock();
	}
	security_task_to_inode(task, inode);

out:
	return inode;

out_unlock:
	iput(inode);
	return NULL;
}

int pid_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat)
{
	struct inode *inode = dentry->d_inode;
	struct task_struct *task;
	const struct cred *cred;
	struct pid_namespace *pid = dentry->d_sb->s_fs_info;

	generic_fillattr(inode, stat);

	rcu_read_lock();
	stat->uid = GLOBAL_ROOT_UID;
	stat->gid = GLOBAL_ROOT_GID;
	task = pid_task(proc_pid(inode), PIDTYPE_PID);
	if (task) {
		if (!has_pid_permissions(pid, task, 2)) {
			rcu_read_unlock();
			/*
			 * This doesn't prevent learning whether PID exists,
			 * it only makes getattr() consistent with readdir().
			 */
			return -ENOENT;
		}
		if ((inode->i_mode == (S_IFDIR|S_IRUGO|S_IXUGO)) ||
		    task_dumpable(task)) {
			cred = __task_cred(task);
			stat->uid = cred->euid;
			stat->gid = cred->egid;
		}
	}
	rcu_read_unlock();
	return 0;
}

/* dentry stuff */

/*
 *	Exceptional case: normally we are not allowed to unhash a busy
 * directory. In this case, however, we can do it - no aliasing problems
 * due to the way we treat inodes.
 *
 * Rewrite the inode's ownerships here because the owning task may have
 * performed a setuid(), etc.
 *
 * Before the /proc/pid/status file was created the only way to read
 * the effective uid of a /process was to stat /proc/pid.  Reading
 * /proc/pid/status is slow enough that procps and other packages
 * kept stating /proc/pid.  To keep the rules in /proc simple I have
 * made this apply to all per process world readable and executable
 * directories.
 */
int pid_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct inode *inode;
	struct task_struct *task;
	const struct cred *cred;

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	inode = dentry->d_inode;
	task = get_proc_task(inode);

	if (task) {
		if ((inode->i_mode == (S_IFDIR|S_IRUGO|S_IXUGO)) ||
		    task_dumpable(task)) {
			rcu_read_lock();
			cred = __task_cred(task);
			inode->i_uid = cred->euid;
			inode->i_gid = cred->egid;
			rcu_read_unlock();
		} else {
			inode->i_uid = GLOBAL_ROOT_UID;
			inode->i_gid = GLOBAL_ROOT_GID;
		}
		inode->i_mode &= ~(S_ISUID | S_ISGID);
		security_task_to_inode(task, inode);
		put_task_struct(task);
		return 1;
	}
	d_drop(dentry);
	return 0;
}

static inline bool proc_inode_is_dead(struct inode *inode)
{
	return !proc_pid(inode)->tasks[PIDTYPE_PID].first;
}

int pid_delete_dentry(const struct dentry *dentry)
{
	/* Is the task we represent dead?
	 * If so, then don't put the dentry on the lru list,
	 * kill it immediately.
	 */
	return proc_inode_is_dead(dentry->d_inode);
}

const struct dentry_operations pid_dentry_operations =
{
	.d_revalidate	= pid_revalidate,
	.d_delete	= pid_delete_dentry,
};

/* Lookups */

/*
 * Fill a directory entry.
 *
 * If possible create the dcache entry and derive our inode number and
 * file type from dcache entry.
 *
 * Since all of the proc inode numbers are dynamically generated, the inode
 * numbers do not exist until the inode is cache.  This means creating the
 * the dcache entry in readdir is necessary to keep the inode numbers
 * reported by readdir in sync with the inode numbers reported
 * by stat.
 */
bool proc_fill_cache(struct file *file, struct dir_context *ctx,
	const char *name, int len,
	instantiate_t instantiate, struct task_struct *task, const void *ptr)
{
	struct dentry *child, *dir = file->f_path.dentry;
	struct qstr qname = QSTR_INIT(name, len);
	struct inode *inode;
	unsigned type;
	ino_t ino;

	child = d_hash_and_lookup(dir, &qname);
	if (!child) {
		child = d_alloc(dir, &qname);
		if (!child)
			goto end_instantiate;
		if (instantiate(dir->d_inode, child, task, ptr) < 0) {
			dput(child);
			goto end_instantiate;
		}
	}
	inode = child->d_inode;
	ino = inode->i_ino;
	type = inode->i_mode >> 12;
	dput(child);
	return dir_emit(ctx, name, len, ino, type);

end_instantiate:
	return dir_emit(ctx, name, len, 1, DT_UNKNOWN);
}

#ifdef CONFIG_CHECKPOINT_RESTORE

/*
 * dname_to_vma_addr - maps a dentry name into two unsigned longs
 * which represent vma start and end addresses.
 */
static int dname_to_vma_addr(struct dentry *dentry,
			     unsigned long *start, unsigned long *end)
{
	if (sscanf(dentry->d_name.name, "%lx-%lx", start, end) != 2)
		return -EINVAL;

	return 0;
}

static int map_files_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	unsigned long vm_start, vm_end;
	bool exact_vma_exists = false;
	struct mm_struct *mm = NULL;
	struct task_struct *task;
	const struct cred *cred;
	struct inode *inode;
	int status = 0;

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	if (!capable(CAP_SYS_ADMIN)) {
		status = -EPERM;
		goto out_notask;
	}

	inode = dentry->d_inode;
	task = get_proc_task(inode);
	if (!task)
		goto out_notask;

	mm = mm_access(task, PTRACE_MODE_READ);
	if (IS_ERR_OR_NULL(mm))
		goto out;

	if (!dname_to_vma_addr(dentry, &vm_start, &vm_end)) {
		down_read(&mm->mmap_sem);
		exact_vma_exists = !!find_exact_vma(mm, vm_start, vm_end);
		up_read(&mm->mmap_sem);
	}

	mmput(mm);

	if (exact_vma_exists) {
		if (task_dumpable(task)) {
			rcu_read_lock();
			cred = __task_cred(task);
			inode->i_uid = cred->euid;
			inode->i_gid = cred->egid;
			rcu_read_unlock();
		} else {
			inode->i_uid = GLOBAL_ROOT_UID;
			inode->i_gid = GLOBAL_ROOT_GID;
		}
		security_task_to_inode(task, inode);
		status = 1;
	}

out:
	put_task_struct(task);

out_notask:
	if (status <= 0)
		d_drop(dentry);

	return status;
}

static const struct dentry_operations tid_map_files_dentry_operations = {
	.d_revalidate	= map_files_d_revalidate,
	.d_delete	= pid_delete_dentry,
};

static int proc_map_files_get_link(struct dentry *dentry, struct path *path)
{
	unsigned long vm_start, vm_end;
	struct vm_area_struct *vma;
	struct task_struct *task;
	struct mm_struct *mm;
	int rc;

	rc = -ENOENT;
	task = get_proc_task(dentry->d_inode);
	if (!task)
		goto out;

	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm)
		goto out;

	rc = dname_to_vma_addr(dentry, &vm_start, &vm_end);
	if (rc)
		goto out_mmput;

	rc = -ENOENT;
	down_read(&mm->mmap_sem);
	vma = find_exact_vma(mm, vm_start, vm_end);
	if (vma && vma->vm_file) {
		*path = vma->vm_file->f_path;
		path_get(path);
		rc = 0;
	}
	up_read(&mm->mmap_sem);

out_mmput:
	mmput(mm);
out:
	return rc;
}

struct map_files_info {
	fmode_t		mode;
	unsigned long	len;
	unsigned char	name[4*sizeof(long)+2]; /* max: %lx-%lx\0 */
};

static int
proc_map_files_instantiate(struct inode *dir, struct dentry *dentry,
			   struct task_struct *task, const void *ptr)
{
	fmode_t mode = (fmode_t)(unsigned long)ptr;
	struct proc_inode *ei;
	struct inode *inode;

	inode = proc_pid_make_inode(dir->i_sb, task);
	if (!inode)
		return -ENOENT;

	ei = PROC_I(inode);
	ei->op.proc_get_link = proc_map_files_get_link;

	inode->i_op = &proc_pid_link_inode_operations;
	inode->i_size = 64;
	inode->i_mode = S_IFLNK;

	if (mode & FMODE_READ)
		inode->i_mode |= S_IRUSR;
	if (mode & FMODE_WRITE)
		inode->i_mode |= S_IWUSR;

	d_set_d_op(dentry, &tid_map_files_dentry_operations);
	d_add(dentry, inode);

	return 0;
}

static struct dentry *proc_map_files_lookup(struct inode *dir,
		struct dentry *dentry, unsigned int flags)
{
	unsigned long vm_start, vm_end;
	struct vm_area_struct *vma;
	struct task_struct *task;
	int result;
	struct mm_struct *mm;

	result = -EPERM;
	if (!capable(CAP_SYS_ADMIN))
		goto out;

	result = -ENOENT;
	task = get_proc_task(dir);
	if (!task)
		goto out;

	result = -EACCES;
	if (!ptrace_may_access(task, PTRACE_MODE_READ))
		goto out_put_task;

	result = -ENOENT;
	if (dname_to_vma_addr(dentry, &vm_start, &vm_end))
		goto out_put_task;

	mm = get_task_mm(task);
	if (!mm)
		goto out_put_task;

	down_read(&mm->mmap_sem);
	vma = find_exact_vma(mm, vm_start, vm_end);
	if (!vma)
		goto out_no_vma;

	if (vma->vm_file)
		result = proc_map_files_instantiate(dir, dentry, task,
				(void *)(unsigned long)vma->vm_file->f_mode);

out_no_vma:
	up_read(&mm->mmap_sem);
	mmput(mm);
out_put_task:
	put_task_struct(task);
out:
	return ERR_PTR(result);
}

static const struct inode_operations proc_map_files_inode_operations = {
	.lookup		= proc_map_files_lookup,
	.permission	= proc_fd_permission,
	.setattr	= proc_setattr,
};

static int
proc_map_files_readdir(struct file *file, struct dir_context *ctx)
{
	struct vm_area_struct *vma;
	struct task_struct *task;
	struct mm_struct *mm;
	unsigned long nr_files, pos, i;
	struct flex_array *fa = NULL;
	struct map_files_info info;
	struct map_files_info *p;
	int ret;

	ret = -EPERM;
	if (!capable(CAP_SYS_ADMIN))
		goto out;

	ret = -ENOENT;
	task = get_proc_task(file_inode(file));
	if (!task)
		goto out;

	ret = -EACCES;
	if (!ptrace_may_access(task, PTRACE_MODE_READ))
		goto out_put_task;

	ret = 0;
	if (!dir_emit_dots(file, ctx))
		goto out_put_task;

	mm = get_task_mm(task);
	if (!mm)
		goto out_put_task;
	down_read(&mm->mmap_sem);

	nr_files = 0;

	/*
	 * We need two passes here:
	 *
	 *  1) Collect vmas of mapped files with mmap_sem taken
	 *  2) Release mmap_sem and instantiate entries
	 *
	 * otherwise we get lockdep complained, since filldir()
	 * routine might require mmap_sem taken in might_fault().
	 */

	for (vma = mm->mmap, pos = 2; vma; vma = vma->vm_next) {
		if (vma->vm_file && ++pos > ctx->pos)
			nr_files++;
	}

	if (nr_files) {
		fa = flex_array_alloc(sizeof(info), nr_files,
					GFP_KERNEL);
		if (!fa || flex_array_prealloc(fa, 0, nr_files,
						GFP_KERNEL)) {
			ret = -ENOMEM;
			if (fa)
				flex_array_free(fa);
			up_read(&mm->mmap_sem);
			mmput(mm);
			goto out_put_task;
		}
		for (i = 0, vma = mm->mmap, pos = 2; vma;
				vma = vma->vm_next) {
			if (!vma->vm_file)
				continue;
			if (++pos <= ctx->pos)
				continue;

			info.mode = vma->vm_file->f_mode;
			info.len = snprintf(info.name,
					sizeof(info.name), "%lx-%lx",
					vma->vm_start, vma->vm_end);
			if (flex_array_put(fa, i++, &info, GFP_KERNEL))
				BUG();
		}
	}
	up_read(&mm->mmap_sem);

	for (i = 0; i < nr_files; i++) {
		p = flex_array_get(fa, i);
		if (!proc_fill_cache(file, ctx,
				      p->name, p->len,
				      proc_map_files_instantiate,
				      task,
				      (void *)(unsigned long)p->mode))
			break;
		ctx->pos++;
	}
	if (fa)
		flex_array_free(fa);
	mmput(mm);

out_put_task:
	put_task_struct(task);
out:
	return ret;
}

static const struct file_operations proc_map_files_operations = {
	.read		= generic_read_dir,
	.iterate	= proc_map_files_readdir,
	.llseek		= default_llseek,
};

struct timers_private {
	struct pid *pid;
	struct task_struct *task;
	struct sighand_struct *sighand;
	struct pid_namespace *ns;
	unsigned long flags;
};

static void *timers_start(struct seq_file *m, loff_t *pos)
{
	struct timers_private *tp = m->private;

	tp->task = get_pid_task(tp->pid, PIDTYPE_PID);
	if (!tp->task)
		return ERR_PTR(-ESRCH);

	tp->sighand = lock_task_sighand(tp->task, &tp->flags);
	if (!tp->sighand)
		return ERR_PTR(-ESRCH);

	return seq_list_start(&tp->task->signal->posix_timers, *pos);
}

static void *timers_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct timers_private *tp = m->private;
	return seq_list_next(v, &tp->task->signal->posix_timers, pos);
}

static void timers_stop(struct seq_file *m, void *v)
{
	struct timers_private *tp = m->private;

	if (tp->sighand) {
		unlock_task_sighand(tp->task, &tp->flags);
		tp->sighand = NULL;
	}

	if (tp->task) {
		put_task_struct(tp->task);
		tp->task = NULL;
	}
}

static int show_timer(struct seq_file *m, void *v)
{
	struct k_itimer *timer;
	struct timers_private *tp = m->private;
	int notify;
	static const char * const nstr[] = {
		[SIGEV_SIGNAL] = "signal",
		[SIGEV_NONE] = "none",
		[SIGEV_THREAD] = "thread",
	};

	timer = list_entry((struct list_head *)v, struct k_itimer, list);
	notify = timer->it_sigev_notify;

	seq_printf(m, "ID: %d\n", timer->it_id);
	seq_printf(m, "signal: %d/%p\n", timer->sigq->info.si_signo,
			timer->sigq->info.si_value.sival_ptr);
	seq_printf(m, "notify: %s/%s.%d\n",
		nstr[notify & ~SIGEV_THREAD_ID],
		(notify & SIGEV_THREAD_ID) ? "tid" : "pid",
		pid_nr_ns(timer->it_pid, tp->ns));
	seq_printf(m, "ClockID: %d\n", timer->it_clock);

	return 0;
}

static const struct seq_operations proc_timers_seq_ops = {
	.start	= timers_start,
	.next	= timers_next,
	.stop	= timers_stop,
	.show	= show_timer,
};

static int proc_timers_open(struct inode *inode, struct file *file)
{
	struct timers_private *tp;

	tp = __seq_open_private(file, &proc_timers_seq_ops,
			sizeof(struct timers_private));
	if (!tp)
		return -ENOMEM;

	tp->pid = proc_pid(inode);
	tp->ns = inode->i_sb->s_fs_info;
	return 0;
}

static const struct file_operations proc_timers_operations = {
	.open		= proc_timers_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release_private,
};
#endif /* CONFIG_CHECKPOINT_RESTORE */

static int proc_pident_instantiate(struct inode *dir,
	struct dentry *dentry, struct task_struct *task, const void *ptr)
{
	const struct pid_entry *p = ptr;
	struct inode *inode;
	struct proc_inode *ei;

	inode = proc_pid_make_inode(dir->i_sb, task);
	if (!inode)
		goto out;

	ei = PROC_I(inode);
	inode->i_mode = p->mode;
	if (S_ISDIR(inode->i_mode))
		set_nlink(inode, 2);	/* Use getattr to fix if necessary */
	if (p->iop)
		inode->i_op = p->iop;
	if (p->fop)
		inode->i_fop = p->fop;
	ei->op = p->op;
	d_set_d_op(dentry, &pid_dentry_operations);
	d_add(dentry, inode);
	/* Close the race of the process dying before we return the dentry */
	if (pid_revalidate(dentry, 0))
		return 0;
out:
	return -ENOENT;
}

static struct dentry *proc_pident_lookup(struct inode *dir,
					 struct dentry *dentry,
					 const struct pid_entry *ents,
					 unsigned int nents)
{
	int error;
	struct task_struct *task = get_proc_task(dir);
	const struct pid_entry *p, *last;

	error = -ENOENT;

	if (!task)
		goto out_no_task;

	/*
	 * Yes, it does not scale. And it should not. Don't add
	 * new entries into /proc/<tgid>/ without very good reasons.
	 */
	last = &ents[nents - 1];
	for (p = ents; p <= last; p++) {
		if (p->len != dentry->d_name.len)
			continue;
		if (!memcmp(dentry->d_name.name, p->name, p->len))
			break;
	}
	if (p > last)
		goto out;

	error = proc_pident_instantiate(dir, dentry, task, p);
out:
	put_task_struct(task);
out_no_task:
	return ERR_PTR(error);
}

static int proc_pident_readdir(struct file *file, struct dir_context *ctx,
		const struct pid_entry *ents, unsigned int nents)
{
	struct task_struct *task = get_proc_task(file_inode(file));
	const struct pid_entry *p;

	if (!task)
		return -ENOENT;

	if (!dir_emit_dots(file, ctx))
		goto out;

	if (ctx->pos >= nents + 2)
		goto out;

	for (p = ents + (ctx->pos - 2); p <= ents + nents - 1; p++) {
		if (!proc_fill_cache(file, ctx, p->name, p->len,
				proc_pident_instantiate, task, p))
			break;
		ctx->pos++;
	}
out:
	put_task_struct(task);
	return 0;
}

#ifdef CONFIG_SECURITY
static ssize_t proc_pid_attr_read(struct file * file, char __user * buf,
				  size_t count, loff_t *ppos)
{
	struct inode * inode = file_inode(file);
	char *p = NULL;
	ssize_t length;
	struct task_struct *task = get_proc_task(inode);

	if (!task)
		return -ESRCH;

	length = security_getprocattr(task,
				      (char*)file->f_path.dentry->d_name.name,
				      &p);
	put_task_struct(task);
	if (length > 0)
		length = simple_read_from_buffer(buf, count, ppos, p, length);
	kfree(p);
	return length;
}

static ssize_t proc_pid_attr_write(struct file * file, const char __user * buf,
				   size_t count, loff_t *ppos)
{
	struct inode * inode = file_inode(file);
	char *page;
	ssize_t length;
	struct task_struct *task = get_proc_task(inode);

	length = -ESRCH;
	if (!task)
		goto out_no_task;
	if (count > PAGE_SIZE)
		count = PAGE_SIZE;

	/* No partial writes. */
	length = -EINVAL;
	if (*ppos != 0)
		goto out;

	length = -ENOMEM;
	page = (char*)__get_free_page(GFP_TEMPORARY);
	if (!page)
		goto out;

	length = -EFAULT;
	if (copy_from_user(page, buf, count))
		goto out_free;

	/* Guard against adverse ptrace interaction */
	length = mutex_lock_interruptible(&task->signal->cred_guard_mutex);
	if (length < 0)
		goto out_free;

	length = security_setprocattr(task,
				      (char*)file->f_path.dentry->d_name.name,
				      (void*)page, count);
	mutex_unlock(&task->signal->cred_guard_mutex);
out_free:
	free_page((unsigned long) page);
out:
	put_task_struct(task);
out_no_task:
	return length;
}

static const struct file_operations proc_pid_attr_operations = {
	.read		= proc_pid_attr_read,
	.write		= proc_pid_attr_write,
	.llseek		= generic_file_llseek,
};

static const struct pid_entry attr_dir_stuff[] = {
	REG("current",    S_IRUGO|S_IWUGO, proc_pid_attr_operations),
	REG("prev",       S_IRUGO,	   proc_pid_attr_operations),
	REG("exec",       S_IRUGO|S_IWUGO, proc_pid_attr_operations),
	REG("fscreate",   S_IRUGO|S_IWUGO, proc_pid_attr_operations),
	REG("keycreate",  S_IRUGO|S_IWUGO, proc_pid_attr_operations),
	REG("sockcreate", S_IRUGO|S_IWUGO, proc_pid_attr_operations),
};

static int proc_attr_dir_readdir(struct file *file, struct dir_context *ctx)
{
	return proc_pident_readdir(file, ctx,
				   attr_dir_stuff, ARRAY_SIZE(attr_dir_stuff));
}

static const struct file_operations proc_attr_dir_operations = {
	.read		= generic_read_dir,
	.iterate	= proc_attr_dir_readdir,
	.llseek		= default_llseek,
};

static struct dentry *proc_attr_dir_lookup(struct inode *dir,
				struct dentry *dentry, unsigned int flags)
{
	return proc_pident_lookup(dir, dentry,
				  attr_dir_stuff, ARRAY_SIZE(attr_dir_stuff));
}

static const struct inode_operations proc_attr_dir_inode_operations = {
	.lookup		= proc_attr_dir_lookup,
	.getattr	= pid_getattr,
	.setattr	= proc_setattr,
};

#endif

#ifdef CONFIG_ELF_CORE
static ssize_t proc_coredump_filter_read(struct file *file, char __user *buf,
					 size_t count, loff_t *ppos)
{
	struct task_struct *task = get_proc_task(file_inode(file));
	struct mm_struct *mm;
	char buffer[PROC_NUMBUF];
	size_t len;
	int ret;

	if (!task)
		return -ESRCH;

	ret = 0;
	mm = get_task_mm(task);
	if (mm) {
		len = snprintf(buffer, sizeof(buffer), "%08lx\n",
			       ((mm->flags & MMF_DUMP_FILTER_MASK) >>
				MMF_DUMP_FILTER_SHIFT));
		mmput(mm);
		ret = simple_read_from_buffer(buf, count, ppos, buffer, len);
	}

	put_task_struct(task);

	return ret;
}

static ssize_t proc_coredump_filter_write(struct file *file,
					  const char __user *buf,
					  size_t count,
					  loff_t *ppos)
{
	struct task_struct *task;
	struct mm_struct *mm;
	char buffer[PROC_NUMBUF], *end;
	unsigned int val;
	int ret;
	int i;
	unsigned long mask;

	ret = -EFAULT;
	memset(buffer, 0, sizeof(buffer));
	if (count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;
	if (copy_from_user(buffer, buf, count))
		goto out_no_task;

	ret = -EINVAL;
	val = (unsigned int)simple_strtoul(buffer, &end, 0);
	if (*end == '\n')
		end++;
	if (end - buffer == 0)
		goto out_no_task;

	ret = -ESRCH;
	task = get_proc_task(file_inode(file));
	if (!task)
		goto out_no_task;

	ret = end - buffer;
	mm = get_task_mm(task);
	if (!mm)
		goto out_no_mm;

	for (i = 0, mask = 1; i < MMF_DUMP_FILTER_BITS; i++, mask <<= 1) {
		if (val & mask)
			set_bit(i + MMF_DUMP_FILTER_SHIFT, &mm->flags);
		else
			clear_bit(i + MMF_DUMP_FILTER_SHIFT, &mm->flags);
	}

	mmput(mm);
 out_no_mm:
	put_task_struct(task);
 out_no_task:
	return ret;
}

static const struct file_operations proc_coredump_filter_operations = {
	.read		= proc_coredump_filter_read,
	.write		= proc_coredump_filter_write,
	.llseek		= generic_file_llseek,
};
#endif

#ifdef CONFIG_TASK_IO_ACCOUNTING
static int do_io_accounting(struct task_struct *task, struct seq_file *m, int whole)
{
	struct task_io_accounting acct = task->ioac;
	unsigned long flags;
	int result;

	result = mutex_lock_killable(&task->signal->cred_guard_mutex);
	if (result)
		return result;

	if (!ptrace_may_access(task, PTRACE_MODE_READ)) {
		result = -EACCES;
		goto out_unlock;
	}

	if (whole && lock_task_sighand(task, &flags)) {
		struct task_struct *t = task;

		task_io_accounting_add(&acct, &task->signal->ioac);
		while_each_thread(task, t)
			task_io_accounting_add(&acct, &t->ioac);

		unlock_task_sighand(task, &flags);
	}
	result = seq_printf(m,
			"rchar: %llu\n"
			"wchar: %llu\n"
			"syscr: %llu\n"
			"syscw: %llu\n"
			"read_bytes: %llu\n"
			"write_bytes: %llu\n"
			"cancelled_write_bytes: %llu\n",
			(unsigned long long)acct.rchar,
			(unsigned long long)acct.wchar,
			(unsigned long long)acct.syscr,
			(unsigned long long)acct.syscw,
			(unsigned long long)acct.read_bytes,
			(unsigned long long)acct.write_bytes,
			(unsigned long long)acct.cancelled_write_bytes);
out_unlock:
	mutex_unlock(&task->signal->cred_guard_mutex);
	return result;
}

static int proc_tid_io_accounting(struct seq_file *m, struct pid_namespace *ns,
				  struct pid *pid, struct task_struct *task)
{
	return do_io_accounting(task, m, 0);
}

static int proc_tgid_io_accounting(struct seq_file *m, struct pid_namespace *ns,
				   struct pid *pid, struct task_struct *task)
{
	return do_io_accounting(task, m, 1);
}
#endif /* CONFIG_TASK_IO_ACCOUNTING */

#ifdef CONFIG_USER_NS
static int proc_id_map_open(struct inode *inode, struct file *file,
	const struct seq_operations *seq_ops)
{
	struct user_namespace *ns = NULL;
	struct task_struct *task;
	struct seq_file *seq;
	int ret = -EINVAL;

	task = get_proc_task(inode);
	if (task) {
		rcu_read_lock();
		ns = get_user_ns(task_cred_xxx(task, user_ns));
		rcu_read_unlock();
		put_task_struct(task);
	}
	if (!ns)
		goto err;

	ret = seq_open(file, seq_ops);
	if (ret)
		goto err_put_ns;

	seq = file->private_data;
	seq->private = ns;

	return 0;
err_put_ns:
	put_user_ns(ns);
err:
	return ret;
}

static int proc_id_map_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;
	struct user_namespace *ns = seq->private;
	put_user_ns(ns);
	return seq_release(inode, file);
}

static int proc_uid_map_open(struct inode *inode, struct file *file)
{
	return proc_id_map_open(inode, file, &proc_uid_seq_operations);
}

static int proc_gid_map_open(struct inode *inode, struct file *file)
{
	return proc_id_map_open(inode, file, &proc_gid_seq_operations);
}

static int proc_projid_map_open(struct inode *inode, struct file *file)
{
	return proc_id_map_open(inode, file, &proc_projid_seq_operations);
}

static const struct file_operations proc_uid_map_operations = {
	.open		= proc_uid_map_open,
	.write		= proc_uid_map_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= proc_id_map_release,
};

static const struct file_operations proc_gid_map_operations = {
	.open		= proc_gid_map_open,
	.write		= proc_gid_map_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= proc_id_map_release,
};

static const struct file_operations proc_projid_map_operations = {
	.open		= proc_projid_map_open,
	.write		= proc_projid_map_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= proc_id_map_release,
};
#endif /* CONFIG_USER_NS */

static int proc_pid_personality(struct seq_file *m, struct pid_namespace *ns,
				struct pid *pid, struct task_struct *task)
{
	int err = lock_trace(task);
	if (!err) {
		seq_printf(m, "%08x\n", task->personality);
		unlock_trace(task);
	}
	return err;
}

/*
 * Thread groups
 */
static const struct file_operations proc_task_operations;
static const struct inode_operations proc_task_inode_operations;

static const struct pid_entry tgid_base_stuff[] = {
	DIR("task",       S_IRUGO|S_IXUGO, proc_task_inode_operations, proc_task_operations),
	DIR("fd",         S_IRUSR|S_IXUSR, proc_fd_inode_operations, proc_fd_operations),
#ifdef CONFIG_CHECKPOINT_RESTORE
	DIR("map_files",  S_IRUSR|S_IXUSR, proc_map_files_inode_operations, proc_map_files_operations),
#endif
	DIR("fdinfo",     S_IRUSR|S_IXUSR, proc_fdinfo_inode_operations, proc_fdinfo_operations),
	DIR("ns",	  S_IRUSR|S_IXUGO, proc_ns_dir_inode_operations, proc_ns_dir_operations),
#ifdef CONFIG_NET
	DIR("net",        S_IRUGO|S_IXUGO, proc_net_inode_operations, proc_net_operations),
#endif
	REG("environ",    S_IRUSR, proc_environ_operations),
	ONE("auxv",       S_IRUSR, proc_pid_auxv),
	ONE("status",     S_IRUGO, proc_pid_status),
	ONE("personality", S_IRUSR, proc_pid_personality),
	ONE("limits",	  S_IRUGO, proc_pid_limits),
#ifdef CONFIG_SCHED_DEBUG
	REG("sched",      S_IRUGO|S_IWUSR, proc_pid_sched_operations),
#endif
#ifdef CONFIG_SCHED_AUTOGROUP
	REG("autogroup",  S_IRUGO|S_IWUSR, proc_pid_sched_autogroup_operations),
#endif
	REG("comm",      S_IRUGO|S_IWUSR, proc_pid_set_comm_operations),
#ifdef CONFIG_HAVE_ARCH_TRACEHOOK
	ONE("syscall",    S_IRUSR, proc_pid_syscall),
#endif
	ONE("cmdline",    S_IRUGO, proc_pid_cmdline),
	ONE("stat",       S_IRUGO, proc_tgid_stat),
	ONE("statm",      S_IRUGO, proc_pid_statm),
	REG("maps",       S_IRUGO, proc_pid_maps_operations),
#ifdef CONFIG_NUMA
	REG("numa_maps",  S_IRUGO, proc_pid_numa_maps_operations),
#endif
	REG("mem",        S_IRUSR|S_IWUSR, proc_mem_operations),
	LNK("cwd",        proc_cwd_link),
	LNK("root",       proc_root_link),
	LNK("exe",        proc_exe_link),
	REG("mounts",     S_IRUGO, proc_mounts_operations),
	REG("mountinfo",  S_IRUGO, proc_mountinfo_operations),
	REG("mountstats", S_IRUSR, proc_mountstats_operations),
#ifdef CONFIG_PROC_PAGE_MONITOR
	REG("clear_refs", S_IWUSR, proc_clear_refs_operations),
	REG("smaps",      S_IRUGO, proc_pid_smaps_operations),
	REG("pagemap",    S_IRUSR, proc_pagemap_operations),
#endif
#ifdef CONFIG_SECURITY
	DIR("attr",       S_IRUGO|S_IXUGO, proc_attr_dir_inode_operations, proc_attr_dir_operations),
#endif
#ifdef CONFIG_KALLSYMS
	ONE("wchan",      S_IRUGO, proc_pid_wchan),
#endif
#ifdef CONFIG_STACKTRACE
	ONE("stack",      S_IRUSR, proc_pid_stack),
#endif
#ifdef CONFIG_SCHEDSTATS
	ONE("schedstat",  S_IRUGO, proc_pid_schedstat),
#endif
#ifdef CONFIG_LATENCYTOP
	REG("latency",  S_IRUGO, proc_lstats_operations),
#endif
#ifdef CONFIG_PROC_PID_CPUSET
	REG("cpuset",     S_IRUGO, proc_cpuset_operations),
#endif
#ifdef CONFIG_CGROUPS
	REG("cgroup",  S_IRUGO, proc_cgroup_operations),
#endif
	ONE("oom_score",  S_IRUGO, proc_oom_score),
	REG("oom_adj",    S_IRUGO|S_IWUSR, proc_oom_adj_operations),
	REG("oom_score_adj", S_IRUGO|S_IWUSR, proc_oom_score_adj_operations),
#ifdef CONFIG_AUDITSYSCALL
	REG("loginuid",   S_IWUSR|S_IRUGO, proc_loginuid_operations),
	REG("sessionid",  S_IRUGO, proc_sessionid_operations),
#endif
#ifdef CONFIG_FAULT_INJECTION
	REG("make-it-fail", S_IRUGO|S_IWUSR, proc_fault_inject_operations),
#endif
#ifdef CONFIG_ELF_CORE
	REG("coredump_filter", S_IRUGO|S_IWUSR, proc_coredump_filter_operations),
#endif
#ifdef CONFIG_TASK_IO_ACCOUNTING
	ONE("io",	S_IRUSR, proc_tgid_io_accounting),
#endif
#ifdef CONFIG_HARDWALL
	ONE("hardwall",   S_IRUGO, proc_pid_hardwall),
#endif
#ifdef CONFIG_USER_NS
	REG("uid_map",    S_IRUGO|S_IWUSR, proc_uid_map_operations),
	REG("gid_map",    S_IRUGO|S_IWUSR, proc_gid_map_operations),
	REG("projid_map", S_IRUGO|S_IWUSR, proc_projid_map_operations),
#endif
#ifdef CONFIG_CHECKPOINT_RESTORE
	REG("timers",	  S_IRUGO, proc_timers_operations),
#endif
};

static int proc_tgid_base_readdir(struct file *file, struct dir_context *ctx)
{
	return proc_pident_readdir(file, ctx,
				   tgid_base_stuff, ARRAY_SIZE(tgid_base_stuff));
}

static const struct file_operations proc_tgid_base_operations = {
	.read		= generic_read_dir,
	.iterate	= proc_tgid_base_readdir,
	.llseek		= default_llseek,
};

static struct dentry *proc_tgid_base_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	return proc_pident_lookup(dir, dentry,
				  tgid_base_stuff, ARRAY_SIZE(tgid_base_stuff));
}

static const struct inode_operations proc_tgid_base_inode_operations = {
	.lookup		= proc_tgid_base_lookup,
	.getattr	= pid_getattr,
	.setattr	= proc_setattr,
	.permission	= proc_pid_permission,
};

static void proc_flush_task_mnt(struct vfsmount *mnt, pid_t pid, pid_t tgid)
{
	struct dentry *dentry, *leader, *dir;
	char buf[PROC_NUMBUF];
	struct qstr name;

	name.name = buf;
	name.len = snprintf(buf, sizeof(buf), "%d", pid);
	/* no ->d_hash() rejects on procfs */
	dentry = d_hash_and_lookup(mnt->mnt_root, &name);
	if (dentry) {
		shrink_dcache_parent(dentry);
		d_drop(dentry);
		dput(dentry);
	}

	name.name = buf;
	name.len = snprintf(buf, sizeof(buf), "%d", tgid);
	leader = d_hash_and_lookup(mnt->mnt_root, &name);
	if (!leader)
		goto out;

	name.name = "task";
	name.len = strlen(name.name);
	dir = d_hash_and_lookup(leader, &name);
	if (!dir)
		goto out_put_leader;

	name.name = buf;
	name.len = snprintf(buf, sizeof(buf), "%d", pid);
	dentry = d_hash_and_lookup(dir, &name);
	if (dentry) {
		shrink_dcache_parent(dentry);
		d_drop(dentry);
		dput(dentry);
	}

	dput(dir);
out_put_leader:
	dput(leader);
out:
	return;
}

/**
 * proc_flush_task -  Remove dcache entries for @task from the /proc dcache.
 * @task: task that should be flushed.
 *
 * When flushing dentries from proc, one needs to flush them from global
 * proc (proc_mnt) and from all the namespaces' procs this task was seen
 * in. This call is supposed to do all of this job.
 *
 * Looks in the dcache for
 * /proc/@pid
 * /proc/@tgid/task/@pid
 * if either directory is present flushes it and all of it'ts children
 * from the dcache.
 *
 * It is safe and reasonable to cache /proc entries for a task until
 * that task exits.  After that they just clog up the dcache with
 * useless entries, possibly causing useful dcache entries to be
 * flushed instead.  This routine is proved to flush those useless
 * dcache entries at process exit time.
 *
 * NOTE: This routine is just an optimization so it does not guarantee
 *       that no dcache entries will exist at process exit time it
 *       just makes it very unlikely that any will persist.
 */

void proc_flush_task(struct task_struct *task)
{
	int i;
	struct pid *pid, *tgid;
	struct upid *upid;

	pid = task_pid(task);
	tgid = task_tgid(task);

	for (i = 0; i <= pid->level; i++) {
		upid = &pid->numbers[i];
		proc_flush_task_mnt(upid->ns->proc_mnt, upid->nr,
					tgid->numbers[i].nr);
	}
}

static int proc_pid_instantiate(struct inode *dir,
				   struct dentry * dentry,
				   struct task_struct *task, const void *ptr)
{
	struct inode *inode;

	inode = proc_pid_make_inode(dir->i_sb, task);
	if (!inode)
		goto out;

	inode->i_mode = S_IFDIR|S_IRUGO|S_IXUGO;
	inode->i_op = &proc_tgid_base_inode_operations;
	inode->i_fop = &proc_tgid_base_operations;
	inode->i_flags|=S_IMMUTABLE;

	set_nlink(inode, 2 + pid_entry_count_dirs(tgid_base_stuff,
						  ARRAY_SIZE(tgid_base_stuff)));

	d_set_d_op(dentry, &pid_dentry_operations);

	d_add(dentry, inode);
	/* Close the race of the process dying before we return the dentry */
	if (pid_revalidate(dentry, 0))
		return 0;
out:
	return -ENOENT;
}

struct dentry *proc_pid_lookup(struct inode *dir, struct dentry * dentry, unsigned int flags)
{
	int result = -ENOENT;
	struct task_struct *task;
	unsigned tgid;
	struct pid_namespace *ns;

	tgid = name_to_int(&dentry->d_name);
	if (tgid == ~0U)
		goto out;

	ns = dentry->d_sb->s_fs_info;
	rcu_read_lock();
	task = find_task_by_pid_ns(tgid, ns);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();
	if (!task)
		goto out;

	result = proc_pid_instantiate(dir, dentry, task, NULL);
	put_task_struct(task);
out:
	return ERR_PTR(result);
}

/*
 * Find the first task with tgid >= tgid
 *
 */
struct tgid_iter {
	unsigned int tgid;
	struct task_struct *task;
};
static struct tgid_iter next_tgid(struct pid_namespace *ns, struct tgid_iter iter)
{
	struct pid *pid;

	if (iter.task)
		put_task_struct(iter.task);
	rcu_read_lock();
retry:
	iter.task = NULL;
	pid = find_ge_pid(iter.tgid, ns);
	if (pid) {
		iter.tgid = pid_nr_ns(pid, ns);
		iter.task = pid_task(pid, PIDTYPE_PID);
		/* What we to know is if the pid we have find is the
		 * pid of a thread_group_leader.  Testing for task
		 * being a thread_group_leader is the obvious thing
		 * todo but there is a window when it fails, due to
		 * the pid transfer logic in de_thread.
		 *
		 * So we perform the straight forward test of seeing
		 * if the pid we have found is the pid of a thread
		 * group leader, and don't worry if the task we have
		 * found doesn't happen to be a thread group leader.
		 * As we don't care in the case of readdir.
		 */
		if (!iter.task || !has_group_leader_pid(iter.task)) {
			iter.tgid += 1;
			goto retry;
		}
		get_task_struct(iter.task);
	}
	rcu_read_unlock();
	return iter;
}

#define TGID_OFFSET (FIRST_PROCESS_ENTRY + 2)

/* for the /proc/ directory itself, after non-process stuff has been done */
int proc_pid_readdir(struct file *file, struct dir_context *ctx)
{
	struct tgid_iter iter;
	struct pid_namespace *ns = file->f_dentry->d_sb->s_fs_info;
	loff_t pos = ctx->pos;

	if (pos >= PID_MAX_LIMIT + TGID_OFFSET)
		return 0;

	if (pos == TGID_OFFSET - 2) {
		struct inode *inode = ns->proc_self->d_inode;
		if (!dir_emit(ctx, "self", 4, inode->i_ino, DT_LNK))
			return 0;
		ctx->pos = pos = pos + 1;
	}
	if (pos == TGID_OFFSET - 1) {
		struct inode *inode = ns->proc_thread_self->d_inode;
		if (!dir_emit(ctx, "thread-self", 11, inode->i_ino, DT_LNK))
			return 0;
		ctx->pos = pos = pos + 1;
	}
	iter.tgid = pos - TGID_OFFSET;
	iter.task = NULL;
	for (iter = next_tgid(ns, iter);
	     iter.task;
	     iter.tgid += 1, iter = next_tgid(ns, iter)) {
		char name[PROC_NUMBUF];
		int len;
		if (!has_pid_permissions(ns, iter.task, 2))
			continue;

		len = snprintf(name, sizeof(name), "%d", iter.tgid);
		ctx->pos = iter.tgid + TGID_OFFSET;
		if (!proc_fill_cache(file, ctx, name, len,
				     proc_pid_instantiate, iter.task, NULL)) {
			put_task_struct(iter.task);
			return 0;
		}
	}
	ctx->pos = PID_MAX_LIMIT + TGID_OFFSET;
	return 0;
}

/*
 * Tasks
 */
static const struct pid_entry tid_base_stuff[] = {
	DIR("fd",        S_IRUSR|S_IXUSR, proc_fd_inode_operations, proc_fd_operations),
	DIR("fdinfo",    S_IRUSR|S_IXUSR, proc_fdinfo_inode_operations, proc_fdinfo_operations),
	DIR("ns",	 S_IRUSR|S_IXUGO, proc_ns_dir_inode_operations, proc_ns_dir_operations),
#ifdef CONFIG_NET
	DIR("net",        S_IRUGO|S_IXUGO, proc_net_inode_operations, proc_net_operations),
#endif
	REG("environ",   S_IRUSR, proc_environ_operations),
	ONE("auxv",      S_IRUSR, proc_pid_auxv),
	ONE("status",    S_IRUGO, proc_pid_status),
	ONE("personality", S_IRUSR, proc_pid_personality),
	ONE("limits",	 S_IRUGO, proc_pid_limits),
#ifdef CONFIG_SCHED_DEBUG
	REG("sched",     S_IRUGO|S_IWUSR, proc_pid_sched_operations),
#endif
	REG("comm",      S_IRUGO|S_IWUSR, proc_pid_set_comm_operations),
#ifdef CONFIG_HAVE_ARCH_TRACEHOOK
	ONE("syscall",   S_IRUSR, proc_pid_syscall),
#endif
	ONE("cmdline",   S_IRUGO, proc_pid_cmdline),
	ONE("stat",      S_IRUGO, proc_tid_stat),
	ONE("statm",     S_IRUGO, proc_pid_statm),
	REG("maps",      S_IRUGO, proc_tid_maps_operations),
#ifdef CONFIG_CHECKPOINT_RESTORE
	REG("children",  S_IRUGO, proc_tid_children_operations),
#endif
#ifdef CONFIG_NUMA
	REG("numa_maps", S_IRUGO, proc_tid_numa_maps_operations),
#endif
	REG("mem",       S_IRUSR|S_IWUSR, proc_mem_operations),
	LNK("cwd",       proc_cwd_link),
	LNK("root",      proc_root_link),
	LNK("exe",       proc_exe_link),
	REG("mounts",    S_IRUGO, proc_mounts_operations),
	REG("mountinfo",  S_IRUGO, proc_mountinfo_operations),
#ifdef CONFIG_PROC_PAGE_MONITOR
	REG("clear_refs", S_IWUSR, proc_clear_refs_operations),
	REG("smaps",     S_IRUGO, proc_tid_smaps_operations),
	REG("pagemap",    S_IRUSR, proc_pagemap_operations),
#endif
#ifdef CONFIG_SECURITY
	DIR("attr",      S_IRUGO|S_IXUGO, proc_attr_dir_inode_operations, proc_attr_dir_operations),
#endif
#ifdef CONFIG_KALLSYMS
	ONE("wchan",     S_IRUGO, proc_pid_wchan),
#endif
#ifdef CONFIG_STACKTRACE
	ONE("stack",      S_IRUSR, proc_pid_stack),
#endif
#ifdef CONFIG_SCHEDSTATS
	ONE("schedstat", S_IRUGO, proc_pid_schedstat),
#endif
#ifdef CONFIG_LATENCYTOP
	REG("latency",  S_IRUGO, proc_lstats_operations),
#endif
#ifdef CONFIG_PROC_PID_CPUSET
	REG("cpuset",    S_IRUGO, proc_cpuset_operations),
#endif
#ifdef CONFIG_CGROUPS
	REG("cgroup",  S_IRUGO, proc_cgroup_operations),
#endif
	ONE("oom_score", S_IRUGO, proc_oom_score),
	REG("oom_adj",   S_IRUGO|S_IWUSR, proc_oom_adj_operations),
	REG("oom_score_adj", S_IRUGO|S_IWUSR, proc_oom_score_adj_operations),
#ifdef CONFIG_AUDITSYSCALL
	REG("loginuid",  S_IWUSR|S_IRUGO, proc_loginuid_operations),
	REG("sessionid",  S_IRUGO, proc_sessionid_operations),
#endif
#ifdef CONFIG_FAULT_INJECTION
	REG("make-it-fail", S_IRUGO|S_IWUSR, proc_fault_inject_operations),
#endif
#ifdef CONFIG_TASK_IO_ACCOUNTING
	ONE("io",	S_IRUSR, proc_tid_io_accounting),
#endif
#ifdef CONFIG_HARDWALL
	ONE("hardwall",   S_IRUGO, proc_pid_hardwall),
#endif
#ifdef CONFIG_USER_NS
	REG("uid_map",    S_IRUGO|S_IWUSR, proc_uid_map_operations),
	REG("gid_map",    S_IRUGO|S_IWUSR, proc_gid_map_operations),
	REG("projid_map", S_IRUGO|S_IWUSR, proc_projid_map_operations),
#endif
};

static int proc_tid_base_readdir(struct file *file, struct dir_context *ctx)
{
	return proc_pident_readdir(file, ctx,
				   tid_base_stuff, ARRAY_SIZE(tid_base_stuff));
}

static struct dentry *proc_tid_base_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	return proc_pident_lookup(dir, dentry,
				  tid_base_stuff, ARRAY_SIZE(tid_base_stuff));
}

static const struct file_operations proc_tid_base_operations = {
	.read		= generic_read_dir,
	.iterate	= proc_tid_base_readdir,
	.llseek		= default_llseek,
};

static const struct inode_operations proc_tid_base_inode_operations = {
	.lookup		= proc_tid_base_lookup,
	.getattr	= pid_getattr,
	.setattr	= proc_setattr,
};

static int proc_task_instantiate(struct inode *dir,
	struct dentry *dentry, struct task_struct *task, const void *ptr)
{
	struct inode *inode;
	inode = proc_pid_make_inode(dir->i_sb, task);

	if (!inode)
		goto out;
	inode->i_mode = S_IFDIR|S_IRUGO|S_IXUGO;
	inode->i_op = &proc_tid_base_inode_operations;
	inode->i_fop = &proc_tid_base_operations;
	inode->i_flags|=S_IMMUTABLE;

	set_nlink(inode, 2 + pid_entry_count_dirs(tid_base_stuff,
						  ARRAY_SIZE(tid_base_stuff)));

	d_set_d_op(dentry, &pid_dentry_operations);

	d_add(dentry, inode);
	/* Close the race of the process dying before we return the dentry */
	if (pid_revalidate(dentry, 0))
		return 0;
out:
	return -ENOENT;
}

static struct dentry *proc_task_lookup(struct inode *dir, struct dentry * dentry, unsigned int flags)
{
	int result = -ENOENT;
	struct task_struct *task;
	struct task_struct *leader = get_proc_task(dir);
	unsigned tid;
	struct pid_namespace *ns;

	if (!leader)
		goto out_no_task;

	tid = name_to_int(&dentry->d_name);
	if (tid == ~0U)
		goto out;

	ns = dentry->d_sb->s_fs_info;
	rcu_read_lock();
	task = find_task_by_pid_ns(tid, ns);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();
	if (!task)
		goto out;
	if (!same_thread_group(leader, task))
		goto out_drop_task;

	result = proc_task_instantiate(dir, dentry, task, NULL);
out_drop_task:
	put_task_struct(task);
out:
	put_task_struct(leader);
out_no_task:
	return ERR_PTR(result);
}

/*
 * Find the first tid of a thread group to return to user space.
 *
 * Usually this is just the thread group leader, but if the users
 * buffer was too small or there was a seek into the middle of the
 * directory we have more work todo.
 *
 * In the case of a short read we start with find_task_by_pid.
 *
 * In the case of a seek we start with the leader and walk nr
 * threads past it.
 */
static struct task_struct *first_tid(struct pid *pid, int tid, loff_t f_pos,
					struct pid_namespace *ns)
{
	struct task_struct *pos, *task;
	unsigned long nr = f_pos;

	if (nr != f_pos)	/* 32bit overflow? */
		return NULL;

	rcu_read_lock();
	task = pid_task(pid, PIDTYPE_PID);
	if (!task)
		goto fail;

	/* Attempt to start with the tid of a thread */
	if (tid && nr) {
		pos = find_task_by_pid_ns(tid, ns);
		if (pos && same_thread_group(pos, task))
			goto found;
	}

	/* If nr exceeds the number of threads there is nothing todo */
	if (nr >= get_nr_threads(task))
		goto fail;

	/* If we haven't found our starting place yet start
	 * with the leader and walk nr threads forward.
	 */
	pos = task = task->group_leader;
	do {
		if (!nr--)
			goto found;
	} while_each_thread(task, pos);
fail:
	pos = NULL;
	goto out;
found:
	get_task_struct(pos);
out:
	rcu_read_unlock();
	return pos;
}

/*
 * Find the next thread in the thread list.
 * Return NULL if there is an error or no next thread.
 *
 * The reference to the input task_struct is released.
 */
static struct task_struct *next_tid(struct task_struct *start)
{
	struct task_struct *pos = NULL;
	rcu_read_lock();
	if (pid_alive(start)) {
		pos = next_thread(start);
		if (thread_group_leader(pos))
			pos = NULL;
		else
			get_task_struct(pos);
	}
	rcu_read_unlock();
	put_task_struct(start);
	return pos;
}

/* for the /proc/TGID/task/ directories */
static int proc_task_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct task_struct *task;
	struct pid_namespace *ns;
	int tid;

	if (proc_inode_is_dead(inode))
		return -ENOENT;

	if (!dir_emit_dots(file, ctx))
		return 0;

	/* f_version caches the tgid value that the last readdir call couldn't
	 * return. lseek aka telldir automagically resets f_version to 0.
	 */
	ns = file->f_dentry->d_sb->s_fs_info;
	tid = (int)file->f_version;
	file->f_version = 0;
	for (task = first_tid(proc_pid(inode), tid, ctx->pos - 2, ns);
	     task;
	     task = next_tid(task), ctx->pos++) {
		char name[PROC_NUMBUF];
		int len;
		tid = task_pid_nr_ns(task, ns);
		len = snprintf(name, sizeof(name), "%d", tid);
		if (!proc_fill_cache(file, ctx, name, len,
				proc_task_instantiate, task, NULL)) {
			/* returning this tgid failed, save it as the first
			 * pid for the next readir call */
			file->f_version = (u64)tid;
			put_task_struct(task);
			break;
		}
	}

	return 0;
}

static int proc_task_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat)
{
	struct inode *inode = dentry->d_inode;
	struct task_struct *p = get_proc_task(inode);
	generic_fillattr(inode, stat);

	if (p) {
		stat->nlink += get_nr_threads(p);
		put_task_struct(p);
	}

	return 0;
}

static const struct inode_operations proc_task_inode_operations = {
	.lookup		= proc_task_lookup,
	.getattr	= proc_task_getattr,
	.setattr	= proc_setattr,
	.permission	= proc_pid_permission,
};

static const struct file_operations proc_task_operations = {
	.read		= generic_read_dir,
	.iterate	= proc_task_readdir,
	.llseek		= default_llseek,
};
/************************************************************/
/* ../linux-3.17/fs/proc/base.c */
/************************************************************/
/*
 * proc/fs/generic.c --- generic routines for the proc-fs
 *
 * This file contains generic proc-fs routines for handling
 * directories and files.
 *
 * Copyright (C) 1991, 1992 Linus Torvalds.
 * Copyright (C) 1997 Theodore Ts'o
 */

// #include <linux/errno.h>
// #include <linux/time.h>
// #include <linux/proc_fs.h>
// #include <linux/stat.h>
// #include <linux/mm.h>
// #include <linux/module.h>
// #include <linux/slab.h>
// #include <linux/printk.h>
// #include <linux/mount.h>
// #include <linux/init.h>
#include <linux/idr.h>
// #include <linux/namei.h>
// #include <linux/bitops.h>
#include <linux/spinlock.h>
// #include <linux/completion.h>
// #include <asm/uaccess.h>

// #include "internal.h"

static DEFINE_SPINLOCK(proc_subdir_lock);

static int proc_match(unsigned int len, const char *name, struct proc_dir_entry *de)
{
	if (de->namelen != len)
		return 0;
	return !memcmp(name, de->name, len);
}

static int proc_notify_change(struct dentry *dentry, struct iattr *iattr)
{
	struct inode *inode = dentry->d_inode;
	struct proc_dir_entry *de = PDE(inode);
	int error;

	error = inode_change_ok(inode, iattr);
	if (error)
		return error;

	setattr_copy(inode, iattr);
	mark_inode_dirty(inode);

	proc_set_user(de, inode->i_uid, inode->i_gid);
	de->mode = inode->i_mode;
	return 0;
}

static int proc_getattr(struct vfsmount *mnt, struct dentry *dentry,
			struct kstat *stat)
{
	struct inode *inode = dentry->d_inode;
	struct proc_dir_entry *de = PROC_I(inode)->pde;
	if (de && de->nlink)
		set_nlink(inode, de->nlink);

	generic_fillattr(inode, stat);
	return 0;
}

static const struct inode_operations proc_file_inode_operations = {
	.setattr	= proc_notify_change,
};

/*
 * This function parses a name such as "tty/driver/serial", and
 * returns the struct proc_dir_entry for "/proc/tty/driver", and
 * returns "serial" in residual.
 */
static int __xlate_proc_name(const char *name, struct proc_dir_entry **ret,
			     const char **residual)
{
	const char     		*cp = name, *next;
	struct proc_dir_entry	*de;
	unsigned int		len;

	de = *ret;
	if (!de)
		de = &proc_root;

	while (1) {
		next = strchr(cp, '/');
		if (!next)
			break;

		len = next - cp;
		for (de = de->subdir; de ; de = de->next) {
			if (proc_match(len, cp, de))
				break;
		}
		if (!de) {
			WARN(1, "name '%s'\n", name);
			return -ENOENT;
		}
		cp += len + 1;
	}
	*residual = cp;
	*ret = de;
	return 0;
}

static int xlate_proc_name(const char *name, struct proc_dir_entry **ret,
			   const char **residual)
{
	int rv;

	spin_lock(&proc_subdir_lock);
	rv = __xlate_proc_name(name, ret, residual);
	spin_unlock(&proc_subdir_lock);
	return rv;
}

static DEFINE_IDA(proc_inum_ida);
static DEFINE_SPINLOCK(proc_inum_lock); /* protects the above */

#define PROC_DYNAMIC_FIRST 0xF0000000U

/*
 * Return an inode number between PROC_DYNAMIC_FIRST and
 * 0xffffffff, or zero on failure.
 */
int proc_alloc_inum(unsigned int *inum)
{
	unsigned int i;
	int error;

retry:
	if (!ida_pre_get(&proc_inum_ida, GFP_KERNEL))
		return -ENOMEM;

	spin_lock_irq(&proc_inum_lock);
	error = ida_get_new(&proc_inum_ida, &i);
	spin_unlock_irq(&proc_inum_lock);
	if (error == -EAGAIN)
		goto retry;
	else if (error)
		return error;

	if (i > UINT_MAX - PROC_DYNAMIC_FIRST) {
		spin_lock_irq(&proc_inum_lock);
		ida_remove(&proc_inum_ida, i);
		spin_unlock_irq(&proc_inum_lock);
		return -ENOSPC;
	}
	*inum = PROC_DYNAMIC_FIRST + i;
	return 0;
}

void proc_free_inum(unsigned int inum)
{
	unsigned long flags;
	spin_lock_irqsave(&proc_inum_lock, flags);
	ida_remove(&proc_inum_ida, inum - PROC_DYNAMIC_FIRST);
	spin_unlock_irqrestore(&proc_inum_lock, flags);
}

static void *proc_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	nd_set_link(nd, __PDE_DATA(dentry->d_inode));
	return NULL;
}

static const struct inode_operations proc_link_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= proc_follow_link,
};

/*
 * Don't create negative dentries here, return -ENOENT by hand
 * instead.
 */
struct dentry *proc_lookup_de(struct proc_dir_entry *de, struct inode *dir,
		struct dentry *dentry)
{
	struct inode *inode;

	spin_lock(&proc_subdir_lock);
	for (de = de->subdir; de ; de = de->next) {
		if (de->namelen != dentry->d_name.len)
			continue;
		if (!memcmp(dentry->d_name.name, de->name, de->namelen)) {
			pde_get(de);
			spin_unlock(&proc_subdir_lock);
			inode = proc_get_inode(dir->i_sb, de);
			if (!inode)
				return ERR_PTR(-ENOMEM);
			d_set_d_op(dentry, &simple_dentry_operations);
			d_add(dentry, inode);
			return NULL;
		}
	}
	spin_unlock(&proc_subdir_lock);
	return ERR_PTR(-ENOENT);
}

struct dentry *proc_lookup(struct inode *dir, struct dentry *dentry,
		unsigned int flags)
{
	return proc_lookup_de(PDE(dir), dir, dentry);
}

/*
 * This returns non-zero if at EOF, so that the /proc
 * root directory can use this and check if it should
 * continue with the <pid> entries..
 *
 * Note that the VFS-layer doesn't care about the return
 * value of the readdir() call, as long as it's non-negative
 * for success..
 */
int proc_readdir_de(struct proc_dir_entry *de, struct file *file,
		    struct dir_context *ctx)
{
	int i;

	if (!dir_emit_dots(file, ctx))
		return 0;

	spin_lock(&proc_subdir_lock);
	de = de->subdir;
	i = ctx->pos - 2;
	for (;;) {
		if (!de) {
			spin_unlock(&proc_subdir_lock);
			return 0;
		}
		if (!i)
			break;
		de = de->next;
		i--;
	}

	do {
		struct proc_dir_entry *next;
		pde_get(de);
		spin_unlock(&proc_subdir_lock);
		if (!dir_emit(ctx, de->name, de->namelen,
			    de->low_ino, de->mode >> 12)) {
			pde_put(de);
			return 0;
		}
		spin_lock(&proc_subdir_lock);
		ctx->pos++;
		next = de->next;
		pde_put(de);
		de = next;
	} while (de);
	spin_unlock(&proc_subdir_lock);
	return 1;
}

int proc_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);

	return proc_readdir_de(PDE(inode), file, ctx);
}

/*
 * These are the generic /proc directory operations. They
 * use the in-memory "struct proc_dir_entry" tree to parse
 * the /proc directory.
 */
static const struct file_operations proc_dir_operations = {
	.llseek			= generic_file_llseek,
	.read			= generic_read_dir,
	.iterate		= proc_readdir,
};

/*
 * proc directories can do almost nothing..
 */
static const struct inode_operations proc_dir_inode_operations = {
	.lookup		= proc_lookup,
	.getattr	= proc_getattr,
	.setattr	= proc_notify_change,
};

static int proc_register(struct proc_dir_entry * dir, struct proc_dir_entry * dp)
{
	struct proc_dir_entry *tmp;
	int ret;

	ret = proc_alloc_inum(&dp->low_ino);
	if (ret)
		return ret;

	if (S_ISDIR(dp->mode)) {
		dp->proc_fops = &proc_dir_operations;
		dp->proc_iops = &proc_dir_inode_operations;
		dir->nlink++;
	} else if (S_ISLNK(dp->mode)) {
		dp->proc_iops = &proc_link_inode_operations;
	} else if (S_ISREG(dp->mode)) {
		BUG_ON(dp->proc_fops == NULL);
		dp->proc_iops = &proc_file_inode_operations;
	} else {
		WARN_ON(1);
		return -EINVAL;
	}

	spin_lock(&proc_subdir_lock);

	for (tmp = dir->subdir; tmp; tmp = tmp->next)
		if (strcmp(tmp->name, dp->name) == 0) {
			WARN(1, "proc_dir_entry '%s/%s' already registered\n",
				dir->name, dp->name);
			break;
		}

	dp->next = dir->subdir;
	dp->parent = dir;
	dir->subdir = dp;
	spin_unlock(&proc_subdir_lock);

	return 0;
}

static struct proc_dir_entry *__proc_create(struct proc_dir_entry **parent,
					  const char *name,
					  umode_t mode,
					  nlink_t nlink)
{
	struct proc_dir_entry *ent = NULL;
	const char *fn;
	struct qstr qstr;

	if (xlate_proc_name(name, parent, &fn) != 0)
		goto out;
	qstr.name = fn;
	qstr.len = strlen(fn);
	if (qstr.len == 0 || qstr.len >= 256) {
		WARN(1, "name len %u\n", qstr.len);
		return NULL;
	}
	if (*parent == &proc_root && name_to_int(&qstr) != ~0U) {
		WARN(1, "create '/proc/%s' by hand\n", qstr.name);
		return NULL;
	}

	ent = kzalloc(sizeof(struct proc_dir_entry) + qstr.len + 1, GFP_KERNEL);
	if (!ent)
		goto out;

	memcpy(ent->name, fn, qstr.len + 1);
	ent->namelen = qstr.len;
	ent->mode = mode;
	ent->nlink = nlink;
	atomic_set(&ent->count, 1);
	spin_lock_init(&ent->pde_unload_lock);
	INIT_LIST_HEAD(&ent->pde_openers);
out:
	return ent;
}

struct proc_dir_entry *proc_symlink(const char *name,
		struct proc_dir_entry *parent, const char *dest)
{
	struct proc_dir_entry *ent;

	ent = __proc_create(&parent, name,
			  (S_IFLNK | S_IRUGO | S_IWUGO | S_IXUGO),1);

	if (ent) {
		ent->data = kmalloc((ent->size=strlen(dest))+1, GFP_KERNEL);
		if (ent->data) {
			strcpy((char*)ent->data,dest);
			if (proc_register(parent, ent) < 0) {
				kfree(ent->data);
				kfree(ent);
				ent = NULL;
			}
		} else {
			kfree(ent);
			ent = NULL;
		}
	}
	return ent;
}
EXPORT_SYMBOL(proc_symlink);

struct proc_dir_entry *proc_mkdir_data(const char *name, umode_t mode,
		struct proc_dir_entry *parent, void *data)
{
	struct proc_dir_entry *ent;

	if (mode == 0)
		mode = S_IRUGO | S_IXUGO;

	ent = __proc_create(&parent, name, S_IFDIR | mode, 2);
	if (ent) {
		ent->data = data;
		if (proc_register(parent, ent) < 0) {
			kfree(ent);
			ent = NULL;
		}
	}
	return ent;
}
EXPORT_SYMBOL_GPL(proc_mkdir_data);

struct proc_dir_entry *proc_mkdir_mode(const char *name, umode_t mode,
				       struct proc_dir_entry *parent)
{
	return proc_mkdir_data(name, mode, parent, NULL);
}
EXPORT_SYMBOL(proc_mkdir_mode);

struct proc_dir_entry *proc_mkdir(const char *name,
		struct proc_dir_entry *parent)
{
	return proc_mkdir_data(name, 0, parent, NULL);
}
EXPORT_SYMBOL(proc_mkdir);

struct proc_dir_entry *proc_create_data(const char *name, umode_t mode,
					struct proc_dir_entry *parent,
					const struct file_operations *proc_fops,
					void *data)
{
	struct proc_dir_entry *pde;
	if ((mode & S_IFMT) == 0)
		mode |= S_IFREG;

	if (!S_ISREG(mode)) {
		WARN_ON(1);	/* use proc_mkdir() */
		return NULL;
	}

	if ((mode & S_IALLUGO) == 0)
		mode |= S_IRUGO;
	pde = __proc_create(&parent, name, mode, 1);
	if (!pde)
		goto out;
	pde->proc_fops = proc_fops;
	pde->data = data;
	if (proc_register(parent, pde) < 0)
		goto out_free;
	return pde;
out_free:
	kfree(pde);
out:
	return NULL;
}
EXPORT_SYMBOL(proc_create_data);

void proc_set_size(struct proc_dir_entry *de, loff_t size)
{
	de->size = size;
}
EXPORT_SYMBOL(proc_set_size);

void proc_set_user(struct proc_dir_entry *de, kuid_t uid, kgid_t gid)
{
	de->uid = uid;
	de->gid = gid;
}
EXPORT_SYMBOL(proc_set_user);

static void free_proc_entry(struct proc_dir_entry *de)
{
	proc_free_inum(de->low_ino);

	if (S_ISLNK(de->mode))
		kfree(de->data);
	kfree(de);
}

void pde_put(struct proc_dir_entry *pde)
{
	if (atomic_dec_and_test(&pde->count))
		free_proc_entry(pde);
}

/*
 * Remove a /proc entry and free it if it's not currently in use.
 */
void remove_proc_entry(const char *name, struct proc_dir_entry *parent)
{
	struct proc_dir_entry **p;
	struct proc_dir_entry *de = NULL;
	const char *fn = name;
	unsigned int len;

	spin_lock(&proc_subdir_lock);
	if (__xlate_proc_name(name, &parent, &fn) != 0) {
		spin_unlock(&proc_subdir_lock);
		return;
	}
	len = strlen(fn);

	for (p = &parent->subdir; *p; p=&(*p)->next ) {
		if (proc_match(len, fn, *p)) {
			de = *p;
			*p = de->next;
			de->next = NULL;
			break;
		}
	}
	spin_unlock(&proc_subdir_lock);
	if (!de) {
		WARN(1, "name '%s'\n", name);
		return;
	}

	proc_entry_rundown(de);

	if (S_ISDIR(de->mode))
		parent->nlink--;
	de->nlink = 0;
	WARN(de->subdir, "%s: removing non-empty directory "
			 "'%s/%s', leaking at least '%s'\n", __func__,
			 de->parent->name, de->name, de->subdir->name);
	pde_put(de);
}
EXPORT_SYMBOL(remove_proc_entry);

int remove_proc_subtree(const char *name, struct proc_dir_entry *parent)
{
	struct proc_dir_entry **p;
	struct proc_dir_entry *root = NULL, *de, *next;
	const char *fn = name;
	unsigned int len;

	spin_lock(&proc_subdir_lock);
	if (__xlate_proc_name(name, &parent, &fn) != 0) {
		spin_unlock(&proc_subdir_lock);
		return -ENOENT;
	}
	len = strlen(fn);

	for (p = &parent->subdir; *p; p=&(*p)->next ) {
		if (proc_match(len, fn, *p)) {
			root = *p;
			*p = root->next;
			root->next = NULL;
			break;
		}
	}
	if (!root) {
		spin_unlock(&proc_subdir_lock);
		return -ENOENT;
	}
	de = root;
	while (1) {
		next = de->subdir;
		if (next) {
			de->subdir = next->next;
			next->next = NULL;
			de = next;
			continue;
		}
		spin_unlock(&proc_subdir_lock);

		proc_entry_rundown(de);
		next = de->parent;
		if (S_ISDIR(de->mode))
			next->nlink--;
		de->nlink = 0;
		if (de == root)
			break;
		pde_put(de);

		spin_lock(&proc_subdir_lock);
		de = next;
	}
	pde_put(root);
	return 0;
}
EXPORT_SYMBOL(remove_proc_subtree);

void *proc_get_parent_data(const struct inode *inode)
{
	struct proc_dir_entry *de = PDE(inode);
	return de->parent->data;
}
EXPORT_SYMBOL_GPL(proc_get_parent_data);

void proc_remove(struct proc_dir_entry *de)
{
	if (de)
		remove_proc_subtree(de->name, de->parent);
}
EXPORT_SYMBOL(proc_remove);

void *PDE_DATA(const struct inode *inode)
{
	return __PDE_DATA(inode);
}
EXPORT_SYMBOL(PDE_DATA);
/************************************************************/
/* ../linux-3.17/fs/proc/generic.c */
/************************************************************/
/*
 *  linux/fs/proc/array.c
 *
 *  Copyright (C) 1992  by Linus Torvalds
 *  based on ideas by Darren Senn
 *
 * Fixes:
 * Michael. K. Johnson: stat,statm extensions.
 *                      <johnsonm@stolaf.edu>
 *
 * Pauline Middelink :  Made cmdline,envline only break at '\0's, to
 *                      make sure SET_PROCTITLE works. Also removed
 *                      bad '!' which forced address recalculation for
 *                      EVERY character on the current page.
 *                      <middelin@polyware.iaf.nl>
 *
 * Danny ter Haar    :	added cpuinfo
 *			<dth@cistron.nl>
 *
 * Alessandro Rubini :  profile extension.
 *                      <rubini@ipvvis.unipv.it>
 *
 * Jeff Tranter      :  added BogoMips field to cpuinfo
 *                      <Jeff_Tranter@Mitel.COM>
 *
 * Bruno Haible      :  remove 4K limit for the maps file
 *			<haible@ma2s2.mathematik.uni-karlsruhe.de>
 *
 * Yves Arrouye      :  remove removal of trailing spaces in get_array.
 *			<Yves.Arrouye@marin.fdn.fr>
 *
 * Jerome Forissier  :  added per-CPU time information to /proc/stat
 *                      and /proc/<pid>/cpu extension
 *                      <forissier@isia.cma.fr>
 *			- Incorporation and non-SMP safe operation
 *			of forissier patch in 2.1.78 by
 *			Hans Marcus <crowbar@concepts.nl>
 *
 * aeb@cwi.nl        :  /proc/partitions
 *
 *
 * Alan Cox	     :  security fixes.
 *			<alan@lxorguk.ukuu.org.uk>
 *
 * Al Viro           :  safe handling of mm_struct
 *
 * Gerhard Wichert   :  added BIGMEM support
 * Siemens AG           <Gerhard.Wichert@pdb.siemens.de>
 *
 * Al Viro & Jeff Garzik :  moved most of the thing into base.c and
 *			 :  proc_misc.c. The rest may eventually go into
 *			 :  base.c too.
 */

#include <linux/types.h>
// #include <linux/errno.h>
// #include <linux/time.h>
// #include <linux/kernel.h>
#include <linux/kernel_stat.h>
#include <linux/tty.h>
// #include <linux/string.h>
// #include <linux/mman.h>
// #include <linux/proc_fs.h>
#include <linux/ioport.h>
#include <linux/uaccess.h>
#include <linux/io.h>
// #include <linux/mm.h>
// #include <linux/hugetlb.h>
// #include <linux/pagemap.h>
// #include <linux/swap.h>
// #include <linux/smp.h>
#include <linux/signal.h>
// #include <linux/highmem.h>
// #include <linux/file.h>
// #include <linux/fdtable.h>
#include <linux/times.h>
// #include <linux/cpuset.h>
// #include <linux/rcupdate.h>
#include <linux/delayacct.h>
// #include <linux/seq_file.h>
// #include <linux/pid_namespace.h>
// #include <linux/ptrace.h>
// #include <linux/tracehook.h>
// #include <linux/user_namespace.h>

// #include <asm/pgtable.h>
#include <asm/processor.h>
// #include "internal.h"

static inline void task_name(struct seq_file *m, struct task_struct *p)
{
	int i;
	char *buf, *end;
	char *name;
	char tcomm[sizeof(p->comm)];

	get_task_comm(tcomm, p);

	seq_puts(m, "Name:\t");
	end = m->buf + m->size;
	buf = m->buf + m->count;
	name = tcomm;
	i = sizeof(tcomm);
	while (i && (buf < end)) {
		unsigned char c = *name;
		name++;
		i--;
		*buf = c;
		if (!c)
			break;
		if (c == '\\') {
			buf++;
			if (buf < end)
				*buf++ = c;
			continue;
		}
		if (c == '\n') {
			*buf++ = '\\';
			if (buf < end)
				*buf++ = 'n';
			continue;
		}
		buf++;
	}
	m->count = buf - m->buf;
	seq_putc(m, '\n');
}

/*
 * The task state array is a strange "bitmap" of
 * reasons to sleep. Thus "running" is zero, and
 * you can test for combinations of others with
 * simple bit tests.
 */
static const char * const task_state_array[] = {
	"R (running)",		/*   0 */
	"S (sleeping)",		/*   1 */
	"D (disk sleep)",	/*   2 */
	"T (stopped)",		/*   4 */
	"t (tracing stop)",	/*   8 */
	"X (dead)",		/*  16 */
	"Z (zombie)",		/*  32 */
};

static inline const char *get_task_state(struct task_struct *tsk)
{
	unsigned int state = (tsk->state | tsk->exit_state) & TASK_REPORT;

	BUILD_BUG_ON(1 + ilog2(TASK_REPORT) != ARRAY_SIZE(task_state_array)-1);

	return task_state_array[fls(state)];
}

static inline void task_state(struct seq_file *m, struct pid_namespace *ns,
				struct pid *pid, struct task_struct *p)
{
	struct user_namespace *user_ns = seq_user_ns(m);
	struct group_info *group_info;
	int g;
	struct fdtable *fdt = NULL;
	const struct cred *cred;
	pid_t ppid, tpid;

	rcu_read_lock();
	ppid = pid_alive(p) ?
		task_tgid_nr_ns(rcu_dereference(p->real_parent), ns) : 0;
	tpid = 0;
	if (pid_alive(p)) {
		struct task_struct *tracer = ptrace_parent(p);
		if (tracer)
			tpid = task_pid_nr_ns(tracer, ns);
	}
	cred = get_task_cred(p);
	seq_printf(m,
		"State:\t%s\n"
		"Tgid:\t%d\n"
		"Ngid:\t%d\n"
		"Pid:\t%d\n"
		"PPid:\t%d\n"
		"TracerPid:\t%d\n"
		"Uid:\t%d\t%d\t%d\t%d\n"
		"Gid:\t%d\t%d\t%d\t%d\n",
		get_task_state(p),
		task_tgid_nr_ns(p, ns),
		task_numa_group_id(p),
		pid_nr_ns(pid, ns),
		ppid, tpid,
		from_kuid_munged(user_ns, cred->uid),
		from_kuid_munged(user_ns, cred->euid),
		from_kuid_munged(user_ns, cred->suid),
		from_kuid_munged(user_ns, cred->fsuid),
		from_kgid_munged(user_ns, cred->gid),
		from_kgid_munged(user_ns, cred->egid),
		from_kgid_munged(user_ns, cred->sgid),
		from_kgid_munged(user_ns, cred->fsgid));

	task_lock(p);
	if (p->files)
		fdt = files_fdtable(p->files);
	seq_printf(m,
		"FDSize:\t%d\n"
		"Groups:\t",
		fdt ? fdt->max_fds : 0);
	rcu_read_unlock();

	group_info = cred->group_info;
	task_unlock(p);

	for (g = 0; g < group_info->ngroups; g++)
		seq_printf(m, "%d ",
			   from_kgid_munged(user_ns, GROUP_AT(group_info, g)));
	put_cred(cred);

	seq_putc(m, '\n');
}

void render_sigset_t(struct seq_file *m, const char *header,
				sigset_t *set)
{
	int i;

	seq_puts(m, header);

	i = _NSIG;
	do {
		int x = 0;

		i -= 4;
		if (sigismember(set, i+1)) x |= 1;
		if (sigismember(set, i+2)) x |= 2;
		if (sigismember(set, i+3)) x |= 4;
		if (sigismember(set, i+4)) x |= 8;
		seq_printf(m, "%x", x);
	} while (i >= 4);

	seq_putc(m, '\n');
}

static void collect_sigign_sigcatch(struct task_struct *p, sigset_t *ign,
				    sigset_t *catch)
{
	struct k_sigaction *k;
	int i;

	k = p->sighand->action;
	for (i = 1; i <= _NSIG; ++i, ++k) {
		if (k->sa.sa_handler == SIG_IGN)
			sigaddset(ign, i);
		else if (k->sa.sa_handler != SIG_DFL)
			sigaddset(catch, i);
	}
}

static inline void task_sig(struct seq_file *m, struct task_struct *p)
{
	unsigned long flags;
	sigset_t pending, shpending, blocked, ignored, caught;
	int num_threads = 0;
	unsigned long qsize = 0;
	unsigned long qlim = 0;

	sigemptyset(&pending);
	sigemptyset(&shpending);
	sigemptyset(&blocked);
	sigemptyset(&ignored);
	sigemptyset(&caught);

	if (lock_task_sighand(p, &flags)) {
		pending = p->pending.signal;
		shpending = p->signal->shared_pending.signal;
		blocked = p->blocked;
		collect_sigign_sigcatch(p, &ignored, &caught);
		num_threads = get_nr_threads(p);
		rcu_read_lock();  /* FIXME: is this correct? */
		qsize = atomic_read(&__task_cred(p)->user->sigpending);
		rcu_read_unlock();
		qlim = task_rlimit(p, RLIMIT_SIGPENDING);
		unlock_task_sighand(p, &flags);
	}

	seq_printf(m, "Threads:\t%d\n", num_threads);
	seq_printf(m, "SigQ:\t%lu/%lu\n", qsize, qlim);

	/* render them all */
	render_sigset_t(m, "SigPnd:\t", &pending);
	render_sigset_t(m, "ShdPnd:\t", &shpending);
	render_sigset_t(m, "SigBlk:\t", &blocked);
	render_sigset_t(m, "SigIgn:\t", &ignored);
	render_sigset_t(m, "SigCgt:\t", &caught);
}

static void render_cap_t(struct seq_file *m, const char *header,
			kernel_cap_t *a)
{
	unsigned __capi;

	seq_puts(m, header);
	CAP_FOR_EACH_U32(__capi) {
		seq_printf(m, "%08x",
			   a->cap[CAP_LAST_U32 - __capi]);
	}
	seq_putc(m, '\n');
}

static inline void task_cap(struct seq_file *m, struct task_struct *p)
{
	const struct cred *cred;
	kernel_cap_t cap_inheritable, cap_permitted, cap_effective, cap_bset;

	rcu_read_lock();
	cred = __task_cred(p);
	cap_inheritable	= cred->cap_inheritable;
	cap_permitted	= cred->cap_permitted;
	cap_effective	= cred->cap_effective;
	cap_bset	= cred->cap_bset;
	rcu_read_unlock();

	render_cap_t(m, "CapInh:\t", &cap_inheritable);
	render_cap_t(m, "CapPrm:\t", &cap_permitted);
	render_cap_t(m, "CapEff:\t", &cap_effective);
	render_cap_t(m, "CapBnd:\t", &cap_bset);
}

static inline void task_seccomp(struct seq_file *m, struct task_struct *p)
{
#ifdef CONFIG_SECCOMP
	seq_printf(m, "Seccomp:\t%d\n", p->seccomp.mode);
#endif
}

static inline void task_context_switch_counts(struct seq_file *m,
						struct task_struct *p)
{
	seq_printf(m,	"voluntary_ctxt_switches:\t%lu\n"
			"nonvoluntary_ctxt_switches:\t%lu\n",
			p->nvcsw,
			p->nivcsw);
}

static void task_cpus_allowed(struct seq_file *m, struct task_struct *task)
{
	seq_puts(m, "Cpus_allowed:\t");
	seq_cpumask(m, &task->cpus_allowed);
	seq_putc(m, '\n');
	seq_puts(m, "Cpus_allowed_list:\t");
	seq_cpumask_list(m, &task->cpus_allowed);
	seq_putc(m, '\n');
}

int proc_pid_status(struct seq_file *m, struct pid_namespace *ns,
			struct pid *pid, struct task_struct *task)
{
	struct mm_struct *mm = get_task_mm(task);

	task_name(m, task);
	task_state(m, ns, pid, task);

	if (mm) {
		task_mem(m, mm);
		mmput(mm);
	}
	task_sig(m, task);
	task_cap(m, task);
	task_seccomp(m, task);
	task_cpus_allowed(m, task);
	cpuset_task_status_allowed(m, task);
	task_context_switch_counts(m, task);
	return 0;
}

static int do_task_stat(struct seq_file *m, struct pid_namespace *ns,
			struct pid *pid, struct task_struct *task, int whole)
{
	unsigned long vsize, eip, esp, wchan = ~0UL;
	int priority, nice;
	int tty_pgrp = -1, tty_nr = 0;
	sigset_t sigign, sigcatch;
	char state;
	pid_t ppid = 0, pgid = -1, sid = -1;
	int num_threads = 0;
	int permitted;
	struct mm_struct *mm;
	unsigned long long start_time;
	unsigned long cmin_flt = 0, cmaj_flt = 0;
	unsigned long  min_flt = 0,  maj_flt = 0;
	cputime_t cutime, cstime, utime, stime;
	cputime_t cgtime, gtime;
	unsigned long rsslim = 0;
	char tcomm[sizeof(task->comm)];
	unsigned long flags;

	state = *get_task_state(task);
	vsize = eip = esp = 0;
	permitted = ptrace_may_access(task, PTRACE_MODE_READ | PTRACE_MODE_NOAUDIT);
	mm = get_task_mm(task);
	if (mm) {
		vsize = task_vsize(mm);
		if (permitted) {
			eip = KSTK_EIP(task);
			esp = KSTK_ESP(task);
		}
	}

	get_task_comm(tcomm, task);

	sigemptyset(&sigign);
	sigemptyset(&sigcatch);
	cutime = cstime = utime = stime = 0;
	cgtime = gtime = 0;

	if (lock_task_sighand(task, &flags)) {
		struct signal_struct *sig = task->signal;

		if (sig->tty) {
			struct pid *pgrp = tty_get_pgrp(sig->tty);
			tty_pgrp = pid_nr_ns(pgrp, ns);
			put_pid(pgrp);
			tty_nr = new_encode_dev(tty_devnum(sig->tty));
		}

		num_threads = get_nr_threads(task);
		collect_sigign_sigcatch(task, &sigign, &sigcatch);

		cmin_flt = sig->cmin_flt;
		cmaj_flt = sig->cmaj_flt;
		cutime = sig->cutime;
		cstime = sig->cstime;
		cgtime = sig->cgtime;
		rsslim = ACCESS_ONCE(sig->rlim[RLIMIT_RSS].rlim_cur);

		/* add up live thread stats at the group level */
		if (whole) {
			struct task_struct *t = task;
			do {
				min_flt += t->min_flt;
				maj_flt += t->maj_flt;
				gtime += task_gtime(t);
			} while_each_thread(task, t);

			min_flt += sig->min_flt;
			maj_flt += sig->maj_flt;
			thread_group_cputime_adjusted(task, &utime, &stime);
			gtime += sig->gtime;
		}

		sid = task_session_nr_ns(task, ns);
		ppid = task_tgid_nr_ns(task->real_parent, ns);
		pgid = task_pgrp_nr_ns(task, ns);

		unlock_task_sighand(task, &flags);
	}

	if (permitted && (!whole || num_threads < 2))
		wchan = get_wchan(task);
	if (!whole) {
		min_flt = task->min_flt;
		maj_flt = task->maj_flt;
		task_cputime_adjusted(task, &utime, &stime);
		gtime = task_gtime(task);
	}

	/* scale priority and nice values from timeslices to -20..20 */
	/* to make it look like a "normal" Unix priority/nice value  */
	priority = task_prio(task);
	nice = task_nice(task);

	/* convert nsec -> ticks */
	start_time = nsec_to_clock_t(task->real_start_time);

	seq_printf(m, "%d (%s) %c", pid_nr_ns(pid, ns), tcomm, state);
	seq_put_decimal_ll(m, ' ', ppid);
	seq_put_decimal_ll(m, ' ', pgid);
	seq_put_decimal_ll(m, ' ', sid);
	seq_put_decimal_ll(m, ' ', tty_nr);
	seq_put_decimal_ll(m, ' ', tty_pgrp);
	seq_put_decimal_ull(m, ' ', task->flags);
	seq_put_decimal_ull(m, ' ', min_flt);
	seq_put_decimal_ull(m, ' ', cmin_flt);
	seq_put_decimal_ull(m, ' ', maj_flt);
	seq_put_decimal_ull(m, ' ', cmaj_flt);
	seq_put_decimal_ull(m, ' ', cputime_to_clock_t(utime));
	seq_put_decimal_ull(m, ' ', cputime_to_clock_t(stime));
	seq_put_decimal_ll(m, ' ', cputime_to_clock_t(cutime));
	seq_put_decimal_ll(m, ' ', cputime_to_clock_t(cstime));
	seq_put_decimal_ll(m, ' ', priority);
	seq_put_decimal_ll(m, ' ', nice);
	seq_put_decimal_ll(m, ' ', num_threads);
	seq_put_decimal_ull(m, ' ', 0);
	seq_put_decimal_ull(m, ' ', start_time);
	seq_put_decimal_ull(m, ' ', vsize);
	seq_put_decimal_ull(m, ' ', mm ? get_mm_rss(mm) : 0);
	seq_put_decimal_ull(m, ' ', rsslim);
	seq_put_decimal_ull(m, ' ', mm ? (permitted ? mm->start_code : 1) : 0);
	seq_put_decimal_ull(m, ' ', mm ? (permitted ? mm->end_code : 1) : 0);
	seq_put_decimal_ull(m, ' ', (permitted && mm) ? mm->start_stack : 0);
	seq_put_decimal_ull(m, ' ', esp);
	seq_put_decimal_ull(m, ' ', eip);
	/* The signal information here is obsolete.
	 * It must be decimal for Linux 2.0 compatibility.
	 * Use /proc/#/status for real-time signals.
	 */
	seq_put_decimal_ull(m, ' ', task->pending.signal.sig[0] & 0x7fffffffUL);
	seq_put_decimal_ull(m, ' ', task->blocked.sig[0] & 0x7fffffffUL);
	seq_put_decimal_ull(m, ' ', sigign.sig[0] & 0x7fffffffUL);
	seq_put_decimal_ull(m, ' ', sigcatch.sig[0] & 0x7fffffffUL);
	seq_put_decimal_ull(m, ' ', wchan);
	seq_put_decimal_ull(m, ' ', 0);
	seq_put_decimal_ull(m, ' ', 0);
	seq_put_decimal_ll(m, ' ', task->exit_signal);
	seq_put_decimal_ll(m, ' ', task_cpu(task));
	seq_put_decimal_ull(m, ' ', task->rt_priority);
	seq_put_decimal_ull(m, ' ', task->policy);
	seq_put_decimal_ull(m, ' ', delayacct_blkio_ticks(task));
	seq_put_decimal_ull(m, ' ', cputime_to_clock_t(gtime));
	seq_put_decimal_ll(m, ' ', cputime_to_clock_t(cgtime));

	if (mm && permitted) {
		seq_put_decimal_ull(m, ' ', mm->start_data);
		seq_put_decimal_ull(m, ' ', mm->end_data);
		seq_put_decimal_ull(m, ' ', mm->start_brk);
		seq_put_decimal_ull(m, ' ', mm->arg_start);
		seq_put_decimal_ull(m, ' ', mm->arg_end);
		seq_put_decimal_ull(m, ' ', mm->env_start);
		seq_put_decimal_ull(m, ' ', mm->env_end);
	} else
		seq_printf(m, " 0 0 0 0 0 0 0");

	if (permitted)
		seq_put_decimal_ll(m, ' ', task->exit_code);
	else
		seq_put_decimal_ll(m, ' ', 0);

	seq_putc(m, '\n');
	if (mm)
		mmput(mm);
	return 0;
}

int proc_tid_stat(struct seq_file *m, struct pid_namespace *ns,
			struct pid *pid, struct task_struct *task)
{
	return do_task_stat(m, ns, pid, task, 0);
}

int proc_tgid_stat(struct seq_file *m, struct pid_namespace *ns,
			struct pid *pid, struct task_struct *task)
{
	return do_task_stat(m, ns, pid, task, 1);
}

int proc_pid_statm(struct seq_file *m, struct pid_namespace *ns,
			struct pid *pid, struct task_struct *task)
{
	unsigned long size = 0, resident = 0, shared = 0, text = 0, data = 0;
	struct mm_struct *mm = get_task_mm(task);

	if (mm) {
		size = task_statm(mm, &shared, &text, &data, &resident);
		mmput(mm);
	}
	/*
	 * For quick read, open code by putting numbers directly
	 * expected format is
	 * seq_printf(m, "%lu %lu %lu %lu 0 %lu 0\n",
	 *               size, resident, shared, text, data);
	 */
	seq_put_decimal_ull(m, 0, size);
	seq_put_decimal_ull(m, ' ', resident);
	seq_put_decimal_ull(m, ' ', shared);
	seq_put_decimal_ull(m, ' ', text);
	seq_put_decimal_ull(m, ' ', 0);
	seq_put_decimal_ull(m, ' ', data);
	seq_put_decimal_ull(m, ' ', 0);
	seq_putc(m, '\n');

	return 0;
}

#ifdef CONFIG_CHECKPOINT_RESTORE
static struct pid *
get_children_pid(struct inode *inode, struct pid *pid_prev, loff_t pos)
{
	struct task_struct *start, *task;
	struct pid *pid = NULL;

	read_lock(&tasklist_lock);

	start = pid_task(proc_pid(inode), PIDTYPE_PID);
	if (!start)
		goto out;

	/*
	 * Lets try to continue searching first, this gives
	 * us significant speedup on children-rich processes.
	 */
	if (pid_prev) {
		task = pid_task(pid_prev, PIDTYPE_PID);
		if (task && task->real_parent == start &&
		    !(list_empty(&task->sibling))) {
			if (list_is_last(&task->sibling, &start->children))
				goto out;
			task = list_first_entry(&task->sibling,
						struct task_struct, sibling);
			pid = get_pid(task_pid(task));
			goto out;
		}
	}

	/*
	 * Slow search case.
	 *
	 * We might miss some children here if children
	 * are exited while we were not holding the lock,
	 * but it was never promised to be accurate that
	 * much.
	 *
	 * "Just suppose that the parent sleeps, but N children
	 *  exit after we printed their tids. Now the slow paths
	 *  skips N extra children, we miss N tasks." (c)
	 *
	 * So one need to stop or freeze the leader and all
	 * its children to get a precise result.
	 */
	list_for_each_entry(task, &start->children, sibling) {
		if (pos-- == 0) {
			pid = get_pid(task_pid(task));
			break;
		}
	}

out:
	read_unlock(&tasklist_lock);
	return pid;
}

static int children_seq_show(struct seq_file *seq, void *v)
{
	struct inode *inode = seq->private;
	pid_t pid;

	pid = pid_nr_ns(v, inode->i_sb->s_fs_info);
	return seq_printf(seq, "%d ", pid);
}

static void *children_seq_start(struct seq_file *seq, loff_t *pos)
{
	return get_children_pid(seq->private, NULL, *pos);
}

static void *children_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct pid *pid;

	pid = get_children_pid(seq->private, v, *pos + 1);
	put_pid(v);

	++*pos;
	return pid;
}

static void children_seq_stop(struct seq_file *seq, void *v)
{
	put_pid(v);
}

static const struct seq_operations children_seq_ops = {
	.start	= children_seq_start,
	.next	= children_seq_next,
	.stop	= children_seq_stop,
	.show	= children_seq_show,
};

static int children_seq_open(struct inode *inode, struct file *file)
{
	struct seq_file *m;
	int ret;

	ret = seq_open(file, &children_seq_ops);
	if (ret)
		return ret;

	m = file->private_data;
	m->private = inode;

	return ret;
}

int children_seq_release(struct inode *inode, struct file *file)
{
	seq_release(inode, file);
	return 0;
}

const struct file_operations proc_tid_children_operations = {
	.open    = children_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = children_seq_release,
};
#endif /* CONFIG_CHECKPOINT_RESTORE */
/************************************************************/
/* ../linux-3.17/fs/proc/array.c */
/************************************************************/
// #include <linux/sched.h>
// #include <linux/errno.h>
#include <linux/dcache.h>
#include <linux/path.h>
// #include <linux/fdtable.h>
// #include <linux/namei.h>
#include <linux/pid.h>
// #include <linux/security.h>
// #include <linux/file.h>
// #include <linux/seq_file.h>

// #include <linux/proc_fs.h>

#include "../mount.h"
// #include "internal.h"
// #include "fd.h"

static int seq_show(struct seq_file *m, void *v)
{
	struct files_struct *files = NULL;
	int f_flags = 0, ret = -ENOENT;
	struct file *file = NULL;
	struct task_struct *task;

	task = get_proc_task(m->private);
	if (!task)
		return -ENOENT;

	files = get_files_struct(task);
	put_task_struct(task);

	if (files) {
		int fd = proc_fd(m->private);

		spin_lock(&files->file_lock);
		file = fcheck_files(files, fd);
		if (file) {
			struct fdtable *fdt = files_fdtable(files);

			f_flags = file->f_flags;
			if (close_on_exec(fd, fdt))
				f_flags |= O_CLOEXEC;

			get_file(file);
			ret = 0;
		}
		spin_unlock(&files->file_lock);
		put_files_struct(files);
	}

	if (!ret) {
		seq_printf(m, "pos:\t%lli\nflags:\t0%o\nmnt_id:\t%i\n",
			   (long long)file->f_pos, f_flags,
			   real_mount(file->f_path.mnt)->mnt_id);
		if (file->f_op->show_fdinfo)
			ret = file->f_op->show_fdinfo(m, file);
		fput(file);
	}

	return ret;
}

static int seq_fdinfo_open(struct inode *inode, struct file *file)
{
	return single_open(file, seq_show, inode);
}

static const struct file_operations proc_fdinfo_file_operations = {
	.open		= seq_fdinfo_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int tid_fd_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct files_struct *files;
	struct task_struct *task;
	const struct cred *cred;
	struct inode *inode;
	int fd;

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	inode = dentry->d_inode;
	task = get_proc_task(inode);
	fd = proc_fd(inode);

	if (task) {
		files = get_files_struct(task);
		if (files) {
			struct file *file;

			rcu_read_lock();
			file = fcheck_files(files, fd);
			if (file) {
				unsigned f_mode = file->f_mode;

				rcu_read_unlock();
				put_files_struct(files);

				if (task_dumpable(task)) {
					rcu_read_lock();
					cred = __task_cred(task);
					inode->i_uid = cred->euid;
					inode->i_gid = cred->egid;
					rcu_read_unlock();
				} else {
					inode->i_uid = GLOBAL_ROOT_UID;
					inode->i_gid = GLOBAL_ROOT_GID;
				}

				if (S_ISLNK(inode->i_mode)) {
					unsigned i_mode = S_IFLNK;
					if (f_mode & FMODE_READ)
						i_mode |= S_IRUSR | S_IXUSR;
					if (f_mode & FMODE_WRITE)
						i_mode |= S_IWUSR | S_IXUSR;
					inode->i_mode = i_mode;
				}

				security_task_to_inode(task, inode);
				put_task_struct(task);
				return 1;
			}
			rcu_read_unlock();
			put_files_struct(files);
		}
		put_task_struct(task);
	}

	d_drop(dentry);
	return 0;
}

static const struct dentry_operations tid_fd_dentry_operations = {
	.d_revalidate	= tid_fd_revalidate,
	.d_delete	= pid_delete_dentry,
};

static int proc_fd_link(struct dentry *dentry, struct path *path)
{
	struct files_struct *files = NULL;
	struct task_struct *task;
	int ret = -ENOENT;

	task = get_proc_task(dentry->d_inode);
	if (task) {
		files = get_files_struct(task);
		put_task_struct(task);
	}

	if (files) {
		int fd = proc_fd(dentry->d_inode);
		struct file *fd_file;

		spin_lock(&files->file_lock);
		fd_file = fcheck_files(files, fd);
		if (fd_file) {
			*path = fd_file->f_path;
			path_get(&fd_file->f_path);
			ret = 0;
		}
		spin_unlock(&files->file_lock);
		put_files_struct(files);
	}

	return ret;
}

static int
proc_fd_instantiate(struct inode *dir, struct dentry *dentry,
		    struct task_struct *task, const void *ptr)
{
	unsigned fd = (unsigned long)ptr;
	struct proc_inode *ei;
	struct inode *inode;

	inode = proc_pid_make_inode(dir->i_sb, task);
	if (!inode)
		goto out;

	ei = PROC_I(inode);
	ei->fd = fd;

	inode->i_mode = S_IFLNK;
	inode->i_op = &proc_pid_link_inode_operations;
	inode->i_size = 64;

	ei->op.proc_get_link = proc_fd_link;

	d_set_d_op(dentry, &tid_fd_dentry_operations);
	d_add(dentry, inode);

	/* Close the race of the process dying before we return the dentry */
	if (tid_fd_revalidate(dentry, 0))
		return 0;
 out:
	return -ENOENT;
}

static struct dentry *proc_lookupfd_common(struct inode *dir,
					   struct dentry *dentry,
					   instantiate_t instantiate)
{
	struct task_struct *task = get_proc_task(dir);
	int result = -ENOENT;
	unsigned fd = name_to_int(&dentry->d_name);

	if (!task)
		goto out_no_task;
	if (fd == ~0U)
		goto out;

	result = instantiate(dir, dentry, task, (void *)(unsigned long)fd);
out:
	put_task_struct(task);
out_no_task:
	return ERR_PTR(result);
}

static int proc_readfd_common(struct file *file, struct dir_context *ctx,
			      instantiate_t instantiate)
{
	struct task_struct *p = get_proc_task(file_inode(file));
	struct files_struct *files;
	unsigned int fd;

	if (!p)
		return -ENOENT;

	if (!dir_emit_dots(file, ctx))
		goto out;
	files = get_files_struct(p);
	if (!files)
		goto out;

	rcu_read_lock();
	for (fd = ctx->pos - 2;
	     fd < files_fdtable(files)->max_fds;
	     fd++, ctx->pos++) {
		char name[PROC_NUMBUF];
		int len;

		if (!fcheck_files(files, fd))
			continue;
		rcu_read_unlock();

		len = snprintf(name, sizeof(name), "%d", fd);
		if (!proc_fill_cache(file, ctx,
				     name, len, instantiate, p,
				     (void *)(unsigned long)fd))
			goto out_fd_loop;
		rcu_read_lock();
	}
	rcu_read_unlock();
out_fd_loop:
	put_files_struct(files);
out:
	put_task_struct(p);
	return 0;
}

static int proc_readfd(struct file *file, struct dir_context *ctx)
{
	return proc_readfd_common(file, ctx, proc_fd_instantiate);
}

const struct file_operations proc_fd_operations = {
	.read		= generic_read_dir,
	.iterate	= proc_readfd,
	.llseek		= default_llseek,
};

static struct dentry *proc_lookupfd(struct inode *dir, struct dentry *dentry,
				    unsigned int flags)
{
	return proc_lookupfd_common(dir, dentry, proc_fd_instantiate);
}

/*
 * /proc/pid/fd needs a special permission handler so that a process can still
 * access /proc/self/fd after it has executed a setuid().
 */
int proc_fd_permission(struct inode *inode, int mask)
{
	int rv = generic_permission(inode, mask);
	if (rv == 0)
		return 0;
	if (task_tgid(current) == proc_pid(inode))
		rv = 0;
	return rv;
}

const struct inode_operations proc_fd_inode_operations = {
	.lookup		= proc_lookupfd,
	.permission	= proc_fd_permission,
	.setattr	= proc_setattr,
};

static int
proc_fdinfo_instantiate(struct inode *dir, struct dentry *dentry,
			struct task_struct *task, const void *ptr)
{
	unsigned fd = (unsigned long)ptr;
	struct proc_inode *ei;
	struct inode *inode;

	inode = proc_pid_make_inode(dir->i_sb, task);
	if (!inode)
		goto out;

	ei = PROC_I(inode);
	ei->fd = fd;

	inode->i_mode = S_IFREG | S_IRUSR;
	inode->i_fop = &proc_fdinfo_file_operations;

	d_set_d_op(dentry, &tid_fd_dentry_operations);
	d_add(dentry, inode);

	/* Close the race of the process dying before we return the dentry */
	if (tid_fd_revalidate(dentry, 0))
		return 0;
 out:
	return -ENOENT;
}

static struct dentry *
proc_lookupfdinfo(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	return proc_lookupfd_common(dir, dentry, proc_fdinfo_instantiate);
}

static int proc_readfdinfo(struct file *file, struct dir_context *ctx)
{
	return proc_readfd_common(file, ctx,
				  proc_fdinfo_instantiate);
}

const struct inode_operations proc_fdinfo_inode_operations = {
	.lookup		= proc_lookupfdinfo,
	.setattr	= proc_setattr,
};

const struct file_operations proc_fdinfo_operations = {
	.read		= generic_read_dir,
	.iterate	= proc_readfdinfo,
	.llseek		= default_llseek,
};
/************************************************************/
/* ../linux-3.17/fs/proc/fd.c */
/************************************************************/
/*
 * proc_tty.c -- handles /proc/tty
 *
 * Copyright 1997, Theodore Ts'o
 */

// #include <asm/uaccess.h>
// #include <linux/module.h>
// #include <linux/init.h>
// #include <linux/errno.h>
// #include <linux/time.h>
// #include <linux/proc_fs.h>
// #include <linux/stat.h>
// #include <linux/tty.h>
// #include <linux/seq_file.h>
// #include <linux/bitops.h>

/*
 * The /proc/tty directory inodes...
 */
static struct proc_dir_entry *proc_tty_driver;

/*
 * This is the handler for /proc/tty/drivers
 */
static void show_tty_range(struct seq_file *m, struct tty_driver *p,
	dev_t from, int num)
{
	seq_printf(m, "%-20s ", p->driver_name ? p->driver_name : "unknown");
	seq_printf(m, "/dev/%-8s ", p->name);
	if (p->num > 1) {
		seq_printf(m, "%3d %d-%d ", MAJOR(from), MINOR(from),
			MINOR(from) + num - 1);
	} else {
		seq_printf(m, "%3d %7d ", MAJOR(from), MINOR(from));
	}
	switch (p->type) {
	case TTY_DRIVER_TYPE_SYSTEM:
		seq_puts(m, "system");
		if (p->subtype == SYSTEM_TYPE_TTY)
			seq_puts(m, ":/dev/tty");
		else if (p->subtype == SYSTEM_TYPE_SYSCONS)
			seq_puts(m, ":console");
		else if (p->subtype == SYSTEM_TYPE_CONSOLE)
			seq_puts(m, ":vtmaster");
		break;
	case TTY_DRIVER_TYPE_CONSOLE:
		seq_puts(m, "console");
		break;
	case TTY_DRIVER_TYPE_SERIAL:
		seq_puts(m, "serial");
		break;
	case TTY_DRIVER_TYPE_PTY:
		if (p->subtype == PTY_TYPE_MASTER)
			seq_puts(m, "pty:master");
		else if (p->subtype == PTY_TYPE_SLAVE)
			seq_puts(m, "pty:slave");
		else
			seq_puts(m, "pty");
		break;
	default:
		seq_printf(m, "type:%d.%d", p->type, p->subtype);
	}
	seq_putc(m, '\n');
}

static int show_tty_driver(struct seq_file *m, void *v)
{
	struct tty_driver *p = list_entry(v, struct tty_driver, tty_drivers);
	dev_t from = MKDEV(p->major, p->minor_start);
	dev_t to = from + p->num;

	if (&p->tty_drivers == tty_drivers.next) {
		/* pseudo-drivers first */
		seq_printf(m, "%-20s /dev/%-8s ", "/dev/tty", "tty");
		seq_printf(m, "%3d %7d ", TTYAUX_MAJOR, 0);
		seq_puts(m, "system:/dev/tty\n");
		seq_printf(m, "%-20s /dev/%-8s ", "/dev/console", "console");
		seq_printf(m, "%3d %7d ", TTYAUX_MAJOR, 1);
		seq_puts(m, "system:console\n");
#ifdef CONFIG_UNIX98_PTYS
		seq_printf(m, "%-20s /dev/%-8s ", "/dev/ptmx", "ptmx");
		seq_printf(m, "%3d %7d ", TTYAUX_MAJOR, 2);
		seq_puts(m, "system\n");
#endif
#ifdef CONFIG_VT
		seq_printf(m, "%-20s /dev/%-8s ", "/dev/vc/0", "vc/0");
		seq_printf(m, "%3d %7d ", TTY_MAJOR, 0);
		seq_puts(m, "system:vtmaster\n");
#endif
	}

	while (MAJOR(from) < MAJOR(to)) {
		dev_t next = MKDEV(MAJOR(from)+1, 0);
		show_tty_range(m, p, from, next - from);
		from = next;
	}
	if (from != to)
		show_tty_range(m, p, from, to - from);
	return 0;
}

/* iterator */
static void *t_start(struct seq_file *m, loff_t *pos)
{
	mutex_lock(&tty_mutex);
	return seq_list_start(&tty_drivers, *pos);
}

static void *t_next(struct seq_file *m, void *v, loff_t *pos)
{
	return seq_list_next(v, &tty_drivers, pos);
}

static void t_stop(struct seq_file *m, void *v)
{
	mutex_unlock(&tty_mutex);
}

static const struct seq_operations tty_drivers_op = {
	.start	= t_start,
	.next	= t_next,
	.stop	= t_stop,
	.show	= show_tty_driver
};

static int tty_drivers_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &tty_drivers_op);
}

static const struct file_operations proc_tty_drivers_operations = {
	.open		= tty_drivers_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

/*
 * This function is called by tty_register_driver() to handle
 * registering the driver's /proc handler into /proc/tty/driver/<foo>
 */
void proc_tty_register_driver(struct tty_driver *driver)
{
	struct proc_dir_entry *ent;

	if (!driver->driver_name || driver->proc_entry ||
	    !driver->ops->proc_fops)
		return;

	ent = proc_create_data(driver->driver_name, 0, proc_tty_driver,
			       driver->ops->proc_fops, driver);
	driver->proc_entry = ent;
}

/*
 * This function is called by tty_unregister_driver()
 */
void proc_tty_unregister_driver(struct tty_driver *driver)
{
	struct proc_dir_entry *ent;

	ent = driver->proc_entry;
	if (!ent)
		return;

	remove_proc_entry(driver->driver_name, proc_tty_driver);

	driver->proc_entry = NULL;
}

/*
 * Called by proc_root_init() to initialize the /proc/tty subtree
 */
void __init proc_tty_init(void)
{
	if (!proc_mkdir("tty", NULL))
		return;
	proc_mkdir("tty/ldisc", NULL);	/* Preserved: it's userspace visible */
	/*
	 * /proc/tty/driver/serial reveals the exact character counts for
	 * serial links which is just too easy to abuse for inferring
	 * password lengths and inter-keystroke timings during password
	 * entry.
	 */
	proc_tty_driver = proc_mkdir_mode("tty/driver", S_IRUSR|S_IXUSR, NULL);
	proc_create("tty/ldiscs", 0, NULL, &tty_ldiscs_proc_fops);
	proc_create("tty/drivers", 0, NULL, &proc_tty_drivers_operations);
}
/************************************************************/
/* ../linux-3.17/fs/proc/proc_tty.c */
/************************************************************/
#include <linux/fs.h>
// #include <linux/init.h>
// #include <linux/proc_fs.h>
// #include <linux/seq_file.h>

static int cmdline_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s\n", saved_command_line);
	return 0;
}

static int cmdline_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, cmdline_proc_show, NULL);
}

static const struct file_operations cmdline_proc_fops = {
	.open		= cmdline_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_cmdline_init(void)
{
	proc_create("cmdline", 0, NULL, &cmdline_proc_fops);
	return 0;
}
fs_initcall(proc_cmdline_init);
/************************************************************/
/* ../linux-3.17/fs/proc/cmdline.c */
/************************************************************/
/*
 * Copyright (c) 2010 Werner Fink, Jiri Slaby
 *
 * Licensed under GPLv2
 */

#include <linux/console.h>
// #include <linux/kernel.h>
// #include <linux/proc_fs.h>
// #include <linux/seq_file.h>
#include <linux/tty_driver.h>

/*
 * This is handler for /proc/consoles
 */
static int show_console_dev(struct seq_file *m, void *v)
{
	static const struct {
		short flag;
		char name;
	} con_flags[] = {
		{ CON_ENABLED,		'E' },
		{ CON_CONSDEV,		'C' },
		{ CON_BOOT,		'B' },
		{ CON_PRINTBUFFER,	'p' },
		{ CON_BRL,		'b' },
		{ CON_ANYTIME,		'a' },
	};
	char flags[ARRAY_SIZE(con_flags) + 1];
	struct console *con = v;
	unsigned int a;
	dev_t dev = 0;

	if (con->device) {
		const struct tty_driver *driver;
		int index;
		driver = con->device(con, &index);
		if (driver) {
			dev = MKDEV(driver->major, driver->minor_start);
			dev += index;
		}
	}

	for (a = 0; a < ARRAY_SIZE(con_flags); a++)
		flags[a] = (con->flags & con_flags[a].flag) ?
			con_flags[a].name : ' ';
	flags[a] = 0;

	seq_setwidth(m, 21 - 1);
	seq_printf(m, "%s%d", con->name, con->index);
	seq_pad(m, ' ');
	seq_printf(m, "%c%c%c (%s)", con->read ? 'R' : '-',
			con->write ? 'W' : '-', con->unblank ? 'U' : '-',
			flags);
	if (dev)
		seq_printf(m, " %4d:%d", MAJOR(dev), MINOR(dev));

	seq_printf(m, "\n");

	return 0;
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
	struct console *con;
	loff_t off = 0;

	console_lock();
	for_each_console(con)
		if (off++ == *pos)
			break;

	return con;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct console *con = v;
	++*pos;
	return con->next;
}

static void c_stop(struct seq_file *m, void *v)
{
	console_unlock();
}

static const struct seq_operations consoles_op = {
	.start	= c_start,
	.next	= c_next,
	.stop	= c_stop,
	.show	= show_console_dev
};

static int consoles_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &consoles_op);
}

static const struct file_operations proc_consoles_operations = {
	.open		= consoles_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int __init proc_consoles_init(void)
{
	proc_create("consoles", 0, NULL, &proc_consoles_operations);
	return 0;
}
fs_initcall(proc_consoles_init);
/************************************************************/
/* ../linux-3.17/fs/proc/consoles.c */
/************************************************************/
// #include <linux/fs.h>
// #include <linux/init.h>
// #include <linux/proc_fs.h>
// #include <linux/seq_file.h>

extern const struct seq_operations cpuinfo_op;
static int cpuinfo_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &cpuinfo_op);
}

static const struct file_operations proc_cpuinfo_operations = {
	.open		= cpuinfo_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int __init proc_cpuinfo_init(void)
{
	proc_create("cpuinfo", 0, NULL, &proc_cpuinfo_operations);
	return 0;
}
fs_initcall(proc_cpuinfo_init);
/************************************************************/
/* ../linux-3.17/fs/proc/cpuinfo.c */
/************************************************************/
// #include <linux/fs.h>
// #include <linux/init.h>
// #include <linux/proc_fs.h>
// #include <linux/seq_file.h>

static int devinfo_show(struct seq_file *f, void *v)
{
	int i = *(loff_t *) v;

	if (i < CHRDEV_MAJOR_HASH_SIZE) {
		if (i == 0)
			seq_puts(f, "Character devices:\n");
		chrdev_show(f, i);
	}
#ifdef CONFIG_BLOCK
	else {
		i -= CHRDEV_MAJOR_HASH_SIZE;
		if (i == 0)
			seq_puts(f, "\nBlock devices:\n");
		blkdev_show(f, i);
	}
#endif
	return 0;
}

static void *devinfo_start(struct seq_file *f, loff_t *pos)
{
	if (*pos < (BLKDEV_MAJOR_HASH_SIZE + CHRDEV_MAJOR_HASH_SIZE))
		return pos;
	return NULL;
}

static void *devinfo_next(struct seq_file *f, void *v, loff_t *pos)
{
	(*pos)++;
	if (*pos >= (BLKDEV_MAJOR_HASH_SIZE + CHRDEV_MAJOR_HASH_SIZE))
		return NULL;
	return pos;
}

static void devinfo_stop(struct seq_file *f, void *v)
{
	/* Nothing to do */
}

static const struct seq_operations devinfo_ops = {
	.start = devinfo_start,
	.next  = devinfo_next,
	.stop  = devinfo_stop,
	.show  = devinfo_show
};

static int devinfo_open(struct inode *inode, struct file *filp)
{
	return seq_open(filp, &devinfo_ops);
}

static const struct file_operations proc_devinfo_operations = {
	.open		= devinfo_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int __init proc_devices_init(void)
{
	proc_create("devices", 0, NULL, &proc_devinfo_operations);
	return 0;
}
fs_initcall(proc_devices_init);
/************************************************************/
/* ../linux-3.17/fs/proc/devices.c */
/************************************************************/
// #include <linux/fs.h>
// #include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/irqnr.h>
// #include <linux/proc_fs.h>
// #include <linux/seq_file.h>

/*
 * /proc/interrupts
 */
static void *int_seq_start(struct seq_file *f, loff_t *pos)
{
	return (*pos <= nr_irqs) ? pos : NULL;
}

static void *int_seq_next(struct seq_file *f, void *v, loff_t *pos)
{
	(*pos)++;
	if (*pos > nr_irqs)
		return NULL;
	return pos;
}

static void int_seq_stop(struct seq_file *f, void *v)
{
	/* Nothing to do */
}

static const struct seq_operations int_seq_ops = {
	.start = int_seq_start,
	.next  = int_seq_next,
	.stop  = int_seq_stop,
	.show  = show_interrupts
};

static int interrupts_open(struct inode *inode, struct file *filp)
{
	return seq_open(filp, &int_seq_ops);
}

static const struct file_operations proc_interrupts_operations = {
	.open		= interrupts_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int __init proc_interrupts_init(void)
{
	proc_create("interrupts", 0, NULL, &proc_interrupts_operations);
	return 0;
}
fs_initcall(proc_interrupts_init);
/************************************************************/
/* ../linux-3.17/fs/proc/interrupts.c */
/************************************************************/
// #include <linux/fs.h>
// #include <linux/init.h>
// #include <linux/pid_namespace.h>
// #include <linux/proc_fs.h>
// #include <linux/sched.h>
// #include <linux/seq_file.h>
#include <linux/seqlock.h>
// #include <linux/time.h>

#define LOAD_INT(x) ((x) >> FSHIFT)
#define LOAD_FRAC(x) LOAD_INT(((x) & (FIXED_1-1)) * 100)

static int loadavg_proc_show(struct seq_file *m, void *v)
{
	unsigned long avnrun[3];

	get_avenrun(avnrun, FIXED_1/200, 0);

	seq_printf(m, "%lu.%02lu %lu.%02lu %lu.%02lu %ld/%d %d\n",
		LOAD_INT(avnrun[0]), LOAD_FRAC(avnrun[0]),
		LOAD_INT(avnrun[1]), LOAD_FRAC(avnrun[1]),
		LOAD_INT(avnrun[2]), LOAD_FRAC(avnrun[2]),
		nr_running(), nr_threads,
		task_active_pid_ns(current)->last_pid);
	return 0;
}

static int loadavg_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, loadavg_proc_show, NULL);
}

static const struct file_operations loadavg_proc_fops = {
	.open		= loadavg_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_loadavg_init(void)
{
	proc_create("loadavg", 0, NULL, &loadavg_proc_fops);
	return 0;
}
fs_initcall(proc_loadavg_init);
/************************************************************/
/* ../linux-3.17/fs/proc/loadavg.c */
/************************************************************/
// #include <linux/fs.h>
// #include <linux/init.h>
// #include <linux/kernel.h>
// #include <linux/mm.h>
// #include <linux/hugetlb.h>
// #include <linux/mman.h>
// #include <linux/mmzone.h>
// #include <linux/proc_fs.h>
#include <linux/quicklist.h>
// #include <linux/seq_file.h>
// #include <linux/swap.h>
#include <linux/vmstat.h>
#include <linux/atomic.h>
// #include <linux/vmalloc.h>
#include <asm/page.h>
// #include <asm/pgtable.h>
// #include "internal.h"

void __attribute__((weak)) arch_report_meminfo(struct seq_file *m)
{
}

static int meminfo_proc_show(struct seq_file *m, void *v)
{
	struct sysinfo i;
	unsigned long committed;
	struct vmalloc_info vmi;
	long cached;
	long available;
	unsigned long pagecache;
	unsigned long wmark_low = 0;
	unsigned long pages[NR_LRU_LISTS];
	struct zone *zone;
	int lru;

/*
 * display in kilobytes.
 */
#define K(x) ((x) << (PAGE_SHIFT - 10))
	si_meminfo(&i);
	si_swapinfo(&i);
	committed = percpu_counter_read_positive(&vm_committed_as);

	cached = global_page_state(NR_FILE_PAGES) -
			total_swapcache_pages() - i.bufferram;
	if (cached < 0)
		cached = 0;

	get_vmalloc_info(&vmi);

	for (lru = LRU_BASE; lru < NR_LRU_LISTS; lru++)
		pages[lru] = global_page_state(NR_LRU_BASE + lru);

	for_each_zone(zone)
		wmark_low += zone->watermark[WMARK_LOW];

	/*
	 * Estimate the amount of memory available for userspace allocations,
	 * without causing swapping.
	 *
	 * Free memory cannot be taken below the low watermark, before the
	 * system starts swapping.
	 */
	available = i.freeram - wmark_low;

	/*
	 * Not all the page cache can be freed, otherwise the system will
	 * start swapping. Assume at least half of the page cache, or the
	 * low watermark worth of cache, needs to stay.
	 */
	pagecache = pages[LRU_ACTIVE_FILE] + pages[LRU_INACTIVE_FILE];
	pagecache -= min(pagecache / 2, wmark_low);
	available += pagecache;

	/*
	 * Part of the reclaimable slab consists of items that are in use,
	 * and cannot be freed. Cap this estimate at the low watermark.
	 */
	available += global_page_state(NR_SLAB_RECLAIMABLE) -
		     min(global_page_state(NR_SLAB_RECLAIMABLE) / 2, wmark_low);

	if (available < 0)
		available = 0;

	/*
	 * Tagged format, for easy grepping and expansion.
	 */
	seq_printf(m,
		"MemTotal:       %8lu kB\n"
		"MemFree:        %8lu kB\n"
		"MemAvailable:   %8lu kB\n"
		"Buffers:        %8lu kB\n"
		"Cached:         %8lu kB\n"
		"SwapCached:     %8lu kB\n"
		"Active:         %8lu kB\n"
		"Inactive:       %8lu kB\n"
		"Active(anon):   %8lu kB\n"
		"Inactive(anon): %8lu kB\n"
		"Active(file):   %8lu kB\n"
		"Inactive(file): %8lu kB\n"
		"Unevictable:    %8lu kB\n"
		"Mlocked:        %8lu kB\n"
#ifdef CONFIG_HIGHMEM
		"HighTotal:      %8lu kB\n"
		"HighFree:       %8lu kB\n"
		"LowTotal:       %8lu kB\n"
		"LowFree:        %8lu kB\n"
#endif
#ifndef CONFIG_MMU
		"MmapCopy:       %8lu kB\n"
#endif
		"SwapTotal:      %8lu kB\n"
		"SwapFree:       %8lu kB\n"
		"Dirty:          %8lu kB\n"
		"Writeback:      %8lu kB\n"
		"AnonPages:      %8lu kB\n"
		"Mapped:         %8lu kB\n"
		"Shmem:          %8lu kB\n"
		"Slab:           %8lu kB\n"
		"SReclaimable:   %8lu kB\n"
		"SUnreclaim:     %8lu kB\n"
		"KernelStack:    %8lu kB\n"
		"PageTables:     %8lu kB\n"
#ifdef CONFIG_QUICKLIST
		"Quicklists:     %8lu kB\n"
#endif
		"NFS_Unstable:   %8lu kB\n"
		"Bounce:         %8lu kB\n"
		"WritebackTmp:   %8lu kB\n"
		"CommitLimit:    %8lu kB\n"
		"Committed_AS:   %8lu kB\n"
		"VmallocTotal:   %8lu kB\n"
		"VmallocUsed:    %8lu kB\n"
		"VmallocChunk:   %8lu kB\n"
#ifdef CONFIG_MEMORY_FAILURE
		"HardwareCorrupted: %5lu kB\n"
#endif
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
		"AnonHugePages:  %8lu kB\n"
#endif
		,
		K(i.totalram),
		K(i.freeram),
		K(available),
		K(i.bufferram),
		K(cached),
		K(total_swapcache_pages()),
		K(pages[LRU_ACTIVE_ANON]   + pages[LRU_ACTIVE_FILE]),
		K(pages[LRU_INACTIVE_ANON] + pages[LRU_INACTIVE_FILE]),
		K(pages[LRU_ACTIVE_ANON]),
		K(pages[LRU_INACTIVE_ANON]),
		K(pages[LRU_ACTIVE_FILE]),
		K(pages[LRU_INACTIVE_FILE]),
		K(pages[LRU_UNEVICTABLE]),
		K(global_page_state(NR_MLOCK)),
#ifdef CONFIG_HIGHMEM
		K(i.totalhigh),
		K(i.freehigh),
		K(i.totalram-i.totalhigh),
		K(i.freeram-i.freehigh),
#endif
#ifndef CONFIG_MMU
		K((unsigned long) atomic_long_read(&mmap_pages_allocated)),
#endif
		K(i.totalswap),
		K(i.freeswap),
		K(global_page_state(NR_FILE_DIRTY)),
		K(global_page_state(NR_WRITEBACK)),
		K(global_page_state(NR_ANON_PAGES)),
		K(global_page_state(NR_FILE_MAPPED)),
		K(i.sharedram),
		K(global_page_state(NR_SLAB_RECLAIMABLE) +
				global_page_state(NR_SLAB_UNRECLAIMABLE)),
		K(global_page_state(NR_SLAB_RECLAIMABLE)),
		K(global_page_state(NR_SLAB_UNRECLAIMABLE)),
		global_page_state(NR_KERNEL_STACK) * THREAD_SIZE / 1024,
		K(global_page_state(NR_PAGETABLE)),
#ifdef CONFIG_QUICKLIST
		K(quicklist_total_size()),
#endif
		K(global_page_state(NR_UNSTABLE_NFS)),
		K(global_page_state(NR_BOUNCE)),
		K(global_page_state(NR_WRITEBACK_TEMP)),
		K(vm_commit_limit()),
		K(committed),
		(unsigned long)VMALLOC_TOTAL >> 10,
		vmi.used >> 10,
		vmi.largest_chunk >> 10
#ifdef CONFIG_MEMORY_FAILURE
		,atomic_long_read(&num_poisoned_pages) << (PAGE_SHIFT - 10)
#endif
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
		,K(global_page_state(NR_ANON_TRANSPARENT_HUGEPAGES) *
		   HPAGE_PMD_NR)
#endif
		);

	hugetlb_report_meminfo(m);

	arch_report_meminfo(m);

	return 0;
#undef K
}

static int meminfo_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, meminfo_proc_show, NULL);
}

static const struct file_operations meminfo_proc_fops = {
	.open		= meminfo_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_meminfo_init(void)
{
	proc_create("meminfo", 0, NULL, &meminfo_proc_fops);
	return 0;
}
fs_initcall(proc_meminfo_init);
/************************************************************/
/* ../linux-3.17/fs/proc/meminfo.c */
/************************************************************/
#include <linux/cpumask.h>
// #include <linux/fs.h>
// #include <linux/init.h>
// #include <linux/interrupt.h>
// #include <linux/kernel_stat.h>
// #include <linux/proc_fs.h>
// #include <linux/sched.h>
// #include <linux/seq_file.h>
// #include <linux/slab.h>
// #include <linux/time.h>
// #include <linux/irqnr.h>
#include <linux/cputime.h>
#include <linux/tick.h>

#ifndef arch_irq_stat_cpu
#define arch_irq_stat_cpu(cpu) 0
#endif
#ifndef arch_irq_stat
#define arch_irq_stat() 0
#endif

#ifdef arch_idle_time

static cputime64_t get_idle_time(int cpu)
{
	cputime64_t idle;

	idle = kcpustat_cpu(cpu).cpustat[CPUTIME_IDLE];
	if (cpu_online(cpu) && !nr_iowait_cpu(cpu))
		idle += arch_idle_time(cpu);
	return idle;
}

static cputime64_t get_iowait_time(int cpu)
{
	cputime64_t iowait;

	iowait = kcpustat_cpu(cpu).cpustat[CPUTIME_IOWAIT];
	if (cpu_online(cpu) && nr_iowait_cpu(cpu))
		iowait += arch_idle_time(cpu);
	return iowait;
}

#else

static u64 get_idle_time(int cpu)
{
	u64 idle, idle_time = -1ULL;

	if (cpu_online(cpu))
		idle_time = get_cpu_idle_time_us(cpu, NULL);

	if (idle_time == -1ULL)
		/* !NO_HZ or cpu offline so we can rely on cpustat.idle */
		idle = kcpustat_cpu(cpu).cpustat[CPUTIME_IDLE];
	else
		idle = usecs_to_cputime64(idle_time);

	return idle;
}

static u64 get_iowait_time(int cpu)
{
	u64 iowait, iowait_time = -1ULL;

	if (cpu_online(cpu))
		iowait_time = get_cpu_iowait_time_us(cpu, NULL);

	if (iowait_time == -1ULL)
		/* !NO_HZ or cpu offline so we can rely on cpustat.iowait */
		iowait = kcpustat_cpu(cpu).cpustat[CPUTIME_IOWAIT];
	else
		iowait = usecs_to_cputime64(iowait_time);

	return iowait;
}

#endif

static int show_stat(struct seq_file *p, void *v)
{
	int i, j;
	unsigned long jif;
	u64 user, nice, system, idle, iowait, irq, softirq, steal;
	u64 guest, guest_nice;
	u64 sum = 0;
	u64 sum_softirq = 0;
	unsigned int per_softirq_sums[NR_SOFTIRQS] = {0};
	struct timespec boottime;

	user = nice = system = idle = iowait =
		irq = softirq = steal = 0;
	guest = guest_nice = 0;
	getboottime(&boottime);
	jif = boottime.tv_sec;

	for_each_possible_cpu(i) {
		user += kcpustat_cpu(i).cpustat[CPUTIME_USER];
		nice += kcpustat_cpu(i).cpustat[CPUTIME_NICE];
		system += kcpustat_cpu(i).cpustat[CPUTIME_SYSTEM];
		idle += get_idle_time(i);
		iowait += get_iowait_time(i);
		irq += kcpustat_cpu(i).cpustat[CPUTIME_IRQ];
		softirq += kcpustat_cpu(i).cpustat[CPUTIME_SOFTIRQ];
		steal += kcpustat_cpu(i).cpustat[CPUTIME_STEAL];
		guest += kcpustat_cpu(i).cpustat[CPUTIME_GUEST];
		guest_nice += kcpustat_cpu(i).cpustat[CPUTIME_GUEST_NICE];
		sum += kstat_cpu_irqs_sum(i);
		sum += arch_irq_stat_cpu(i);

		for (j = 0; j < NR_SOFTIRQS; j++) {
			unsigned int softirq_stat = kstat_softirqs_cpu(j, i);

			per_softirq_sums[j] += softirq_stat;
			sum_softirq += softirq_stat;
		}
	}
	sum += arch_irq_stat();

	seq_puts(p, "cpu ");
	seq_put_decimal_ull(p, ' ', cputime64_to_clock_t(user));
	seq_put_decimal_ull(p, ' ', cputime64_to_clock_t(nice));
	seq_put_decimal_ull(p, ' ', cputime64_to_clock_t(system));
	seq_put_decimal_ull(p, ' ', cputime64_to_clock_t(idle));
	seq_put_decimal_ull(p, ' ', cputime64_to_clock_t(iowait));
	seq_put_decimal_ull(p, ' ', cputime64_to_clock_t(irq));
	seq_put_decimal_ull(p, ' ', cputime64_to_clock_t(softirq));
	seq_put_decimal_ull(p, ' ', cputime64_to_clock_t(steal));
	seq_put_decimal_ull(p, ' ', cputime64_to_clock_t(guest));
	seq_put_decimal_ull(p, ' ', cputime64_to_clock_t(guest_nice));
	seq_putc(p, '\n');

	for_each_online_cpu(i) {
		/* Copy values here to work around gcc-2.95.3, gcc-2.96 */
		user = kcpustat_cpu(i).cpustat[CPUTIME_USER];
		nice = kcpustat_cpu(i).cpustat[CPUTIME_NICE];
		system = kcpustat_cpu(i).cpustat[CPUTIME_SYSTEM];
		idle = get_idle_time(i);
		iowait = get_iowait_time(i);
		irq = kcpustat_cpu(i).cpustat[CPUTIME_IRQ];
		softirq = kcpustat_cpu(i).cpustat[CPUTIME_SOFTIRQ];
		steal = kcpustat_cpu(i).cpustat[CPUTIME_STEAL];
		guest = kcpustat_cpu(i).cpustat[CPUTIME_GUEST];
		guest_nice = kcpustat_cpu(i).cpustat[CPUTIME_GUEST_NICE];
		seq_printf(p, "cpu%d", i);
		seq_put_decimal_ull(p, ' ', cputime64_to_clock_t(user));
		seq_put_decimal_ull(p, ' ', cputime64_to_clock_t(nice));
		seq_put_decimal_ull(p, ' ', cputime64_to_clock_t(system));
		seq_put_decimal_ull(p, ' ', cputime64_to_clock_t(idle));
		seq_put_decimal_ull(p, ' ', cputime64_to_clock_t(iowait));
		seq_put_decimal_ull(p, ' ', cputime64_to_clock_t(irq));
		seq_put_decimal_ull(p, ' ', cputime64_to_clock_t(softirq));
		seq_put_decimal_ull(p, ' ', cputime64_to_clock_t(steal));
		seq_put_decimal_ull(p, ' ', cputime64_to_clock_t(guest));
		seq_put_decimal_ull(p, ' ', cputime64_to_clock_t(guest_nice));
		seq_putc(p, '\n');
	}
	seq_printf(p, "intr %llu", (unsigned long long)sum);

	/* sum again ? it could be updated? */
	for_each_irq_nr(j)
		seq_put_decimal_ull(p, ' ', kstat_irqs(j));

	seq_printf(p,
		"\nctxt %llu\n"
		"btime %lu\n"
		"processes %lu\n"
		"procs_running %lu\n"
		"procs_blocked %lu\n",
		nr_context_switches(),
		(unsigned long)jif,
		total_forks,
		nr_running(),
		nr_iowait());

	seq_printf(p, "softirq %llu", (unsigned long long)sum_softirq);

	for (i = 0; i < NR_SOFTIRQS; i++)
		seq_put_decimal_ull(p, ' ', per_softirq_sums[i]);
	seq_putc(p, '\n');

	return 0;
}

static int stat_open(struct inode *inode, struct file *file)
{
	size_t size = 1024 + 128 * num_online_cpus();

	/* minimum size to display an interrupt count : 2 bytes */
	size += 2 * nr_irqs;
	return single_open_size(file, show_stat, NULL, size);
}

static const struct file_operations proc_stat_operations = {
	.open		= stat_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_stat_init(void)
{
	proc_create("stat", 0, NULL, &proc_stat_operations);
	return 0;
}
fs_initcall(proc_stat_init);
/************************************************************/
/* ../linux-3.17/fs/proc/stat.c */
/************************************************************/
// #include <linux/fs.h>
// #include <linux/init.h>
// #include <linux/proc_fs.h>
// #include <linux/sched.h>
// #include <linux/seq_file.h>
// #include <linux/time.h>
// #include <linux/kernel_stat.h>
// #include <linux/cputime.h>

static int uptime_proc_show(struct seq_file *m, void *v)
{
	struct timespec uptime;
	struct timespec idle;
	u64 idletime;
	u64 nsec;
	u32 rem;
	int i;

	idletime = 0;
	for_each_possible_cpu(i)
		idletime += (__force u64) kcpustat_cpu(i).cpustat[CPUTIME_IDLE];

	get_monotonic_boottime(&uptime);
	nsec = cputime64_to_jiffies64(idletime) * TICK_NSEC;
	idle.tv_sec = div_u64_rem(nsec, NSEC_PER_SEC, &rem);
	idle.tv_nsec = rem;
	seq_printf(m, "%lu.%02lu %lu.%02lu\n",
			(unsigned long) uptime.tv_sec,
			(uptime.tv_nsec / (NSEC_PER_SEC / 100)),
			(unsigned long) idle.tv_sec,
			(idle.tv_nsec / (NSEC_PER_SEC / 100)));
	return 0;
}

static int uptime_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, uptime_proc_show, NULL);
}

static const struct file_operations uptime_proc_fops = {
	.open		= uptime_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_uptime_init(void)
{
	proc_create("uptime", 0, NULL, &uptime_proc_fops);
	return 0;
}
fs_initcall(proc_uptime_init);
/************************************************************/
/* ../linux-3.17/fs/proc/uptime.c */
/************************************************************/
// #include <linux/fs.h>
// #include <linux/init.h>
// #include <linux/kernel.h>
// #include <linux/proc_fs.h>
// #include <linux/seq_file.h>
#include <linux/utsname.h>

static int version_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, linux_proc_banner,
		utsname()->sysname,
		utsname()->release,
		utsname()->version);
	return 0;
}

static int version_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, version_proc_show, NULL);
}

static const struct file_operations version_proc_fops = {
	.open		= version_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_version_init(void)
{
	proc_create("version", 0, NULL, &version_proc_fops);
	return 0;
}
fs_initcall(proc_version_init);
/************************************************************/
/* ../linux-3.17/fs/proc/version.c */
/************************************************************/
// #include <linux/init.h>
// #include <linux/kernel_stat.h>
// #include <linux/proc_fs.h>
// #include <linux/seq_file.h>

/*
 * /proc/softirqs  ... display the number of softirqs
 */
static int show_softirqs(struct seq_file *p, void *v)
{
	int i, j;

	seq_puts(p, "                    ");
	for_each_possible_cpu(i)
		seq_printf(p, "CPU%-8d", i);
	seq_putc(p, '\n');

	for (i = 0; i < NR_SOFTIRQS; i++) {
		seq_printf(p, "%12s:", softirq_to_name[i]);
		for_each_possible_cpu(j)
			seq_printf(p, " %10u", kstat_softirqs_cpu(i, j));
		seq_putc(p, '\n');
	}
	return 0;
}

static int softirqs_open(struct inode *inode, struct file *file)
{
	return single_open(file, show_softirqs, NULL);
}

static const struct file_operations proc_softirqs_operations = {
	.open		= softirqs_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_softirqs_init(void)
{
	proc_create("softirqs", 0, NULL, &proc_softirqs_operations);
	return 0;
}
fs_initcall(proc_softirqs_init);
/************************************************************/
/* ../linux-3.17/fs/proc/softirqs.c */
/************************************************************/
// #include <linux/proc_fs.h>
// #include <linux/nsproxy.h>
// #include <linux/sched.h>
// #include <linux/ptrace.h>
// #include <linux/fs_struct.h>
// #include <linux/mount.h>
// #include <linux/path.h>
// #include <linux/namei.h>
// #include <linux/file.h>
// #include <linux/utsname.h>
#include <net/net_namespace.h>
#include <linux/ipc_namespace.h>
// #include <linux/pid_namespace.h>
// #include <linux/user_namespace.h>
// #include "internal.h"


static const struct proc_ns_operations *ns_entries[] = {
#ifdef CONFIG_NET_NS
	&netns_operations,
#endif
#ifdef CONFIG_UTS_NS
	&utsns_operations,
#endif
#ifdef CONFIG_IPC_NS
	&ipcns_operations,
#endif
#ifdef CONFIG_PID_NS
	&pidns_operations,
#endif
#ifdef CONFIG_USER_NS
	&userns_operations,
#endif
	&mntns_operations,
};

static const struct file_operations ns_file_operations = {
	.llseek		= no_llseek,
};

static const struct inode_operations ns_inode_operations = {
	.setattr	= proc_setattr,
};

static char *ns_dname(struct dentry *dentry, char *buffer, int buflen)
{
	struct inode *inode = dentry->d_inode;
	const struct proc_ns_operations *ns_ops = PROC_I(inode)->ns.ns_ops;

	return dynamic_dname(dentry, buffer, buflen, "%s:[%lu]",
		ns_ops->name, inode->i_ino);
}

const struct dentry_operations ns_dentry_operations =
{
	.d_delete	= always_delete_dentry,
	.d_dname	= ns_dname,
};

static struct dentry *proc_ns_get_dentry(struct super_block *sb,
	struct task_struct *task, const struct proc_ns_operations *ns_ops)
{
	struct dentry *dentry, *result;
	struct inode *inode;
	struct proc_inode *ei;
	struct qstr qname = { .name = "", };
	void *ns;

	ns = ns_ops->get(task);
	if (!ns)
		return ERR_PTR(-ENOENT);

	dentry = d_alloc_pseudo(sb, &qname);
	if (!dentry) {
		ns_ops->put(ns);
		return ERR_PTR(-ENOMEM);
	}

	inode = iget_locked(sb, ns_ops->inum(ns));
	if (!inode) {
		dput(dentry);
		ns_ops->put(ns);
		return ERR_PTR(-ENOMEM);
	}

	ei = PROC_I(inode);
	if (inode->i_state & I_NEW) {
		inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
		inode->i_op = &ns_inode_operations;
		inode->i_mode = S_IFREG | S_IRUGO;
		inode->i_fop = &ns_file_operations;
		ei->ns.ns_ops = ns_ops;
		ei->ns.ns = ns;
		unlock_new_inode(inode);
	} else {
		ns_ops->put(ns);
	}

	d_set_d_op(dentry, &ns_dentry_operations);
	result = d_instantiate_unique(dentry, inode);
	if (result) {
		dput(dentry);
		dentry = result;
	}

	return dentry;
}

static void *proc_ns_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct proc_inode *ei = PROC_I(inode);
	struct task_struct *task;
	struct path ns_path;
	void *error = ERR_PTR(-EACCES);

	task = get_proc_task(inode);
	if (!task)
		goto out;

	if (!ptrace_may_access(task, PTRACE_MODE_READ))
		goto out_put_task;

	ns_path.dentry = proc_ns_get_dentry(sb, task, ei->ns.ns_ops);
	if (IS_ERR(ns_path.dentry)) {
		error = ERR_CAST(ns_path.dentry);
		goto out_put_task;
	}

	ns_path.mnt = mntget(nd->path.mnt);
	nd_jump_link(nd, &ns_path);
	error = NULL;

out_put_task:
	put_task_struct(task);
out:
	return error;
}

static int proc_ns_readlink(struct dentry *dentry, char __user *buffer, int buflen)
{
	struct inode *inode = dentry->d_inode;
	struct proc_inode *ei = PROC_I(inode);
	const struct proc_ns_operations *ns_ops = ei->ns.ns_ops;
	struct task_struct *task;
	void *ns;
	char name[50];
	int res = -EACCES;

	task = get_proc_task(inode);
	if (!task)
		goto out;

	if (!ptrace_may_access(task, PTRACE_MODE_READ))
		goto out_put_task;

	res = -ENOENT;
	ns = ns_ops->get(task);
	if (!ns)
		goto out_put_task;

	snprintf(name, sizeof(name), "%s:[%u]", ns_ops->name, ns_ops->inum(ns));
	res = readlink_copy(buffer, buflen, name);
	ns_ops->put(ns);
out_put_task:
	put_task_struct(task);
out:
	return res;
}

static const struct inode_operations proc_ns_link_inode_operations = {
	.readlink	= proc_ns_readlink,
	.follow_link	= proc_ns_follow_link,
	.setattr	= proc_setattr,
};

static int proc_ns_instantiate(struct inode *dir,
	struct dentry *dentry, struct task_struct *task, const void *ptr)
{
	const struct proc_ns_operations *ns_ops = ptr;
	struct inode *inode;
	struct proc_inode *ei;

	inode = proc_pid_make_inode(dir->i_sb, task);
	if (!inode)
		goto out;

	ei = PROC_I(inode);
	inode->i_mode = S_IFLNK|S_IRWXUGO;
	inode->i_op = &proc_ns_link_inode_operations;
	ei->ns.ns_ops = ns_ops;

	d_set_d_op(dentry, &pid_dentry_operations);
	d_add(dentry, inode);
	/* Close the race of the process dying before we return the dentry */
	if (pid_revalidate(dentry, 0))
		return 0;
out:
	return -ENOENT;
}

static int proc_ns_dir_readdir(struct file *file, struct dir_context *ctx)
{
	struct task_struct *task = get_proc_task(file_inode(file));
	const struct proc_ns_operations **entry, **last;

	if (!task)
		return -ENOENT;

	if (!dir_emit_dots(file, ctx))
		goto out;
	if (ctx->pos >= 2 + ARRAY_SIZE(ns_entries))
		goto out;
	entry = ns_entries + (ctx->pos - 2);
	last = &ns_entries[ARRAY_SIZE(ns_entries) - 1];
	while (entry <= last) {
		const struct proc_ns_operations *ops = *entry;
		if (!proc_fill_cache(file, ctx, ops->name, strlen(ops->name),
				     proc_ns_instantiate, task, ops))
			break;
		ctx->pos++;
		entry++;
	}
out:
	put_task_struct(task);
	return 0;
}

const struct file_operations proc_ns_dir_operations = {
	.read		= generic_read_dir,
	.iterate	= proc_ns_dir_readdir,
};

static struct dentry *proc_ns_dir_lookup(struct inode *dir,
				struct dentry *dentry, unsigned int flags)
{
	int error;
	struct task_struct *task = get_proc_task(dir);
	const struct proc_ns_operations **entry, **last;
	unsigned int len = dentry->d_name.len;

	error = -ENOENT;

	if (!task)
		goto out_no_task;

	last = &ns_entries[ARRAY_SIZE(ns_entries)];
	for (entry = ns_entries; entry < last; entry++) {
		if (strlen((*entry)->name) != len)
			continue;
		if (!memcmp(dentry->d_name.name, (*entry)->name, len))
			break;
	}
	if (entry == last)
		goto out;

	error = proc_ns_instantiate(dir, dentry, task, *entry);
out:
	put_task_struct(task);
out_no_task:
	return ERR_PTR(error);
}

const struct inode_operations proc_ns_dir_inode_operations = {
	.lookup		= proc_ns_dir_lookup,
	.getattr	= pid_getattr,
	.setattr	= proc_setattr,
};

struct file *proc_ns_fget(int fd)
{
	struct file *file;

	file = fget(fd);
	if (!file)
		return ERR_PTR(-EBADF);

	if (file->f_op != &ns_file_operations)
		goto out_invalid;

	return file;

out_invalid:
	fput(file);
	return ERR_PTR(-EINVAL);
}

struct proc_ns *get_proc_ns(struct inode *inode)
{
	return &PROC_I(inode)->ns;
}

bool proc_ns_inode(struct inode *inode)
{
	return inode->i_fop == &ns_file_operations;
}
/************************************************************/
/* ../linux-3.17/fs/proc/namespaces.c */
/************************************************************/
// #include <linux/sched.h>
// #include <linux/namei.h>
// #include <linux/slab.h>
// #include <linux/pid_namespace.h>
// #include "internal.h"

/*
 * /proc/self:
 */
static int proc_self_readlink(struct dentry *dentry, char __user *buffer,
			      int buflen)
{
	struct pid_namespace *ns = dentry->d_sb->s_fs_info;
	pid_t tgid = task_tgid_nr_ns(current, ns);
	char tmp[PROC_NUMBUF];
	if (!tgid)
		return -ENOENT;
	sprintf(tmp, "%d", tgid);
	return readlink_copy(buffer, buflen, tmp);
}

static void *proc_self_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct pid_namespace *ns = dentry->d_sb->s_fs_info;
	pid_t tgid = task_tgid_nr_ns(current, ns);
	char *name = ERR_PTR(-ENOENT);
	if (tgid) {
		/* 11 for max length of signed int in decimal + NULL term */
		name = kmalloc(12, GFP_KERNEL);
		if (!name)
			name = ERR_PTR(-ENOMEM);
		else
			sprintf(name, "%d", tgid);
	}
	nd_set_link(nd, name);
	return NULL;
}

static const struct inode_operations proc_self_inode_operations = {
	.readlink	= proc_self_readlink,
	.follow_link	= proc_self_follow_link,
	.put_link	= kfree_put_link,
};

static unsigned self_inum;

int proc_setup_self(struct super_block *s)
{
	struct inode *root_inode = s->s_root->d_inode;
	struct pid_namespace *ns = s->s_fs_info;
	struct dentry *self;

	mutex_lock(&root_inode->i_mutex);
	self = d_alloc_name(s->s_root, "self");
	if (self) {
		struct inode *inode = new_inode_pseudo(s);
		if (inode) {
			inode->i_ino = self_inum;
			inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
			inode->i_mode = S_IFLNK | S_IRWXUGO;
			inode->i_uid = GLOBAL_ROOT_UID;
			inode->i_gid = GLOBAL_ROOT_GID;
			inode->i_op = &proc_self_inode_operations;
			d_add(self, inode);
		} else {
			dput(self);
			self = ERR_PTR(-ENOMEM);
		}
	} else {
		self = ERR_PTR(-ENOMEM);
	}
	mutex_unlock(&root_inode->i_mutex);
	if (IS_ERR(self)) {
		pr_err("proc_fill_super: can't allocate /proc/self\n");
		return PTR_ERR(self);
	}
	ns->proc_self = self;
	return 0;
}

void __init proc_self_init(void)
{
	proc_alloc_inum(&self_inum);
}
/************************************************************/
/* ../linux-3.17/fs/proc/self.c */
/************************************************************/
// #include <linux/sched.h>
// #include <linux/namei.h>
// #include <linux/slab.h>
// #include <linux/pid_namespace.h>
// #include "internal.h"

/*
 * /proc/thread_self:
 */
static int proc_thread_self_readlink(struct dentry *dentry, char __user *buffer,
			      int buflen)
{
	struct pid_namespace *ns = dentry->d_sb->s_fs_info;
	pid_t tgid = task_tgid_nr_ns(current, ns);
	pid_t pid = task_pid_nr_ns(current, ns);
	char tmp[PROC_NUMBUF + 6 + PROC_NUMBUF];
	if (!pid)
		return -ENOENT;
	sprintf(tmp, "%d/task/%d", tgid, pid);
	return readlink_copy(buffer, buflen, tmp);
}

static void *proc_thread_self_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct pid_namespace *ns = dentry->d_sb->s_fs_info;
	pid_t tgid = task_tgid_nr_ns(current, ns);
	pid_t pid = task_pid_nr_ns(current, ns);
	char *name = ERR_PTR(-ENOENT);
	if (pid) {
		name = kmalloc(PROC_NUMBUF + 6 + PROC_NUMBUF, GFP_KERNEL);
		if (!name)
			name = ERR_PTR(-ENOMEM);
		else
			sprintf(name, "%d/task/%d", tgid, pid);
	}
	nd_set_link(nd, name);
	return NULL;
}

static const struct inode_operations proc_thread_self_inode_operations = {
	.readlink	= proc_thread_self_readlink,
	.follow_link	= proc_thread_self_follow_link,
	.put_link	= kfree_put_link,
};

static unsigned thread_self_inum;

int proc_setup_thread_self(struct super_block *s)
{
	struct inode *root_inode = s->s_root->d_inode;
	struct pid_namespace *ns = s->s_fs_info;
	struct dentry *thread_self;

	mutex_lock(&root_inode->i_mutex);
	thread_self = d_alloc_name(s->s_root, "thread-self");
	if (thread_self) {
		struct inode *inode = new_inode_pseudo(s);
		if (inode) {
			inode->i_ino = thread_self_inum;
			inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
			inode->i_mode = S_IFLNK | S_IRWXUGO;
			inode->i_uid = GLOBAL_ROOT_UID;
			inode->i_gid = GLOBAL_ROOT_GID;
			inode->i_op = &proc_thread_self_inode_operations;
			d_add(thread_self, inode);
		} else {
			dput(thread_self);
			thread_self = ERR_PTR(-ENOMEM);
		}
	} else {
		thread_self = ERR_PTR(-ENOMEM);
	}
	mutex_unlock(&root_inode->i_mutex);
	if (IS_ERR(thread_self)) {
		pr_err("proc_fill_super: can't allocate /proc/thread_self\n");
		return PTR_ERR(thread_self);
	}
	ns->proc_thread_self = thread_self;
	return 0;
}

void __init proc_thread_self_init(void)
{
	proc_alloc_inum(&thread_self_inum);
}
/************************************************************/
/* ../linux-3.17/fs/proc/thread_self.c */
/************************************************************/
/*
 * /proc/sys support
 */
// #include <linux/init.h>
// #include <linux/sysctl.h>
// #include <linux/poll.h>
// #include <linux/proc_fs.h>
// #include <linux/printk.h>
// #include <linux/security.h>
// #include <linux/sched.h>
// #include <linux/namei.h>
// #include <linux/mm.h>
// #include <linux/module.h>
// #include "internal.h"

static const struct dentry_operations proc_sys_dentry_operations;
static const struct file_operations proc_sys_file_operations;
static const struct inode_operations proc_sys_inode_operations;
static const struct file_operations proc_sys_dir_file_operations;
static const struct inode_operations proc_sys_dir_operations;

void proc_sys_poll_notify(struct ctl_table_poll *poll)
{
	if (!poll)
		return;

	atomic_inc(&poll->event);
	wake_up_interruptible(&poll->wait);
}

static struct ctl_table root_table[] = {
	{
		.procname = "",
		.mode = S_IFDIR|S_IRUGO|S_IXUGO,
	},
	{ }
};
static struct ctl_table_root sysctl_table_root = {
	.default_set.dir.header = {
		{{.count = 1,
		  .nreg = 1,
		  .ctl_table = root_table }},
		.ctl_table_arg = root_table,
		.root = &sysctl_table_root,
		.set = &sysctl_table_root.default_set,
	},
};

static DEFINE_SPINLOCK(sysctl_lock);

static void drop_sysctl_table(struct ctl_table_header *header);
static int sysctl_follow_link(struct ctl_table_header **phead,
	struct ctl_table **pentry, struct nsproxy *namespaces);
static int insert_links(struct ctl_table_header *head);
static void put_links(struct ctl_table_header *header);

static void sysctl_print_dir(struct ctl_dir *dir)
{
	if (dir->header.parent)
		sysctl_print_dir(dir->header.parent);
	pr_cont("%s/", dir->header.ctl_table[0].procname);
}

static int namecmp(const char *name1, int len1, const char *name2, int len2)
{
	int minlen;
	int cmp;

	minlen = len1;
	if (minlen > len2)
		minlen = len2;

	cmp = memcmp(name1, name2, minlen);
	if (cmp == 0)
		cmp = len1 - len2;
	return cmp;
}

/* Called under sysctl_lock */
static struct ctl_table *find_entry(struct ctl_table_header **phead,
	struct ctl_dir *dir, const char *name, int namelen)
{
	struct ctl_table_header *head;
	struct ctl_table *entry;
	struct rb_node *node = dir->root.rb_node;

	while (node)
	{
		struct ctl_node *ctl_node;
		const char *procname;
		int cmp;

		ctl_node = rb_entry(node, struct ctl_node, node);
		head = ctl_node->header;
		entry = &head->ctl_table[ctl_node - head->node];
		procname = entry->procname;

		cmp = namecmp(name, namelen, procname, strlen(procname));
		if (cmp < 0)
			node = node->rb_left;
		else if (cmp > 0)
			node = node->rb_right;
		else {
			*phead = head;
			return entry;
		}
	}
	return NULL;
}

static int insert_entry(struct ctl_table_header *head, struct ctl_table *entry)
{
	struct rb_node *node = &head->node[entry - head->ctl_table].node;
	struct rb_node **p = &head->parent->root.rb_node;
	struct rb_node *parent = NULL;
	const char *name = entry->procname;
	int namelen = strlen(name);

	while (*p) {
		struct ctl_table_header *parent_head;
		struct ctl_table *parent_entry;
		struct ctl_node *parent_node;
		const char *parent_name;
		int cmp;

		parent = *p;
		parent_node = rb_entry(parent, struct ctl_node, node);
		parent_head = parent_node->header;
		parent_entry = &parent_head->ctl_table[parent_node - parent_head->node];
		parent_name = parent_entry->procname;

		cmp = namecmp(name, namelen, parent_name, strlen(parent_name));
		if (cmp < 0)
			p = &(*p)->rb_left;
		else if (cmp > 0)
			p = &(*p)->rb_right;
		else {
			pr_err("sysctl duplicate entry: ");
			sysctl_print_dir(head->parent);
			pr_cont("/%s\n", entry->procname);
			return -EEXIST;
		}
	}

	rb_link_node(node, parent, p);
	rb_insert_color(node, &head->parent->root);
	return 0;
}

static void erase_entry(struct ctl_table_header *head, struct ctl_table *entry)
{
	struct rb_node *node = &head->node[entry - head->ctl_table].node;

	rb_erase(node, &head->parent->root);
}

static void init_header(struct ctl_table_header *head,
	struct ctl_table_root *root, struct ctl_table_set *set,
	struct ctl_node *node, struct ctl_table *table)
{
	head->ctl_table = table;
	head->ctl_table_arg = table;
	head->used = 0;
	head->count = 1;
	head->nreg = 1;
	head->unregistering = NULL;
	head->root = root;
	head->set = set;
	head->parent = NULL;
	head->node = node;
	if (node) {
		struct ctl_table *entry;
		for (entry = table; entry->procname; entry++, node++)
			node->header = head;
	}
}

static void erase_header(struct ctl_table_header *head)
{
	struct ctl_table *entry;
	for (entry = head->ctl_table; entry->procname; entry++)
		erase_entry(head, entry);
}

static int insert_header(struct ctl_dir *dir, struct ctl_table_header *header)
{
	struct ctl_table *entry;
	int err;

	dir->header.nreg++;
	header->parent = dir;
	err = insert_links(header);
	if (err)
		goto fail_links;
	for (entry = header->ctl_table; entry->procname; entry++) {
		err = insert_entry(header, entry);
		if (err)
			goto fail;
	}
	return 0;
fail:
	erase_header(header);
	put_links(header);
fail_links:
	header->parent = NULL;
	drop_sysctl_table(&dir->header);
	return err;
}

/* called under sysctl_lock */
static int use_table(struct ctl_table_header *p)
{
	if (unlikely(p->unregistering))
		return 0;
	p->used++;
	return 1;
}

/* called under sysctl_lock */
static void unuse_table(struct ctl_table_header *p)
{
	if (!--p->used)
		if (unlikely(p->unregistering))
			complete(p->unregistering);
}

/* called under sysctl_lock, will reacquire if has to wait */
static void start_unregistering(struct ctl_table_header *p)
{
	/*
	 * if p->used is 0, nobody will ever touch that entry again;
	 * we'll eliminate all paths to it before dropping sysctl_lock
	 */
	if (unlikely(p->used)) {
		struct completion wait;
		init_completion(&wait);
		p->unregistering = &wait;
		spin_unlock(&sysctl_lock);
		wait_for_completion(&wait);
		spin_lock(&sysctl_lock);
	} else {
		/* anything non-NULL; we'll never dereference it */
		p->unregistering = ERR_PTR(-EINVAL);
	}
	/*
	 * do not remove from the list until nobody holds it; walking the
	 * list in do_sysctl() relies on that.
	 */
	erase_header(p);
}

static void sysctl_head_get(struct ctl_table_header *head)
{
	spin_lock(&sysctl_lock);
	head->count++;
	spin_unlock(&sysctl_lock);
}

void sysctl_head_put(struct ctl_table_header *head)
{
	spin_lock(&sysctl_lock);
	if (!--head->count)
		kfree_rcu(head, rcu);
	spin_unlock(&sysctl_lock);
}

static struct ctl_table_header *sysctl_head_grab(struct ctl_table_header *head)
{
	BUG_ON(!head);
	spin_lock(&sysctl_lock);
	if (!use_table(head))
		head = ERR_PTR(-ENOENT);
	spin_unlock(&sysctl_lock);
	return head;
}

static void sysctl_head_finish(struct ctl_table_header *head)
{
	if (!head)
		return;
	spin_lock(&sysctl_lock);
	unuse_table(head);
	spin_unlock(&sysctl_lock);
}

static struct ctl_table_set *
lookup_header_set(struct ctl_table_root *root, struct nsproxy *namespaces)
{
	struct ctl_table_set *set = &root->default_set;
	if (root->lookup)
		set = root->lookup(root, namespaces);
	return set;
}

static struct ctl_table *lookup_entry(struct ctl_table_header **phead,
				      struct ctl_dir *dir,
				      const char *name, int namelen)
{
	struct ctl_table_header *head;
	struct ctl_table *entry;

	spin_lock(&sysctl_lock);
	entry = find_entry(&head, dir, name, namelen);
	if (entry && use_table(head))
		*phead = head;
	else
		entry = NULL;
	spin_unlock(&sysctl_lock);
	return entry;
}

static struct ctl_node *first_usable_entry(struct rb_node *node)
{
	struct ctl_node *ctl_node;

	for (;node; node = rb_next(node)) {
		ctl_node = rb_entry(node, struct ctl_node, node);
		if (use_table(ctl_node->header))
			return ctl_node;
	}
	return NULL;
}

static void first_entry(struct ctl_dir *dir,
	struct ctl_table_header **phead, struct ctl_table **pentry)
{
	struct ctl_table_header *head = NULL;
	struct ctl_table *entry = NULL;
	struct ctl_node *ctl_node;

	spin_lock(&sysctl_lock);
	ctl_node = first_usable_entry(rb_first(&dir->root));
	spin_unlock(&sysctl_lock);
	if (ctl_node) {
		head = ctl_node->header;
		entry = &head->ctl_table[ctl_node - head->node];
	}
	*phead = head;
	*pentry = entry;
}

static void next_entry(struct ctl_table_header **phead, struct ctl_table **pentry)
{
	struct ctl_table_header *head = *phead;
	struct ctl_table *entry = *pentry;
	struct ctl_node *ctl_node = &head->node[entry - head->ctl_table];

	spin_lock(&sysctl_lock);
	unuse_table(head);

	ctl_node = first_usable_entry(rb_next(&ctl_node->node));
	spin_unlock(&sysctl_lock);
	head = NULL;
	if (ctl_node) {
		head = ctl_node->header;
		entry = &head->ctl_table[ctl_node - head->node];
	}
	*phead = head;
	*pentry = entry;
}

void register_sysctl_root(struct ctl_table_root *root)
{
}

/*
 * sysctl_perm does NOT grant the superuser all rights automatically, because
 * some sysctl variables are readonly even to root.
 */

static int test_perm(int mode, int op)
{
	if (uid_eq(current_euid(), GLOBAL_ROOT_UID))
		mode >>= 6;
	else if (in_egroup_p(GLOBAL_ROOT_GID))
		mode >>= 3;
	if ((op & ~mode & (MAY_READ|MAY_WRITE|MAY_EXEC)) == 0)
		return 0;
	return -EACCES;
}

static int sysctl_perm(struct ctl_table_header *head, struct ctl_table *table, int op)
{
	struct ctl_table_root *root = head->root;
	int mode;

	if (root->permissions)
		mode = root->permissions(head, table);
	else
		mode = table->mode;

	return test_perm(mode, op);
}

static struct inode *proc_sys_make_inode(struct super_block *sb,
		struct ctl_table_header *head, struct ctl_table *table)
{
	struct inode *inode;
	struct proc_inode *ei;

	inode = new_inode(sb);
	if (!inode)
		goto out;

	inode->i_ino = get_next_ino();

	sysctl_head_get(head);
	ei = PROC_I(inode);
	ei->sysctl = head;
	ei->sysctl_entry = table;

	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
	inode->i_mode = table->mode;
	if (!S_ISDIR(table->mode)) {
		inode->i_mode |= S_IFREG;
		inode->i_op = &proc_sys_inode_operations;
		inode->i_fop = &proc_sys_file_operations;
	} else {
		inode->i_mode |= S_IFDIR;
		inode->i_op = &proc_sys_dir_operations;
		inode->i_fop = &proc_sys_dir_file_operations;
	}
out:
	return inode;
}

static struct ctl_table_header *grab_header(struct inode *inode)
{
	struct ctl_table_header *head = PROC_I(inode)->sysctl;
	if (!head)
		head = &sysctl_table_root.default_set.dir.header;
	return sysctl_head_grab(head);
}

static struct dentry *proc_sys_lookup(struct inode *dir, struct dentry *dentry,
					unsigned int flags)
{
	struct ctl_table_header *head = grab_header(dir);
	struct ctl_table_header *h = NULL;
	struct qstr *name = &dentry->d_name;
	struct ctl_table *p;
	struct inode *inode;
	struct dentry *err = ERR_PTR(-ENOENT);
	struct ctl_dir *ctl_dir;
	int ret;

	if (IS_ERR(head))
		return ERR_CAST(head);

	ctl_dir = container_of(head, struct ctl_dir, header);

	p = lookup_entry(&h, ctl_dir, name->name, name->len);
	if (!p)
		goto out;

	if (S_ISLNK(p->mode)) {
		ret = sysctl_follow_link(&h, &p, current->nsproxy);
		err = ERR_PTR(ret);
		if (ret)
			goto out;
	}

	err = ERR_PTR(-ENOMEM);
	inode = proc_sys_make_inode(dir->i_sb, h ? h : head, p);
	if (!inode)
		goto out;

	err = NULL;
	d_set_d_op(dentry, &proc_sys_dentry_operations);
	d_add(dentry, inode);

out:
	if (h)
		sysctl_head_finish(h);
	sysctl_head_finish(head);
	return err;
}

static ssize_t proc_sys_call_handler(struct file *filp, void __user *buf,
		size_t count, loff_t *ppos, int write)
{
	struct inode *inode = file_inode(filp);
	struct ctl_table_header *head = grab_header(inode);
	struct ctl_table *table = PROC_I(inode)->sysctl_entry;
	ssize_t error;
	size_t res;

	if (IS_ERR(head))
		return PTR_ERR(head);

	/*
	 * At this point we know that the sysctl was not unregistered
	 * and won't be until we finish.
	 */
	error = -EPERM;
	if (sysctl_perm(head, table, write ? MAY_WRITE : MAY_READ))
		goto out;

	/* if that can happen at all, it should be -EINVAL, not -EISDIR */
	error = -EINVAL;
	if (!table->proc_handler)
		goto out;

	/* careful: calling conventions are nasty here */
	res = count;
	error = table->proc_handler(table, write, buf, &res, ppos);
	if (!error)
		error = res;
out:
	sysctl_head_finish(head);

	return error;
}

static ssize_t proc_sys_read(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	return proc_sys_call_handler(filp, (void __user *)buf, count, ppos, 0);
}

static ssize_t proc_sys_write(struct file *filp, const char __user *buf,
				size_t count, loff_t *ppos)
{
	return proc_sys_call_handler(filp, (void __user *)buf, count, ppos, 1);
}

static int proc_sys_open(struct inode *inode, struct file *filp)
{
	struct ctl_table_header *head = grab_header(inode);
	struct ctl_table *table = PROC_I(inode)->sysctl_entry;

	/* sysctl was unregistered */
	if (IS_ERR(head))
		return PTR_ERR(head);

	if (table->poll)
		filp->private_data = proc_sys_poll_event(table->poll);

	sysctl_head_finish(head);

	return 0;
}

static unsigned int proc_sys_poll(struct file *filp, poll_table *wait)
{
	struct inode *inode = file_inode(filp);
	struct ctl_table_header *head = grab_header(inode);
	struct ctl_table *table = PROC_I(inode)->sysctl_entry;
	unsigned int ret = DEFAULT_POLLMASK;
	unsigned long event;

	/* sysctl was unregistered */
	if (IS_ERR(head))
		return POLLERR | POLLHUP;

	if (!table->proc_handler)
		goto out;

	if (!table->poll)
		goto out;

	event = (unsigned long)filp->private_data;
	poll_wait(filp, &table->poll->wait, wait);

	if (event != atomic_read(&table->poll->event)) {
		filp->private_data = proc_sys_poll_event(table->poll);
		ret = POLLIN | POLLRDNORM | POLLERR | POLLPRI;
	}

out:
	sysctl_head_finish(head);

	return ret;
}

static bool proc_sys_fill_cache(struct file *file,
				struct dir_context *ctx,
				struct ctl_table_header *head,
				struct ctl_table *table)
{
	struct dentry *child, *dir = file->f_path.dentry;
	struct inode *inode;
	struct qstr qname;
	ino_t ino = 0;
	unsigned type = DT_UNKNOWN;

	qname.name = table->procname;
	qname.len  = strlen(table->procname);
	qname.hash = full_name_hash(qname.name, qname.len);

	child = d_lookup(dir, &qname);
	if (!child) {
		child = d_alloc(dir, &qname);
		if (child) {
			inode = proc_sys_make_inode(dir->d_sb, head, table);
			if (!inode) {
				dput(child);
				return false;
			} else {
				d_set_d_op(child, &proc_sys_dentry_operations);
				d_add(child, inode);
			}
		} else {
			return false;
		}
	}
	inode = child->d_inode;
	ino  = inode->i_ino;
	type = inode->i_mode >> 12;
	dput(child);
	return dir_emit(ctx, qname.name, qname.len, ino, type);
}

static bool proc_sys_link_fill_cache(struct file *file,
				    struct dir_context *ctx,
				    struct ctl_table_header *head,
				    struct ctl_table *table)
{
	bool ret = true;
	head = sysctl_head_grab(head);

	if (S_ISLNK(table->mode)) {
		/* It is not an error if we can not follow the link ignore it */
		int err = sysctl_follow_link(&head, &table, current->nsproxy);
		if (err)
			goto out;
	}

	ret = proc_sys_fill_cache(file, ctx, head, table);
out:
	sysctl_head_finish(head);
	return ret;
}

static int scan(struct ctl_table_header *head, struct ctl_table *table,
		unsigned long *pos, struct file *file,
		struct dir_context *ctx)
{
	bool res;

	if ((*pos)++ < ctx->pos)
		return true;

	if (unlikely(S_ISLNK(table->mode)))
		res = proc_sys_link_fill_cache(file, ctx, head, table);
	else
		res = proc_sys_fill_cache(file, ctx, head, table);

	if (res)
		ctx->pos = *pos;

	return res;
}

static int proc_sys_readdir(struct file *file, struct dir_context *ctx)
{
	struct ctl_table_header *head = grab_header(file_inode(file));
	struct ctl_table_header *h = NULL;
	struct ctl_table *entry;
	struct ctl_dir *ctl_dir;
	unsigned long pos;

	if (IS_ERR(head))
		return PTR_ERR(head);

	ctl_dir = container_of(head, struct ctl_dir, header);

	if (!dir_emit_dots(file, ctx))
		return 0;

	pos = 2;

	for (first_entry(ctl_dir, &h, &entry); h; next_entry(&h, &entry)) {
		if (!scan(h, entry, &pos, file, ctx)) {
			sysctl_head_finish(h);
			break;
		}
	}
	sysctl_head_finish(head);
	return 0;
}

static int proc_sys_permission(struct inode *inode, int mask)
{
	/*
	 * sysctl entries that are not writeable,
	 * are _NOT_ writeable, capabilities or not.
	 */
	struct ctl_table_header *head;
	struct ctl_table *table;
	int error;

	/* Executable files are not allowed under /proc/sys/ */
	if ((mask & MAY_EXEC) && S_ISREG(inode->i_mode))
		return -EACCES;

	head = grab_header(inode);
	if (IS_ERR(head))
		return PTR_ERR(head);

	table = PROC_I(inode)->sysctl_entry;
	if (!table) /* global root - r-xr-xr-x */
		error = mask & MAY_WRITE ? -EACCES : 0;
	else /* Use the permissions on the sysctl table entry */
		error = sysctl_perm(head, table, mask & ~MAY_NOT_BLOCK);

	sysctl_head_finish(head);
	return error;
}

static int proc_sys_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	int error;

	if (attr->ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID))
		return -EPERM;

	error = inode_change_ok(inode, attr);
	if (error)
		return error;

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);
	return 0;
}

static int proc_sys_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat)
{
	struct inode *inode = dentry->d_inode;
	struct ctl_table_header *head = grab_header(inode);
	struct ctl_table *table = PROC_I(inode)->sysctl_entry;

	if (IS_ERR(head))
		return PTR_ERR(head);

	generic_fillattr(inode, stat);
	if (table)
		stat->mode = (stat->mode & S_IFMT) | table->mode;

	sysctl_head_finish(head);
	return 0;
}

static const struct file_operations proc_sys_file_operations = {
	.open		= proc_sys_open,
	.poll		= proc_sys_poll,
	.read		= proc_sys_read,
	.write		= proc_sys_write,
	.llseek		= default_llseek,
};

static const struct file_operations proc_sys_dir_file_operations = {
	.read		= generic_read_dir,
	.iterate	= proc_sys_readdir,
	.llseek		= generic_file_llseek,
};

static const struct inode_operations proc_sys_inode_operations = {
	.permission	= proc_sys_permission,
	.setattr	= proc_sys_setattr,
	.getattr	= proc_sys_getattr,
};

static const struct inode_operations proc_sys_dir_operations = {
	.lookup		= proc_sys_lookup,
	.permission	= proc_sys_permission,
	.setattr	= proc_sys_setattr,
	.getattr	= proc_sys_getattr,
};

static int proc_sys_revalidate(struct dentry *dentry, unsigned int flags)
{
	if (flags & LOOKUP_RCU)
		return -ECHILD;
	return !PROC_I(dentry->d_inode)->sysctl->unregistering;
}

static int proc_sys_delete(const struct dentry *dentry)
{
	return !!PROC_I(dentry->d_inode)->sysctl->unregistering;
}

static int sysctl_is_seen(struct ctl_table_header *p)
{
	struct ctl_table_set *set = p->set;
	int res;
	spin_lock(&sysctl_lock);
	if (p->unregistering)
		res = 0;
	else if (!set->is_seen)
		res = 1;
	else
		res = set->is_seen(set);
	spin_unlock(&sysctl_lock);
	return res;
}

static int proc_sys_compare(const struct dentry *parent, const struct dentry *dentry,
		unsigned int len, const char *str, const struct qstr *name)
{
	struct ctl_table_header *head;
	struct inode *inode;

	/* Although proc doesn't have negative dentries, rcu-walk means
	 * that inode here can be NULL */
	/* AV: can it, indeed? */
	inode = ACCESS_ONCE(dentry->d_inode);
	if (!inode)
		return 1;
	if (name->len != len)
		return 1;
	if (memcmp(name->name, str, len))
		return 1;
	head = rcu_dereference(PROC_I(inode)->sysctl);
	return !head || !sysctl_is_seen(head);
}

static const struct dentry_operations proc_sys_dentry_operations = {
	.d_revalidate	= proc_sys_revalidate,
	.d_delete	= proc_sys_delete,
	.d_compare	= proc_sys_compare,
};

static struct ctl_dir *find_subdir(struct ctl_dir *dir,
				   const char *name, int namelen)
{
	struct ctl_table_header *head;
	struct ctl_table *entry;

	entry = find_entry(&head, dir, name, namelen);
	if (!entry)
		return ERR_PTR(-ENOENT);
	if (!S_ISDIR(entry->mode))
		return ERR_PTR(-ENOTDIR);
	return container_of(head, struct ctl_dir, header);
}

static struct ctl_dir *new_dir(struct ctl_table_set *set,
			       const char *name, int namelen)
{
	struct ctl_table *table;
	struct ctl_dir *new;
	struct ctl_node *node;
	char *new_name;

	new = kzalloc(sizeof(*new) + sizeof(struct ctl_node) +
		      sizeof(struct ctl_table)*2 +  namelen + 1,
		      GFP_KERNEL);
	if (!new)
		return NULL;

	node = (struct ctl_node *)(new + 1);
	table = (struct ctl_table *)(node + 1);
	new_name = (char *)(table + 2);
	memcpy(new_name, name, namelen);
	new_name[namelen] = '\0';
	table[0].procname = new_name;
	table[0].mode = S_IFDIR|S_IRUGO|S_IXUGO;
	init_header(&new->header, set->dir.header.root, set, node, table);

	return new;
}

/**
 * get_subdir - find or create a subdir with the specified name.
 * @dir:  Directory to create the subdirectory in
 * @name: The name of the subdirectory to find or create
 * @namelen: The length of name
 *
 * Takes a directory with an elevated reference count so we know that
 * if we drop the lock the directory will not go away.  Upon success
 * the reference is moved from @dir to the returned subdirectory.
 * Upon error an error code is returned and the reference on @dir is
 * simply dropped.
 */
static struct ctl_dir *get_subdir(struct ctl_dir *dir,
				  const char *name, int namelen)
{
	struct ctl_table_set *set = dir->header.set;
	struct ctl_dir *subdir, *new = NULL;
	int err;

	spin_lock(&sysctl_lock);
	subdir = find_subdir(dir, name, namelen);
	if (!IS_ERR(subdir))
		goto found;
	if (PTR_ERR(subdir) != -ENOENT)
		goto failed;

	spin_unlock(&sysctl_lock);
	new = new_dir(set, name, namelen);
	spin_lock(&sysctl_lock);
	subdir = ERR_PTR(-ENOMEM);
	if (!new)
		goto failed;

	/* Was the subdir added while we dropped the lock? */
	subdir = find_subdir(dir, name, namelen);
	if (!IS_ERR(subdir))
		goto found;
	if (PTR_ERR(subdir) != -ENOENT)
		goto failed;

	/* Nope.  Use the our freshly made directory entry. */
	err = insert_header(dir, &new->header);
	subdir = ERR_PTR(err);
	if (err)
		goto failed;
	subdir = new;
found:
	subdir->header.nreg++;
failed:
	if (unlikely(IS_ERR(subdir))) {
		pr_err("sysctl could not get directory: ");
		sysctl_print_dir(dir);
		pr_cont("/%*.*s %ld\n",
			namelen, namelen, name, PTR_ERR(subdir));
	}
	drop_sysctl_table(&dir->header);
	if (new)
		drop_sysctl_table(&new->header);
	spin_unlock(&sysctl_lock);
	return subdir;
}

static struct ctl_dir *xlate_dir(struct ctl_table_set *set, struct ctl_dir *dir)
{
	struct ctl_dir *parent;
	const char *procname;
	if (!dir->header.parent)
		return &set->dir;
	parent = xlate_dir(set, dir->header.parent);
	if (IS_ERR(parent))
		return parent;
	procname = dir->header.ctl_table[0].procname;
	return find_subdir(parent, procname, strlen(procname));
}

static int sysctl_follow_link(struct ctl_table_header **phead,
	struct ctl_table **pentry, struct nsproxy *namespaces)
{
	struct ctl_table_header *head;
	struct ctl_table_root *root;
	struct ctl_table_set *set;
	struct ctl_table *entry;
	struct ctl_dir *dir;
	int ret;

	ret = 0;
	spin_lock(&sysctl_lock);
	root = (*pentry)->data;
	set = lookup_header_set(root, namespaces);
	dir = xlate_dir(set, (*phead)->parent);
	if (IS_ERR(dir))
		ret = PTR_ERR(dir);
	else {
		const char *procname = (*pentry)->procname;
		head = NULL;
		entry = find_entry(&head, dir, procname, strlen(procname));
		ret = -ENOENT;
		if (entry && use_table(head)) {
			unuse_table(*phead);
			*phead = head;
			*pentry = entry;
			ret = 0;
		}
	}

	spin_unlock(&sysctl_lock);
	return ret;
}

static int sysctl_err(const char *path, struct ctl_table *table, char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;

	pr_err("sysctl table check failed: %s/%s %pV\n",
	       path, table->procname, &vaf);

	va_end(args);
	return -EINVAL;
}

static int sysctl_check_table(const char *path, struct ctl_table *table)
{
	int err = 0;
	for (; table->procname; table++) {
		if (table->child)
			err = sysctl_err(path, table, "Not a file");

		if ((table->proc_handler == proc_dostring) ||
		    (table->proc_handler == proc_dointvec) ||
		    (table->proc_handler == proc_dointvec_minmax) ||
		    (table->proc_handler == proc_dointvec_jiffies) ||
		    (table->proc_handler == proc_dointvec_userhz_jiffies) ||
		    (table->proc_handler == proc_dointvec_ms_jiffies) ||
		    (table->proc_handler == proc_doulongvec_minmax) ||
		    (table->proc_handler == proc_doulongvec_ms_jiffies_minmax)) {
			if (!table->data)
				err = sysctl_err(path, table, "No data");
			if (!table->maxlen)
				err = sysctl_err(path, table, "No maxlen");
		}
		if (!table->proc_handler)
			err = sysctl_err(path, table, "No proc_handler");

		if ((table->mode & (S_IRUGO|S_IWUGO)) != table->mode)
			err = sysctl_err(path, table, "bogus .mode 0%o",
				table->mode);
	}
	return err;
}

static struct ctl_table_header *new_links(struct ctl_dir *dir, struct ctl_table *table,
	struct ctl_table_root *link_root)
{
	struct ctl_table *link_table, *entry, *link;
	struct ctl_table_header *links;
	struct ctl_node *node;
	char *link_name;
	int nr_entries, name_bytes;

	name_bytes = 0;
	nr_entries = 0;
	for (entry = table; entry->procname; entry++) {
		nr_entries++;
		name_bytes += strlen(entry->procname) + 1;
	}

	links = kzalloc(sizeof(struct ctl_table_header) +
			sizeof(struct ctl_node)*nr_entries +
			sizeof(struct ctl_table)*(nr_entries + 1) +
			name_bytes,
			GFP_KERNEL);

	if (!links)
		return NULL;

	node = (struct ctl_node *)(links + 1);
	link_table = (struct ctl_table *)(node + nr_entries);
	link_name = (char *)&link_table[nr_entries + 1];

	for (link = link_table, entry = table; entry->procname; link++, entry++) {
		int len = strlen(entry->procname) + 1;
		memcpy(link_name, entry->procname, len);
		link->procname = link_name;
		link->mode = S_IFLNK|S_IRWXUGO;
		link->data = link_root;
		link_name += len;
	}
	init_header(links, dir->header.root, dir->header.set, node, link_table);
	links->nreg = nr_entries;

	return links;
}

static bool get_links(struct ctl_dir *dir,
	struct ctl_table *table, struct ctl_table_root *link_root)
{
	struct ctl_table_header *head;
	struct ctl_table *entry, *link;

	/* Are there links available for every entry in table? */
	for (entry = table; entry->procname; entry++) {
		const char *procname = entry->procname;
		link = find_entry(&head, dir, procname, strlen(procname));
		if (!link)
			return false;
		if (S_ISDIR(link->mode) && S_ISDIR(entry->mode))
			continue;
		if (S_ISLNK(link->mode) && (link->data == link_root))
			continue;
		return false;
	}

	/* The checks passed.  Increase the registration count on the links */
	for (entry = table; entry->procname; entry++) {
		const char *procname = entry->procname;
		link = find_entry(&head, dir, procname, strlen(procname));
		head->nreg++;
	}
	return true;
}

static int insert_links(struct ctl_table_header *head)
{
	struct ctl_table_set *root_set = &sysctl_table_root.default_set;
	struct ctl_dir *core_parent = NULL;
	struct ctl_table_header *links;
	int err;

	if (head->set == root_set)
		return 0;

	core_parent = xlate_dir(root_set, head->parent);
	if (IS_ERR(core_parent))
		return 0;

	if (get_links(core_parent, head->ctl_table, head->root))
		return 0;

	core_parent->header.nreg++;
	spin_unlock(&sysctl_lock);

	links = new_links(core_parent, head->ctl_table, head->root);

	spin_lock(&sysctl_lock);
	err = -ENOMEM;
	if (!links)
		goto out;

	err = 0;
	if (get_links(core_parent, head->ctl_table, head->root)) {
		kfree(links);
		goto out;
	}

	err = insert_header(core_parent, links);
	if (err)
		kfree(links);
out:
	drop_sysctl_table(&core_parent->header);
	return err;
}

/**
 * __register_sysctl_table - register a leaf sysctl table
 * @set: Sysctl tree to register on
 * @path: The path to the directory the sysctl table is in.
 * @table: the top-level table structure
 *
 * Register a sysctl table hierarchy. @table should be a filled in ctl_table
 * array. A completely 0 filled entry terminates the table.
 *
 * The members of the &struct ctl_table structure are used as follows:
 *
 * procname - the name of the sysctl file under /proc/sys. Set to %NULL to not
 *            enter a sysctl file
 *
 * data - a pointer to data for use by proc_handler
 *
 * maxlen - the maximum size in bytes of the data
 *
 * mode - the file permissions for the /proc/sys file
 *
 * child - must be %NULL.
 *
 * proc_handler - the text handler routine (described below)
 *
 * extra1, extra2 - extra pointers usable by the proc handler routines
 *
 * Leaf nodes in the sysctl tree will be represented by a single file
 * under /proc; non-leaf nodes will be represented by directories.
 *
 * There must be a proc_handler routine for any terminal nodes.
 * Several default handlers are available to cover common cases -
 *
 * proc_dostring(), proc_dointvec(), proc_dointvec_jiffies(),
 * proc_dointvec_userhz_jiffies(), proc_dointvec_minmax(),
 * proc_doulongvec_ms_jiffies_minmax(), proc_doulongvec_minmax()
 *
 * It is the handler's job to read the input buffer from user memory
 * and process it. The handler should return 0 on success.
 *
 * This routine returns %NULL on a failure to register, and a pointer
 * to the table header on success.
 */
struct ctl_table_header *__register_sysctl_table(
	struct ctl_table_set *set,
	const char *path, struct ctl_table *table)
{
	struct ctl_table_root *root = set->dir.header.root;
	struct ctl_table_header *header;
	const char *name, *nextname;
	struct ctl_dir *dir;
	struct ctl_table *entry;
	struct ctl_node *node;
	int nr_entries = 0;

	for (entry = table; entry->procname; entry++)
		nr_entries++;

	header = kzalloc(sizeof(struct ctl_table_header) +
			 sizeof(struct ctl_node)*nr_entries, GFP_KERNEL);
	if (!header)
		return NULL;

	node = (struct ctl_node *)(header + 1);
	init_header(header, root, set, node, table);
	if (sysctl_check_table(path, table))
		goto fail;

	spin_lock(&sysctl_lock);
	dir = &set->dir;
	/* Reference moved down the diretory tree get_subdir */
	dir->header.nreg++;
	spin_unlock(&sysctl_lock);

	/* Find the directory for the ctl_table */
	for (name = path; name; name = nextname) {
		int namelen;
		nextname = strchr(name, '/');
		if (nextname) {
			namelen = nextname - name;
			nextname++;
		} else {
			namelen = strlen(name);
		}
		if (namelen == 0)
			continue;

		dir = get_subdir(dir, name, namelen);
		if (IS_ERR(dir))
			goto fail;
	}

	spin_lock(&sysctl_lock);
	if (insert_header(dir, header))
		goto fail_put_dir_locked;

	drop_sysctl_table(&dir->header);
	spin_unlock(&sysctl_lock);

	return header;

fail_put_dir_locked:
	drop_sysctl_table(&dir->header);
	spin_unlock(&sysctl_lock);
fail:
	kfree(header);
	dump_stack();
	return NULL;
}

/**
 * register_sysctl - register a sysctl table
 * @path: The path to the directory the sysctl table is in.
 * @table: the table structure
 *
 * Register a sysctl table. @table should be a filled in ctl_table
 * array. A completely 0 filled entry terminates the table.
 *
 * See __register_sysctl_table for more details.
 */
struct ctl_table_header *register_sysctl(const char *path, struct ctl_table *table)
{
	return __register_sysctl_table(&sysctl_table_root.default_set,
					path, table);
}
EXPORT_SYMBOL(register_sysctl);

static char *append_path(const char *path, char *pos, const char *name)
{
	int namelen;
	namelen = strlen(name);
	if (((pos - path) + namelen + 2) >= PATH_MAX)
		return NULL;
	memcpy(pos, name, namelen);
	pos[namelen] = '/';
	pos[namelen + 1] = '\0';
	pos += namelen + 1;
	return pos;
}

static int count_subheaders(struct ctl_table *table)
{
	int has_files = 0;
	int nr_subheaders = 0;
	struct ctl_table *entry;

	/* special case: no directory and empty directory */
	if (!table || !table->procname)
		return 1;

	for (entry = table; entry->procname; entry++) {
		if (entry->child)
			nr_subheaders += count_subheaders(entry->child);
		else
			has_files = 1;
	}
	return nr_subheaders + has_files;
}

static int register_leaf_sysctl_tables(const char *path, char *pos,
	struct ctl_table_header ***subheader, struct ctl_table_set *set,
	struct ctl_table *table)
{
	struct ctl_table *ctl_table_arg = NULL;
	struct ctl_table *entry, *files;
	int nr_files = 0;
	int nr_dirs = 0;
	int err = -ENOMEM;

	for (entry = table; entry->procname; entry++) {
		if (entry->child)
			nr_dirs++;
		else
			nr_files++;
	}

	files = table;
	/* If there are mixed files and directories we need a new table */
	if (nr_dirs && nr_files) {
		struct ctl_table *new;
		files = kzalloc(sizeof(struct ctl_table) * (nr_files + 1),
				GFP_KERNEL);
		if (!files)
			goto out;

		ctl_table_arg = files;
		for (new = files, entry = table; entry->procname; entry++) {
			if (entry->child)
				continue;
			*new = *entry;
			new++;
		}
	}

	/* Register everything except a directory full of subdirectories */
	if (nr_files || !nr_dirs) {
		struct ctl_table_header *header;
		header = __register_sysctl_table(set, path, files);
		if (!header) {
			kfree(ctl_table_arg);
			goto out;
		}

		/* Remember if we need to free the file table */
		header->ctl_table_arg = ctl_table_arg;
		**subheader = header;
		(*subheader)++;
	}

	/* Recurse into the subdirectories. */
	for (entry = table; entry->procname; entry++) {
		char *child_pos;

		if (!entry->child)
			continue;

		err = -ENAMETOOLONG;
		child_pos = append_path(path, pos, entry->procname);
		if (!child_pos)
			goto out;

		err = register_leaf_sysctl_tables(path, child_pos, subheader,
						  set, entry->child);
		pos[0] = '\0';
		if (err)
			goto out;
	}
	err = 0;
out:
	/* On failure our caller will unregister all registered subheaders */
	return err;
}

/**
 * __register_sysctl_paths - register a sysctl table hierarchy
 * @set: Sysctl tree to register on
 * @path: The path to the directory the sysctl table is in.
 * @table: the top-level table structure
 *
 * Register a sysctl table hierarchy. @table should be a filled in ctl_table
 * array. A completely 0 filled entry terminates the table.
 *
 * See __register_sysctl_table for more details.
 */
struct ctl_table_header *__register_sysctl_paths(
	struct ctl_table_set *set,
	const struct ctl_path *path, struct ctl_table *table)
{
	struct ctl_table *ctl_table_arg = table;
	int nr_subheaders = count_subheaders(table);
	struct ctl_table_header *header = NULL, **subheaders, **subheader;
	const struct ctl_path *component;
	char *new_path, *pos;

	pos = new_path = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!new_path)
		return NULL;

	pos[0] = '\0';
	for (component = path; component->procname; component++) {
		pos = append_path(new_path, pos, component->procname);
		if (!pos)
			goto out;
	}
	while (table->procname && table->child && !table[1].procname) {
		pos = append_path(new_path, pos, table->procname);
		if (!pos)
			goto out;
		table = table->child;
	}
	if (nr_subheaders == 1) {
		header = __register_sysctl_table(set, new_path, table);
		if (header)
			header->ctl_table_arg = ctl_table_arg;
	} else {
		header = kzalloc(sizeof(*header) +
				 sizeof(*subheaders)*nr_subheaders, GFP_KERNEL);
		if (!header)
			goto out;

		subheaders = (struct ctl_table_header **) (header + 1);
		subheader = subheaders;
		header->ctl_table_arg = ctl_table_arg;

		if (register_leaf_sysctl_tables(new_path, pos, &subheader,
						set, table))
			goto err_register_leaves;
	}

out:
	kfree(new_path);
	return header;

err_register_leaves:
	while (subheader > subheaders) {
		struct ctl_table_header *subh = *(--subheader);
		struct ctl_table *table = subh->ctl_table_arg;
		unregister_sysctl_table(subh);
		kfree(table);
	}
	kfree(header);
	header = NULL;
	goto out;
}

/**
 * register_sysctl_table_path - register a sysctl table hierarchy
 * @path: The path to the directory the sysctl table is in.
 * @table: the top-level table structure
 *
 * Register a sysctl table hierarchy. @table should be a filled in ctl_table
 * array. A completely 0 filled entry terminates the table.
 *
 * See __register_sysctl_paths for more details.
 */
struct ctl_table_header *register_sysctl_paths(const struct ctl_path *path,
						struct ctl_table *table)
{
	return __register_sysctl_paths(&sysctl_table_root.default_set,
					path, table);
}
EXPORT_SYMBOL(register_sysctl_paths);

/**
 * register_sysctl_table - register a sysctl table hierarchy
 * @table: the top-level table structure
 *
 * Register a sysctl table hierarchy. @table should be a filled in ctl_table
 * array. A completely 0 filled entry terminates the table.
 *
 * See register_sysctl_paths for more details.
 */
struct ctl_table_header *register_sysctl_table(struct ctl_table *table)
{
	static const struct ctl_path null_path[] = { {} };

	return register_sysctl_paths(null_path, table);
}
EXPORT_SYMBOL(register_sysctl_table);

static void put_links(struct ctl_table_header *header)
{
	struct ctl_table_set *root_set = &sysctl_table_root.default_set;
	struct ctl_table_root *root = header->root;
	struct ctl_dir *parent = header->parent;
	struct ctl_dir *core_parent;
	struct ctl_table *entry;

	if (header->set == root_set)
		return;

	core_parent = xlate_dir(root_set, parent);
	if (IS_ERR(core_parent))
		return;

	for (entry = header->ctl_table; entry->procname; entry++) {
		struct ctl_table_header *link_head;
		struct ctl_table *link;
		const char *name = entry->procname;

		link = find_entry(&link_head, core_parent, name, strlen(name));
		if (link &&
		    ((S_ISDIR(link->mode) && S_ISDIR(entry->mode)) ||
		     (S_ISLNK(link->mode) && (link->data == root)))) {
			drop_sysctl_table(link_head);
		}
		else {
			pr_err("sysctl link missing during unregister: ");
			sysctl_print_dir(parent);
			pr_cont("/%s\n", name);
		}
	}
}

static void drop_sysctl_table(struct ctl_table_header *header)
{
	struct ctl_dir *parent = header->parent;

	if (--header->nreg)
		return;

	put_links(header);
	start_unregistering(header);
	if (!--header->count)
		kfree_rcu(header, rcu);

	if (parent)
		drop_sysctl_table(&parent->header);
}

/**
 * unregister_sysctl_table - unregister a sysctl table hierarchy
 * @header: the header returned from register_sysctl_table
 *
 * Unregisters the sysctl table and all children. proc entries may not
 * actually be removed until they are no longer used by anyone.
 */
void unregister_sysctl_table(struct ctl_table_header * header)
{
	int nr_subheaders;
	might_sleep();

	if (header == NULL)
		return;

	nr_subheaders = count_subheaders(header->ctl_table_arg);
	if (unlikely(nr_subheaders > 1)) {
		struct ctl_table_header **subheaders;
		int i;

		subheaders = (struct ctl_table_header **)(header + 1);
		for (i = nr_subheaders -1; i >= 0; i--) {
			struct ctl_table_header *subh = subheaders[i];
			struct ctl_table *table = subh->ctl_table_arg;
			unregister_sysctl_table(subh);
			kfree(table);
		}
		kfree(header);
		return;
	}

	spin_lock(&sysctl_lock);
	drop_sysctl_table(header);
	spin_unlock(&sysctl_lock);
}
EXPORT_SYMBOL(unregister_sysctl_table);

void setup_sysctl_set(struct ctl_table_set *set,
	struct ctl_table_root *root,
	int (*is_seen)(struct ctl_table_set *))
{
	memset(set, 0, sizeof(*set));
	set->is_seen = is_seen;
	init_header(&set->dir.header, root, set, NULL, root_table);
}

void retire_sysctl_set(struct ctl_table_set *set)
{
	WARN_ON(!RB_EMPTY_ROOT(&set->dir.root));
}

int __init proc_sys_init(void)
{
	struct proc_dir_entry *proc_sys_root;

	proc_sys_root = proc_mkdir("sys", NULL);
	proc_sys_root->proc_iops = &proc_sys_dir_operations;
	proc_sys_root->proc_fops = &proc_sys_dir_file_operations;
	proc_sys_root->nlink = 0;

	return sysctl_init();
}
/************************************************************/
/* ../linux-3.17/fs/proc/proc_sysctl.c */
/************************************************************/
/*
 *  linux/fs/proc/net.c
 *
 *  Copyright (C) 2007
 *
 *  Author: Eric Biederman <ebiederm@xmission.com>
 *
 *  proc net directory handling functions
 */

// #include <asm/uaccess.h>

// #include <linux/errno.h>
// #include <linux/time.h>
// #include <linux/proc_fs.h>
// #include <linux/stat.h>
// #include <linux/slab.h>
// #include <linux/init.h>
// #include <linux/sched.h>
// #include <linux/module.h>
// #include <linux/bitops.h>
// #include <linux/mount.h>
// #include <linux/nsproxy.h>
// #include <net/net_namespace.h>
// #include <linux/seq_file.h>

// #include "internal.h"

static inline struct net *PDE_NET(struct proc_dir_entry *pde)
{
	return pde->parent->data;
}

static struct net *get_proc_net(const struct inode *inode)
{
	return maybe_get_net(PDE_NET(PDE(inode)));
}

int seq_open_net(struct inode *ino, struct file *f,
		 const struct seq_operations *ops, int size)
{
	struct net *net;
	struct seq_net_private *p;

	BUG_ON(size < sizeof(*p));

	net = get_proc_net(ino);
	if (net == NULL)
		return -ENXIO;

	p = __seq_open_private(f, ops, size);
	if (p == NULL) {
		put_net(net);
		return -ENOMEM;
	}
#ifdef CONFIG_NET_NS
	p->net = net;
#endif
	return 0;
}
EXPORT_SYMBOL_GPL(seq_open_net);

int single_open_net(struct inode *inode, struct file *file,
		int (*show)(struct seq_file *, void *))
{
	int err;
	struct net *net;

	err = -ENXIO;
	net = get_proc_net(inode);
	if (net == NULL)
		goto err_net;

	err = single_open(file, show, net);
	if (err < 0)
		goto err_open;

	return 0;

err_open:
	put_net(net);
err_net:
	return err;
}
EXPORT_SYMBOL_GPL(single_open_net);

int seq_release_net(struct inode *ino, struct file *f)
{
	struct seq_file *seq;

	seq = f->private_data;

	put_net(seq_file_net(seq));
	seq_release_private(ino, f);
	return 0;
}
EXPORT_SYMBOL_GPL(seq_release_net);

int single_release_net(struct inode *ino, struct file *f)
{
	struct seq_file *seq = f->private_data;
	put_net(seq->private);
	return single_release(ino, f);
}
EXPORT_SYMBOL_GPL(single_release_net);

static struct net *get_proc_task_net(struct inode *dir)
{
	struct task_struct *task;
	struct nsproxy *ns;
	struct net *net = NULL;

	rcu_read_lock();
	task = pid_task(proc_pid(dir), PIDTYPE_PID);
	if (task != NULL) {
		task_lock(task);
		ns = task->nsproxy;
		if (ns != NULL)
			net = get_net(ns->net_ns);
		task_unlock(task);
	}
	rcu_read_unlock();

	return net;
}

static struct dentry *proc_tgid_net_lookup(struct inode *dir,
		struct dentry *dentry, unsigned int flags)
{
	struct dentry *de;
	struct net *net;

	de = ERR_PTR(-ENOENT);
	net = get_proc_task_net(dir);
	if (net != NULL) {
		de = proc_lookup_de(net->proc_net, dir, dentry);
		put_net(net);
	}
	return de;
}

static int proc_tgid_net_getattr(struct vfsmount *mnt, struct dentry *dentry,
		struct kstat *stat)
{
	struct inode *inode = dentry->d_inode;
	struct net *net;

	net = get_proc_task_net(inode);

	generic_fillattr(inode, stat);

	if (net != NULL) {
		stat->nlink = net->proc_net->nlink;
		put_net(net);
	}

	return 0;
}

const struct inode_operations proc_net_inode_operations = {
	.lookup		= proc_tgid_net_lookup,
	.getattr	= proc_tgid_net_getattr,
};

static int proc_tgid_net_readdir(struct file *file, struct dir_context *ctx)
{
	int ret;
	struct net *net;

	ret = -EINVAL;
	net = get_proc_task_net(file_inode(file));
	if (net != NULL) {
		ret = proc_readdir_de(net->proc_net, file, ctx);
		put_net(net);
	}
	return ret;
}

const struct file_operations proc_net_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate	= proc_tgid_net_readdir,
};

static __net_init int proc_net_ns_init(struct net *net)
{
	struct proc_dir_entry *netd, *net_statd;
	int err;

	err = -ENOMEM;
	netd = kzalloc(sizeof(*netd) + 4, GFP_KERNEL);
	if (!netd)
		goto out;

	netd->data = net;
	netd->nlink = 2;
	netd->namelen = 3;
	netd->parent = &proc_root;
	memcpy(netd->name, "net", 4);

	err = -EEXIST;
	net_statd = proc_net_mkdir(net, "stat", netd);
	if (!net_statd)
		goto free_net;

	net->proc_net = netd;
	net->proc_net_stat = net_statd;
	return 0;

free_net:
	kfree(netd);
out:
	return err;
}

static __net_exit void proc_net_ns_exit(struct net *net)
{
	remove_proc_entry("stat", net->proc_net);
	kfree(net->proc_net);
}

static struct pernet_operations __net_initdata proc_net_ns_ops = {
	.init = proc_net_ns_init,
	.exit = proc_net_ns_exit,
};

int __init proc_net_init(void)
{
	proc_symlink("net", NULL, "self/net");

	return register_pernet_subsys(&proc_net_ns_ops);
}
/************************************************************/
/* ../linux-3.17/fs/proc/proc_net.c */
/************************************************************/
/*
 *	fs/proc/kcore.c kernel ELF core dumper
 *
 *	Modelled on fs/exec.c:aout_core_dump()
 *	Jeremy Fitzhardinge <jeremy@sw.oz.au>
 *	ELF version written by David Howells <David.Howells@nexor.co.uk>
 *	Modified and incorporated into 2.3.x by Tigran Aivazian <tigran@veritas.com>
 *	Support to dump vmalloc'd areas (ELF only), Tigran Aivazian <tigran@veritas.com>
 *	Safe accesses to vmalloc/direct-mapped discontiguous areas, Kanoj Sarcar <kanoj@sgi.com>
 */

// #include <linux/mm.h>
// #include <linux/proc_fs.h>
#include <linux/kcore.h>
#include <linux/user.h>
// #include <linux/capability.h>
// #include <linux/elf.h>
#include <linux/elfcore.h>
#include <linux/notifier.h>
// #include <linux/vmalloc.h>
// #include <linux/highmem.h>
// #include <linux/printk.h>
#include <linux/bootmem.h>
// #include <linux/init.h>
// #include <linux/slab.h>
// #include <asm/uaccess.h>
#include <asm/io.h>
#include <linux/list.h>
// #include <linux/ioport.h>
#include <linux/memory.h>
#include <asm/sections.h>
// #include "internal.h"

#define CORE_STR "CORE"

#ifndef ELF_CORE_EFLAGS
#define ELF_CORE_EFLAGS	0
#endif

static struct proc_dir_entry *proc_root_kcore;


#ifndef kc_vaddr_to_offset
#define	kc_vaddr_to_offset(v) ((v) - PAGE_OFFSET)
#endif
#ifndef	kc_offset_to_vaddr
#define	kc_offset_to_vaddr(o) ((o) + PAGE_OFFSET)
#endif

/* An ELF note in memory */
struct memelfnote
{
	const char *name;
	int type;
	unsigned int datasz;
	void *data;
};

static LIST_HEAD(kclist_head);
static DEFINE_RWLOCK(kclist_lock);
static int kcore_need_update = 1;

void
kclist_add(struct kcore_list *new, void *addr, size_t size, int type)
{
	new->addr = (unsigned long)addr;
	new->size = size;
	new->type = type;

	write_lock(&kclist_lock);
	list_add_tail(&new->list, &kclist_head);
	write_unlock(&kclist_lock);
}

static size_t get_kcore_size(int *nphdr, size_t *elf_buflen)
{
	size_t try, size;
	struct kcore_list *m;

	*nphdr = 1; /* PT_NOTE */
	size = 0;

	list_for_each_entry(m, &kclist_head, list) {
		try = kc_vaddr_to_offset((size_t)m->addr + m->size);
		if (try > size)
			size = try;
		*nphdr = *nphdr + 1;
	}
	*elf_buflen =	sizeof(struct elfhdr) +
			(*nphdr + 2)*sizeof(struct elf_phdr) +
			3 * ((sizeof(struct elf_note)) +
			     roundup(sizeof(CORE_STR), 4)) +
			roundup(sizeof(struct elf_prstatus), 4) +
			roundup(sizeof(struct elf_prpsinfo), 4) +
			roundup(sizeof(struct task_struct), 4);
	*elf_buflen = PAGE_ALIGN(*elf_buflen);
	return size + *elf_buflen;
}

static void free_kclist_ents(struct list_head *head)
{
	struct kcore_list *tmp, *pos;

	list_for_each_entry_safe(pos, tmp, head, list) {
		list_del(&pos->list);
		kfree(pos);
	}
}
/*
 * Replace all KCORE_RAM/KCORE_VMEMMAP information with passed list.
 */
static void __kcore_update_ram(struct list_head *list)
{
	int nphdr;
	size_t size;
	struct kcore_list *tmp, *pos;
	LIST_HEAD(garbage);

	write_lock(&kclist_lock);
	if (kcore_need_update) {
		list_for_each_entry_safe(pos, tmp, &kclist_head, list) {
			if (pos->type == KCORE_RAM
				|| pos->type == KCORE_VMEMMAP)
				list_move(&pos->list, &garbage);
		}
		list_splice_tail(list, &kclist_head);
	} else
		list_splice(list, &garbage);
	kcore_need_update = 0;
	proc_root_kcore->size = get_kcore_size(&nphdr, &size);
	write_unlock(&kclist_lock);

	free_kclist_ents(&garbage);
}


#ifdef CONFIG_HIGHMEM
/*
 * If no highmem, we can assume [0...max_low_pfn) continuous range of memory
 * because memory hole is not as big as !HIGHMEM case.
 * (HIGHMEM is special because part of memory is _invisible_ from the kernel.)
 */
static int kcore_update_ram(void)
{
	LIST_HEAD(head);
	struct kcore_list *ent;
	int ret = 0;

	ent = kmalloc(sizeof(*ent), GFP_KERNEL);
	if (!ent)
		return -ENOMEM;
	ent->addr = (unsigned long)__va(0);
	ent->size = max_low_pfn << PAGE_SHIFT;
	ent->type = KCORE_RAM;
	list_add(&ent->list, &head);
	__kcore_update_ram(&head);
	return ret;
}

#else /* !CONFIG_HIGHMEM */

#ifdef CONFIG_SPARSEMEM_VMEMMAP
/* calculate vmemmap's address from given system ram pfn and register it */
static int
get_sparsemem_vmemmap_info(struct kcore_list *ent, struct list_head *head)
{
	unsigned long pfn = __pa(ent->addr) >> PAGE_SHIFT;
	unsigned long nr_pages = ent->size >> PAGE_SHIFT;
	unsigned long start, end;
	struct kcore_list *vmm, *tmp;


	start = ((unsigned long)pfn_to_page(pfn)) & PAGE_MASK;
	end = ((unsigned long)pfn_to_page(pfn + nr_pages)) - 1;
	end = PAGE_ALIGN(end);
	/* overlap check (because we have to align page */
	list_for_each_entry(tmp, head, list) {
		if (tmp->type != KCORE_VMEMMAP)
			continue;
		if (start < tmp->addr + tmp->size)
			if (end > tmp->addr)
				end = tmp->addr;
	}
	if (start < end) {
		vmm = kmalloc(sizeof(*vmm), GFP_KERNEL);
		if (!vmm)
			return 0;
		vmm->addr = start;
		vmm->size = end - start;
		vmm->type = KCORE_VMEMMAP;
		list_add_tail(&vmm->list, head);
	}
	return 1;

}
#else
static int
get_sparsemem_vmemmap_info(struct kcore_list *ent, struct list_head *head)
{
	return 1;
}

#endif

static int
kclist_add_private(unsigned long pfn, unsigned long nr_pages, void *arg)
{
	struct list_head *head = (struct list_head *)arg;
	struct kcore_list *ent;

	ent = kmalloc(sizeof(*ent), GFP_KERNEL);
	if (!ent)
		return -ENOMEM;
	ent->addr = (unsigned long)__va((pfn << PAGE_SHIFT));
	ent->size = nr_pages << PAGE_SHIFT;

	/* Sanity check: Can happen in 32bit arch...maybe */
	if (ent->addr < (unsigned long) __va(0))
		goto free_out;

	/* cut not-mapped area. ....from ppc-32 code. */
	if (ULONG_MAX - ent->addr < ent->size)
		ent->size = ULONG_MAX - ent->addr;

	/* cut when vmalloc() area is higher than direct-map area */
	if (VMALLOC_START > (unsigned long)__va(0)) {
		if (ent->addr > VMALLOC_START)
			goto free_out;
		if (VMALLOC_START - ent->addr < ent->size)
			ent->size = VMALLOC_START - ent->addr;
	}

	ent->type = KCORE_RAM;
	list_add_tail(&ent->list, head);

	if (!get_sparsemem_vmemmap_info(ent, head)) {
		list_del(&ent->list);
		goto free_out;
	}

	return 0;
free_out:
	kfree(ent);
	return 1;
}

static int kcore_update_ram(void)
{
	int nid, ret;
	unsigned long end_pfn;
	LIST_HEAD(head);

	/* Not inialized....update now */
	/* find out "max pfn" */
	end_pfn = 0;
	for_each_node_state(nid, N_MEMORY) {
		unsigned long node_end;
		node_end = node_end_pfn(nid);
		if (end_pfn < node_end)
			end_pfn = node_end;
	}
	/* scan 0 to max_pfn */
	ret = walk_system_ram_range(0, end_pfn, &head, kclist_add_private);
	if (ret) {
		free_kclist_ents(&head);
		return -ENOMEM;
	}
	__kcore_update_ram(&head);
	return ret;
}
#endif /* CONFIG_HIGHMEM */

/*****************************************************************************/
/*
 * determine size of ELF note
 */
static int notesize(struct memelfnote *en)
{
	int sz;

	sz = sizeof(struct elf_note);
	sz += roundup((strlen(en->name) + 1), 4);
	sz += roundup(en->datasz, 4);

	return sz;
} /* end notesize() */

/*****************************************************************************/
/*
 * store a note in the header buffer
 */
static char *storenote(struct memelfnote *men, char *bufp)
{
	struct elf_note en;

#define DUMP_WRITE(addr,nr) do { memcpy(bufp,addr,nr); bufp += nr; } while(0)

	en.n_namesz = strlen(men->name) + 1;
	en.n_descsz = men->datasz;
	en.n_type = men->type;

	DUMP_WRITE(&en, sizeof(en));
	DUMP_WRITE(men->name, en.n_namesz);

	/* XXX - cast from long long to long to avoid need for libgcc.a */
	bufp = (char*) roundup((unsigned long)bufp,4);
	DUMP_WRITE(men->data, men->datasz);
	bufp = (char*) roundup((unsigned long)bufp,4);

#undef DUMP_WRITE

	return bufp;
} /* end storenote() */

/*
 * store an ELF coredump header in the supplied buffer
 * nphdr is the number of elf_phdr to insert
 */
static void elf_kcore_store_hdr(char *bufp, int nphdr, int dataoff)
{
	struct elf_prstatus prstatus;	/* NT_PRSTATUS */
	struct elf_prpsinfo prpsinfo;	/* NT_PRPSINFO */
	struct elf_phdr *nhdr, *phdr;
	struct elfhdr *elf;
	struct memelfnote notes[3];
	off_t offset = 0;
	struct kcore_list *m;

	/* setup ELF header */
	elf = (struct elfhdr *) bufp;
	bufp += sizeof(struct elfhdr);
	offset += sizeof(struct elfhdr);
	memcpy(elf->e_ident, ELFMAG, SELFMAG);
	elf->e_ident[EI_CLASS]	= ELF_CLASS;
	elf->e_ident[EI_DATA]	= ELF_DATA;
	elf->e_ident[EI_VERSION]= EV_CURRENT;
	elf->e_ident[EI_OSABI] = ELF_OSABI;
	memset(elf->e_ident+EI_PAD, 0, EI_NIDENT-EI_PAD);
	elf->e_type	= ET_CORE;
	elf->e_machine	= ELF_ARCH;
	elf->e_version	= EV_CURRENT;
	elf->e_entry	= 0;
	elf->e_phoff	= sizeof(struct elfhdr);
	elf->e_shoff	= 0;
	elf->e_flags	= ELF_CORE_EFLAGS;
	elf->e_ehsize	= sizeof(struct elfhdr);
	elf->e_phentsize= sizeof(struct elf_phdr);
	elf->e_phnum	= nphdr;
	elf->e_shentsize= 0;
	elf->e_shnum	= 0;
	elf->e_shstrndx	= 0;

	/* setup ELF PT_NOTE program header */
	nhdr = (struct elf_phdr *) bufp;
	bufp += sizeof(struct elf_phdr);
	offset += sizeof(struct elf_phdr);
	nhdr->p_type	= PT_NOTE;
	nhdr->p_offset	= 0;
	nhdr->p_vaddr	= 0;
	nhdr->p_paddr	= 0;
	nhdr->p_filesz	= 0;
	nhdr->p_memsz	= 0;
	nhdr->p_flags	= 0;
	nhdr->p_align	= 0;

	/* setup ELF PT_LOAD program header for every area */
	list_for_each_entry(m, &kclist_head, list) {
		phdr = (struct elf_phdr *) bufp;
		bufp += sizeof(struct elf_phdr);
		offset += sizeof(struct elf_phdr);

		phdr->p_type	= PT_LOAD;
		phdr->p_flags	= PF_R|PF_W|PF_X;
		phdr->p_offset	= kc_vaddr_to_offset(m->addr) + dataoff;
		phdr->p_vaddr	= (size_t)m->addr;
		phdr->p_paddr	= 0;
		phdr->p_filesz	= phdr->p_memsz	= m->size;
		phdr->p_align	= PAGE_SIZE;
	}

	/*
	 * Set up the notes in similar form to SVR4 core dumps made
	 * with info from their /proc.
	 */
	nhdr->p_offset	= offset;

	/* set up the process status */
	notes[0].name = CORE_STR;
	notes[0].type = NT_PRSTATUS;
	notes[0].datasz = sizeof(struct elf_prstatus);
	notes[0].data = &prstatus;

	memset(&prstatus, 0, sizeof(struct elf_prstatus));

	nhdr->p_filesz	= notesize(&notes[0]);
	bufp = storenote(&notes[0], bufp);

	/* set up the process info */
	notes[1].name	= CORE_STR;
	notes[1].type	= NT_PRPSINFO;
	notes[1].datasz	= sizeof(struct elf_prpsinfo);
	notes[1].data	= &prpsinfo;

	memset(&prpsinfo, 0, sizeof(struct elf_prpsinfo));
	prpsinfo.pr_state	= 0;
	prpsinfo.pr_sname	= 'R';
	prpsinfo.pr_zomb	= 0;

	strcpy(prpsinfo.pr_fname, "vmlinux");
	strlcpy(prpsinfo.pr_psargs, saved_command_line, sizeof(prpsinfo.pr_psargs));

	nhdr->p_filesz	+= notesize(&notes[1]);
	bufp = storenote(&notes[1], bufp);

	/* set up the task structure */
	notes[2].name	= CORE_STR;
	notes[2].type	= NT_TASKSTRUCT;
	notes[2].datasz	= sizeof(struct task_struct);
	notes[2].data	= current;

	nhdr->p_filesz	+= notesize(&notes[2]);
	bufp = storenote(&notes[2], bufp);

} /* end elf_kcore_store_hdr() */

/*****************************************************************************/
/*
 * read from the ELF header and then kernel memory
 */
static ssize_t
read_kcore(struct file *file, char __user *buffer, size_t buflen, loff_t *fpos)
{
	ssize_t acc = 0;
	size_t size, tsz;
	size_t elf_buflen;
	int nphdr;
	unsigned long start;

	read_lock(&kclist_lock);
	size = get_kcore_size(&nphdr, &elf_buflen);

	if (buflen == 0 || *fpos >= size) {
		read_unlock(&kclist_lock);
		return 0;
	}

	/* trim buflen to not go beyond EOF */
	if (buflen > size - *fpos)
		buflen = size - *fpos;

	/* construct an ELF core header if we'll need some of it */
	if (*fpos < elf_buflen) {
		char * elf_buf;

		tsz = elf_buflen - *fpos;
		if (buflen < tsz)
			tsz = buflen;
		elf_buf = kzalloc(elf_buflen, GFP_ATOMIC);
		if (!elf_buf) {
			read_unlock(&kclist_lock);
			return -ENOMEM;
		}
		elf_kcore_store_hdr(elf_buf, nphdr, elf_buflen);
		read_unlock(&kclist_lock);
		if (copy_to_user(buffer, elf_buf + *fpos, tsz)) {
			kfree(elf_buf);
			return -EFAULT;
		}
		kfree(elf_buf);
		buflen -= tsz;
		*fpos += tsz;
		buffer += tsz;
		acc += tsz;

		/* leave now if filled buffer already */
		if (buflen == 0)
			return acc;
	} else
		read_unlock(&kclist_lock);

	/*
	 * Check to see if our file offset matches with any of
	 * the addresses in the elf_phdr on our list.
	 */
	start = kc_offset_to_vaddr(*fpos - elf_buflen);
	if ((tsz = (PAGE_SIZE - (start & ~PAGE_MASK))) > buflen)
		tsz = buflen;

	while (buflen) {
		struct kcore_list *m;

		read_lock(&kclist_lock);
		list_for_each_entry(m, &kclist_head, list) {
			if (start >= m->addr && start < (m->addr+m->size))
				break;
		}
		read_unlock(&kclist_lock);

		if (&m->list == &kclist_head) {
			if (clear_user(buffer, tsz))
				return -EFAULT;
		} else if (is_vmalloc_or_module_addr((void *)start)) {
			char * elf_buf;

			elf_buf = kzalloc(tsz, GFP_KERNEL);
			if (!elf_buf)
				return -ENOMEM;
			vread(elf_buf, (char *)start, tsz);
			/* we have to zero-fill user buffer even if no read */
			if (copy_to_user(buffer, elf_buf, tsz)) {
				kfree(elf_buf);
				return -EFAULT;
			}
			kfree(elf_buf);
		} else {
			if (kern_addr_valid(start)) {
				unsigned long n;

				n = copy_to_user(buffer, (char *)start, tsz);
				/*
				 * We cannot distinguish between fault on source
				 * and fault on destination. When this happens
				 * we clear too and hope it will trigger the
				 * EFAULT again.
				 */
				if (n) {
					if (clear_user(buffer + tsz - n,
								n))
						return -EFAULT;
				}
			} else {
				if (clear_user(buffer, tsz))
					return -EFAULT;
			}
		}
		buflen -= tsz;
		*fpos += tsz;
		buffer += tsz;
		acc += tsz;
		start += tsz;
		tsz = (buflen > PAGE_SIZE ? PAGE_SIZE : buflen);
	}

	return acc;
}


static int open_kcore(struct inode *inode, struct file *filp)
{
	if (!capable(CAP_SYS_RAWIO))
		return -EPERM;
	if (kcore_need_update)
		kcore_update_ram();
	if (i_size_read(inode) != proc_root_kcore->size) {
		mutex_lock(&inode->i_mutex);
		i_size_write(inode, proc_root_kcore->size);
		mutex_unlock(&inode->i_mutex);
	}
	return 0;
}


static const struct file_operations proc_kcore_operations = {
	.read		= read_kcore,
	.open		= open_kcore,
	.llseek		= default_llseek,
};

/* just remember that we have to update kcore */
static int __meminit kcore_callback(struct notifier_block *self,
				    unsigned long action, void *arg)
{
	switch (action) {
	case MEM_ONLINE:
	case MEM_OFFLINE:
		write_lock(&kclist_lock);
		kcore_need_update = 1;
		write_unlock(&kclist_lock);
	}
	return NOTIFY_OK;
}

static struct notifier_block kcore_callback_nb __meminitdata = {
	.notifier_call = kcore_callback,
	.priority = 0,
};

static struct kcore_list kcore_vmalloc;

#ifdef CONFIG_ARCH_PROC_KCORE_TEXT
static struct kcore_list kcore_text;
/*
 * If defined, special segment is used for mapping kernel text instead of
 * direct-map area. We need to create special TEXT section.
 */
static void __init proc_kcore_text_init(void)
{
	kclist_add(&kcore_text, _text, _end - _text, KCORE_TEXT);
}
#else
static void __init proc_kcore_text_init(void)
{
}
#endif

#if defined(CONFIG_MODULES) && defined(MODULES_VADDR)
/*
 * MODULES_VADDR has no intersection with VMALLOC_ADDR.
 */
struct kcore_list kcore_modules;
static void __init add_modules_range(void)
{
	kclist_add(&kcore_modules, (void *)MODULES_VADDR,
			MODULES_END - MODULES_VADDR, KCORE_VMALLOC);
}
#else
static void __init add_modules_range(void)
{
}
#endif

static int __init proc_kcore_init(void)
{
	proc_root_kcore = proc_create("kcore", S_IRUSR, NULL,
				      &proc_kcore_operations);
	if (!proc_root_kcore) {
		pr_err("couldn't create /proc/kcore\n");
		return 0; /* Always returns 0. */
	}
	/* Store text area if it's special */
	proc_kcore_text_init();
	/* Store vmalloc area */
	kclist_add(&kcore_vmalloc, (void *)VMALLOC_START,
		VMALLOC_END - VMALLOC_START, KCORE_VMALLOC);
	add_modules_range();
	/* Store direct-map area from physical memory map */
	kcore_update_ram();
	register_hotmemory_notifier(&kcore_callback_nb);

	return 0;
}
fs_initcall(proc_kcore_init);
/************************************************************/
/* ../linux-3.17/fs/proc/kcore.c */
/************************************************************/
/*
 *	fs/proc/vmcore.c Interface for accessing the crash
 * 				 dump from the system's previous life.
 * 	Heavily borrowed from fs/proc/kcore.c
 *	Created by: Hariprasad Nellitheertha (hari@in.ibm.com)
 *	Copyright (C) IBM Corporation, 2004. All rights reserved
 *
 */

// #include <linux/mm.h>
// #include <linux/kcore.h>
// #include <linux/user.h>
// #include <linux/elf.h>
// #include <linux/elfcore.h>
#include <linux/export.h>
// #include <linux/slab.h>
// #include <linux/highmem.h>
// #include <linux/printk.h>
// #include <linux/bootmem.h>
// #include <linux/init.h>
#include <linux/crash_dump.h>
// #include <linux/list.h>
// #include <linux/vmalloc.h>
// #include <linux/pagemap.h>
// #include <asm/uaccess.h>
// #include <asm/io.h>
// #include "internal.h"

/* List representing chunks of contiguous memory areas and their offsets in
 * vmcore file.
 */
static LIST_HEAD(vmcore_list);

/* Stores the pointer to the buffer containing kernel elf core headers. */
static char *elfcorebuf;
static size_t elfcorebuf_sz;
static size_t elfcorebuf_sz_orig;

static char *elfnotes_buf;
static size_t elfnotes_sz;

/* Total size of vmcore file. */
static u64 vmcore_size;

static struct proc_dir_entry *proc_vmcore;

/*
 * Returns > 0 for RAM pages, 0 for non-RAM pages, < 0 on error
 * The called function has to take care of module refcounting.
 */
static int (*oldmem_pfn_is_ram)(unsigned long pfn);

int register_oldmem_pfn_is_ram(int (*fn)(unsigned long pfn))
{
	if (oldmem_pfn_is_ram)
		return -EBUSY;
	oldmem_pfn_is_ram = fn;
	return 0;
}
EXPORT_SYMBOL_GPL(register_oldmem_pfn_is_ram);

void unregister_oldmem_pfn_is_ram(void)
{
	oldmem_pfn_is_ram = NULL;
	wmb();
}
EXPORT_SYMBOL_GPL(unregister_oldmem_pfn_is_ram);

static int pfn_is_ram(unsigned long pfn)
{
	int (*fn)(unsigned long pfn);
	/* pfn is ram unless fn() checks pagetype */
	int ret = 1;

	/*
	 * Ask hypervisor if the pfn is really ram.
	 * A ballooned page contains no data and reading from such a page
	 * will cause high load in the hypervisor.
	 */
	fn = oldmem_pfn_is_ram;
	if (fn)
		ret = fn(pfn);

	return ret;
}

/* Reads a page from the oldmem device from given offset. */
static ssize_t read_from_oldmem(char *buf, size_t count,
				u64 *ppos, int userbuf)
{
	unsigned long pfn, offset;
	size_t nr_bytes;
	ssize_t read = 0, tmp;

	if (!count)
		return 0;

	offset = (unsigned long)(*ppos % PAGE_SIZE);
	pfn = (unsigned long)(*ppos / PAGE_SIZE);

	do {
		if (count > (PAGE_SIZE - offset))
			nr_bytes = PAGE_SIZE - offset;
		else
			nr_bytes = count;

		/* If pfn is not ram, return zeros for sparse dump files */
		if (pfn_is_ram(pfn) == 0)
			memset(buf, 0, nr_bytes);
		else {
			tmp = copy_oldmem_page(pfn, buf, nr_bytes,
						offset, userbuf);
			if (tmp < 0)
				return tmp;
		}
		*ppos += nr_bytes;
		count -= nr_bytes;
		buf += nr_bytes;
		read += nr_bytes;
		++pfn;
		offset = 0;
	} while (count);

	return read;
}

/*
 * Architectures may override this function to allocate ELF header in 2nd kernel
 */
int __weak elfcorehdr_alloc(unsigned long long *addr, unsigned long long *size)
{
	return 0;
}

/*
 * Architectures may override this function to free header
 */
void __weak elfcorehdr_free(unsigned long long addr)
{}

/*
 * Architectures may override this function to read from ELF header
 */
ssize_t __weak elfcorehdr_read(char *buf, size_t count, u64 *ppos)
{
	return read_from_oldmem(buf, count, ppos, 0);
}

/*
 * Architectures may override this function to read from notes sections
 */
ssize_t __weak elfcorehdr_read_notes(char *buf, size_t count, u64 *ppos)
{
	return read_from_oldmem(buf, count, ppos, 0);
}

/*
 * Architectures may override this function to map oldmem
 */
int __weak remap_oldmem_pfn_range(struct vm_area_struct *vma,
				  unsigned long from, unsigned long pfn,
				  unsigned long size, pgprot_t prot)
{
	return remap_pfn_range(vma, from, pfn, size, prot);
}

/*
 * Copy to either kernel or user space
 */
static int copy_to(void *target, void *src, size_t size, int userbuf)
{
	if (userbuf) {
		if (copy_to_user((char __user *) target, src, size))
			return -EFAULT;
	} else {
		memcpy(target, src, size);
	}
	return 0;
}

/* Read from the ELF header and then the crash dump. On error, negative value is
 * returned otherwise number of bytes read are returned.
 */
static ssize_t __read_vmcore(char *buffer, size_t buflen, loff_t *fpos,
			     int userbuf)
{
	ssize_t acc = 0, tmp;
	size_t tsz;
	u64 start;
	struct vmcore *m = NULL;

	if (buflen == 0 || *fpos >= vmcore_size)
		return 0;

	/* trim buflen to not go beyond EOF */
	if (buflen > vmcore_size - *fpos)
		buflen = vmcore_size - *fpos;

	/* Read ELF core header */
	if (*fpos < elfcorebuf_sz) {
		tsz = min(elfcorebuf_sz - (size_t)*fpos, buflen);
		if (copy_to(buffer, elfcorebuf + *fpos, tsz, userbuf))
			return -EFAULT;
		buflen -= tsz;
		*fpos += tsz;
		buffer += tsz;
		acc += tsz;

		/* leave now if filled buffer already */
		if (buflen == 0)
			return acc;
	}

	/* Read Elf note segment */
	if (*fpos < elfcorebuf_sz + elfnotes_sz) {
		void *kaddr;

		tsz = min(elfcorebuf_sz + elfnotes_sz - (size_t)*fpos, buflen);
		kaddr = elfnotes_buf + *fpos - elfcorebuf_sz;
		if (copy_to(buffer, kaddr, tsz, userbuf))
			return -EFAULT;
		buflen -= tsz;
		*fpos += tsz;
		buffer += tsz;
		acc += tsz;

		/* leave now if filled buffer already */
		if (buflen == 0)
			return acc;
	}

	list_for_each_entry(m, &vmcore_list, list) {
		if (*fpos < m->offset + m->size) {
			tsz = min_t(size_t, m->offset + m->size - *fpos, buflen);
			start = m->paddr + *fpos - m->offset;
			tmp = read_from_oldmem(buffer, tsz, &start, userbuf);
			if (tmp < 0)
				return tmp;
			buflen -= tsz;
			*fpos += tsz;
			buffer += tsz;
			acc += tsz;

			/* leave now if filled buffer already */
			if (buflen == 0)
				return acc;
		}
	}

	return acc;
}

static ssize_t read_vmcore(struct file *file, char __user *buffer,
			   size_t buflen, loff_t *fpos)
{
	return __read_vmcore((__force char *) buffer, buflen, fpos, 1);
}

/*
 * The vmcore fault handler uses the page cache and fills data using the
 * standard __vmcore_read() function.
 *
 * On s390 the fault handler is used for memory regions that can't be mapped
 * directly with remap_pfn_range().
 */
static int mmap_vmcore_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
#ifdef CONFIG_S390
	struct address_space *mapping = vma->vm_file->f_mapping;
	pgoff_t index = vmf->pgoff;
	struct page *page;
	loff_t offset;
	char *buf;
	int rc;

	page = find_or_create_page(mapping, index, GFP_KERNEL);
	if (!page)
		return VM_FAULT_OOM;
	if (!PageUptodate(page)) {
		offset = (loff_t) index << PAGE_CACHE_SHIFT;
		buf = __va((page_to_pfn(page) << PAGE_SHIFT));
		rc = __read_vmcore(buf, PAGE_SIZE, &offset, 0);
		if (rc < 0) {
			unlock_page(page);
			page_cache_release(page);
			return (rc == -ENOMEM) ? VM_FAULT_OOM : VM_FAULT_SIGBUS;
		}
		SetPageUptodate(page);
	}
	unlock_page(page);
	vmf->page = page;
	return 0;
#else
	return VM_FAULT_SIGBUS;
#endif
}

static const struct vm_operations_struct vmcore_mmap_ops = {
	.fault = mmap_vmcore_fault,
};

/**
 * alloc_elfnotes_buf - allocate buffer for ELF note segment in
 *                      vmalloc memory
 *
 * @notes_sz: size of buffer
 *
 * If CONFIG_MMU is defined, use vmalloc_user() to allow users to mmap
 * the buffer to user-space by means of remap_vmalloc_range().
 *
 * If CONFIG_MMU is not defined, use vzalloc() since mmap_vmcore() is
 * disabled and there's no need to allow users to mmap the buffer.
 */
static inline char *alloc_elfnotes_buf(size_t notes_sz)
{
#ifdef CONFIG_MMU
	return vmalloc_user(notes_sz);
#else
	return vzalloc(notes_sz);
#endif
}

/*
 * Disable mmap_vmcore() if CONFIG_MMU is not defined. MMU is
 * essential for mmap_vmcore() in order to map physically
 * non-contiguous objects (ELF header, ELF note segment and memory
 * regions in the 1st kernel pointed to by PT_LOAD entries) into
 * virtually contiguous user-space in ELF layout.
 */
#ifdef CONFIG_MMU
/*
 * remap_oldmem_pfn_checked - do remap_oldmem_pfn_range replacing all pages
 * reported as not being ram with the zero page.
 *
 * @vma: vm_area_struct describing requested mapping
 * @from: start remapping from
 * @pfn: page frame number to start remapping to
 * @size: remapping size
 * @prot: protection bits
 *
 * Returns zero on success, -EAGAIN on failure.
 */
static int remap_oldmem_pfn_checked(struct vm_area_struct *vma,
				    unsigned long from, unsigned long pfn,
				    unsigned long size, pgprot_t prot)
{
	unsigned long map_size;
	unsigned long pos_start, pos_end, pos;
	unsigned long zeropage_pfn = my_zero_pfn(0);
	size_t len = 0;

	pos_start = pfn;
	pos_end = pfn + (size >> PAGE_SHIFT);

	for (pos = pos_start; pos < pos_end; ++pos) {
		if (!pfn_is_ram(pos)) {
			/*
			 * We hit a page which is not ram. Remap the continuous
			 * region between pos_start and pos-1 and replace
			 * the non-ram page at pos with the zero page.
			 */
			if (pos > pos_start) {
				/* Remap continuous region */
				map_size = (pos - pos_start) << PAGE_SHIFT;
				if (remap_oldmem_pfn_range(vma, from + len,
							   pos_start, map_size,
							   prot))
					goto fail;
				len += map_size;
			}
			/* Remap the zero page */
			if (remap_oldmem_pfn_range(vma, from + len,
						   zeropage_pfn,
						   PAGE_SIZE, prot))
				goto fail;
			len += PAGE_SIZE;
			pos_start = pos + 1;
		}
	}
	if (pos > pos_start) {
		/* Remap the rest */
		map_size = (pos - pos_start) << PAGE_SHIFT;
		if (remap_oldmem_pfn_range(vma, from + len, pos_start,
					   map_size, prot))
			goto fail;
	}
	return 0;
fail:
	do_munmap(vma->vm_mm, from, len);
	return -EAGAIN;
}

static int vmcore_remap_oldmem_pfn(struct vm_area_struct *vma,
			    unsigned long from, unsigned long pfn,
			    unsigned long size, pgprot_t prot)
{
	/*
	 * Check if oldmem_pfn_is_ram was registered to avoid
	 * looping over all pages without a reason.
	 */
	if (oldmem_pfn_is_ram)
		return remap_oldmem_pfn_checked(vma, from, pfn, size, prot);
	else
		return remap_oldmem_pfn_range(vma, from, pfn, size, prot);
}

static int mmap_vmcore(struct file *file, struct vm_area_struct *vma)
{
	size_t size = vma->vm_end - vma->vm_start;
	u64 start, end, len, tsz;
	struct vmcore *m;

	start = (u64)vma->vm_pgoff << PAGE_SHIFT;
	end = start + size;

	if (size > vmcore_size || end > vmcore_size)
		return -EINVAL;

	if (vma->vm_flags & (VM_WRITE | VM_EXEC))
		return -EPERM;

	vma->vm_flags &= ~(VM_MAYWRITE | VM_MAYEXEC);
	vma->vm_flags |= VM_MIXEDMAP;
	vma->vm_ops = &vmcore_mmap_ops;

	len = 0;

	if (start < elfcorebuf_sz) {
		u64 pfn;

		tsz = min(elfcorebuf_sz - (size_t)start, size);
		pfn = __pa(elfcorebuf + start) >> PAGE_SHIFT;
		if (remap_pfn_range(vma, vma->vm_start, pfn, tsz,
				    vma->vm_page_prot))
			return -EAGAIN;
		size -= tsz;
		start += tsz;
		len += tsz;

		if (size == 0)
			return 0;
	}

	if (start < elfcorebuf_sz + elfnotes_sz) {
		void *kaddr;

		tsz = min(elfcorebuf_sz + elfnotes_sz - (size_t)start, size);
		kaddr = elfnotes_buf + start - elfcorebuf_sz;
		if (remap_vmalloc_range_partial(vma, vma->vm_start + len,
						kaddr, tsz))
			goto fail;
		size -= tsz;
		start += tsz;
		len += tsz;

		if (size == 0)
			return 0;
	}

	list_for_each_entry(m, &vmcore_list, list) {
		if (start < m->offset + m->size) {
			u64 paddr = 0;

			tsz = min_t(size_t, m->offset + m->size - start, size);
			paddr = m->paddr + start - m->offset;
			if (vmcore_remap_oldmem_pfn(vma, vma->vm_start + len,
						    paddr >> PAGE_SHIFT, tsz,
						    vma->vm_page_prot))
				goto fail;
			size -= tsz;
			start += tsz;
			len += tsz;

			if (size == 0)
				return 0;
		}
	}

	return 0;
fail:
	do_munmap(vma->vm_mm, vma->vm_start, len);
	return -EAGAIN;
}
#else
static int mmap_vmcore(struct file *file, struct vm_area_struct *vma)
{
	return -ENOSYS;
}
#endif

static const struct file_operations proc_vmcore_operations = {
	.read		= read_vmcore,
	.llseek		= default_llseek,
	.mmap		= mmap_vmcore,
};

static struct vmcore* __init get_new_element(void)
{
	return kzalloc(sizeof(struct vmcore), GFP_KERNEL);
}

static u64 __init get_vmcore_size(size_t elfsz, size_t elfnotesegsz,
				  struct list_head *vc_list)
{
	u64 size;
	struct vmcore *m;

	size = elfsz + elfnotesegsz;
	list_for_each_entry(m, vc_list, list) {
		size += m->size;
	}
	return size;
}

/**
 * update_note_header_size_elf64 - update p_memsz member of each PT_NOTE entry
 *
 * @ehdr_ptr: ELF header
 *
 * This function updates p_memsz member of each PT_NOTE entry in the
 * program header table pointed to by @ehdr_ptr to real size of ELF
 * note segment.
 */
static int __init update_note_header_size_elf64(const Elf64_Ehdr *ehdr_ptr)
{
	int i, rc=0;
	Elf64_Phdr *phdr_ptr;
	Elf64_Nhdr *nhdr_ptr;

	phdr_ptr = (Elf64_Phdr *)(ehdr_ptr + 1);
	for (i = 0; i < ehdr_ptr->e_phnum; i++, phdr_ptr++) {
		void *notes_section;
		u64 offset, max_sz, sz, real_sz = 0;
		if (phdr_ptr->p_type != PT_NOTE)
			continue;
		max_sz = phdr_ptr->p_memsz;
		offset = phdr_ptr->p_offset;
		notes_section = kmalloc(max_sz, GFP_KERNEL);
		if (!notes_section)
			return -ENOMEM;
		rc = elfcorehdr_read_notes(notes_section, max_sz, &offset);
		if (rc < 0) {
			kfree(notes_section);
			return rc;
		}
		nhdr_ptr = notes_section;
		while (nhdr_ptr->n_namesz != 0) {
			sz = sizeof(Elf64_Nhdr) +
				((nhdr_ptr->n_namesz + 3) & ~3) +
				((nhdr_ptr->n_descsz + 3) & ~3);
			if ((real_sz + sz) > max_sz) {
				pr_warn("Warning: Exceeded p_memsz, dropping PT_NOTE entry n_namesz=0x%x, n_descsz=0x%x\n",
					nhdr_ptr->n_namesz, nhdr_ptr->n_descsz);
				break;
			}
			real_sz += sz;
			nhdr_ptr = (Elf64_Nhdr*)((char*)nhdr_ptr + sz);
		}
		kfree(notes_section);
		phdr_ptr->p_memsz = real_sz;
		if (real_sz == 0) {
			pr_warn("Warning: Zero PT_NOTE entries found\n");
		}
	}

	return 0;
}

/**
 * get_note_number_and_size_elf64 - get the number of PT_NOTE program
 * headers and sum of real size of their ELF note segment headers and
 * data.
 *
 * @ehdr_ptr: ELF header
 * @nr_ptnote: buffer for the number of PT_NOTE program headers
 * @sz_ptnote: buffer for size of unique PT_NOTE program header
 *
 * This function is used to merge multiple PT_NOTE program headers
 * into a unique single one. The resulting unique entry will have
 * @sz_ptnote in its phdr->p_mem.
 *
 * It is assumed that program headers with PT_NOTE type pointed to by
 * @ehdr_ptr has already been updated by update_note_header_size_elf64
 * and each of PT_NOTE program headers has actual ELF note segment
 * size in its p_memsz member.
 */
static int __init get_note_number_and_size_elf64(const Elf64_Ehdr *ehdr_ptr,
						 int *nr_ptnote, u64 *sz_ptnote)
{
	int i;
	Elf64_Phdr *phdr_ptr;

	*nr_ptnote = *sz_ptnote = 0;

	phdr_ptr = (Elf64_Phdr *)(ehdr_ptr + 1);
	for (i = 0; i < ehdr_ptr->e_phnum; i++, phdr_ptr++) {
		if (phdr_ptr->p_type != PT_NOTE)
			continue;
		*nr_ptnote += 1;
		*sz_ptnote += phdr_ptr->p_memsz;
	}

	return 0;
}

/**
 * copy_notes_elf64 - copy ELF note segments in a given buffer
 *
 * @ehdr_ptr: ELF header
 * @notes_buf: buffer into which ELF note segments are copied
 *
 * This function is used to copy ELF note segment in the 1st kernel
 * into the buffer @notes_buf in the 2nd kernel. It is assumed that
 * size of the buffer @notes_buf is equal to or larger than sum of the
 * real ELF note segment headers and data.
 *
 * It is assumed that program headers with PT_NOTE type pointed to by
 * @ehdr_ptr has already been updated by update_note_header_size_elf64
 * and each of PT_NOTE program headers has actual ELF note segment
 * size in its p_memsz member.
 */
static int __init copy_notes_elf64(const Elf64_Ehdr *ehdr_ptr, char *notes_buf)
{
	int i, rc=0;
	Elf64_Phdr *phdr_ptr;

	phdr_ptr = (Elf64_Phdr*)(ehdr_ptr + 1);

	for (i = 0; i < ehdr_ptr->e_phnum; i++, phdr_ptr++) {
		u64 offset;
		if (phdr_ptr->p_type != PT_NOTE)
			continue;
		offset = phdr_ptr->p_offset;
		rc = elfcorehdr_read_notes(notes_buf, phdr_ptr->p_memsz,
					   &offset);
		if (rc < 0)
			return rc;
		notes_buf += phdr_ptr->p_memsz;
	}

	return 0;
}

/* Merges all the PT_NOTE headers into one. */
static int __init merge_note_headers_elf64(char *elfptr, size_t *elfsz,
					   char **notes_buf, size_t *notes_sz)
{
	int i, nr_ptnote=0, rc=0;
	char *tmp;
	Elf64_Ehdr *ehdr_ptr;
	Elf64_Phdr phdr;
	u64 phdr_sz = 0, note_off;

	ehdr_ptr = (Elf64_Ehdr *)elfptr;

	rc = update_note_header_size_elf64(ehdr_ptr);
	if (rc < 0)
		return rc;

	rc = get_note_number_and_size_elf64(ehdr_ptr, &nr_ptnote, &phdr_sz);
	if (rc < 0)
		return rc;

	*notes_sz = roundup(phdr_sz, PAGE_SIZE);
	*notes_buf = alloc_elfnotes_buf(*notes_sz);
	if (!*notes_buf)
		return -ENOMEM;

	rc = copy_notes_elf64(ehdr_ptr, *notes_buf);
	if (rc < 0)
		return rc;

	/* Prepare merged PT_NOTE program header. */
	phdr.p_type    = PT_NOTE;
	phdr.p_flags   = 0;
	note_off = sizeof(Elf64_Ehdr) +
			(ehdr_ptr->e_phnum - nr_ptnote +1) * sizeof(Elf64_Phdr);
	phdr.p_offset  = roundup(note_off, PAGE_SIZE);
	phdr.p_vaddr   = phdr.p_paddr = 0;
	phdr.p_filesz  = phdr.p_memsz = phdr_sz;
	phdr.p_align   = 0;

	/* Add merged PT_NOTE program header*/
	tmp = elfptr + sizeof(Elf64_Ehdr);
	memcpy(tmp, &phdr, sizeof(phdr));
	tmp += sizeof(phdr);

	/* Remove unwanted PT_NOTE program headers. */
	i = (nr_ptnote - 1) * sizeof(Elf64_Phdr);
	*elfsz = *elfsz - i;
	memmove(tmp, tmp+i, ((*elfsz)-sizeof(Elf64_Ehdr)-sizeof(Elf64_Phdr)));
	memset(elfptr + *elfsz, 0, i);
	*elfsz = roundup(*elfsz, PAGE_SIZE);

	/* Modify e_phnum to reflect merged headers. */
	ehdr_ptr->e_phnum = ehdr_ptr->e_phnum - nr_ptnote + 1;

	return 0;
}

/**
 * update_note_header_size_elf32 - update p_memsz member of each PT_NOTE entry
 *
 * @ehdr_ptr: ELF header
 *
 * This function updates p_memsz member of each PT_NOTE entry in the
 * program header table pointed to by @ehdr_ptr to real size of ELF
 * note segment.
 */
static int __init update_note_header_size_elf32(const Elf32_Ehdr *ehdr_ptr)
{
	int i, rc=0;
	Elf32_Phdr *phdr_ptr;
	Elf32_Nhdr *nhdr_ptr;

	phdr_ptr = (Elf32_Phdr *)(ehdr_ptr + 1);
	for (i = 0; i < ehdr_ptr->e_phnum; i++, phdr_ptr++) {
		void *notes_section;
		u64 offset, max_sz, sz, real_sz = 0;
		if (phdr_ptr->p_type != PT_NOTE)
			continue;
		max_sz = phdr_ptr->p_memsz;
		offset = phdr_ptr->p_offset;
		notes_section = kmalloc(max_sz, GFP_KERNEL);
		if (!notes_section)
			return -ENOMEM;
		rc = elfcorehdr_read_notes(notes_section, max_sz, &offset);
		if (rc < 0) {
			kfree(notes_section);
			return rc;
		}
		nhdr_ptr = notes_section;
		while (nhdr_ptr->n_namesz != 0) {
			sz = sizeof(Elf32_Nhdr) +
				((nhdr_ptr->n_namesz + 3) & ~3) +
				((nhdr_ptr->n_descsz + 3) & ~3);
			if ((real_sz + sz) > max_sz) {
				pr_warn("Warning: Exceeded p_memsz, dropping PT_NOTE entry n_namesz=0x%x, n_descsz=0x%x\n",
					nhdr_ptr->n_namesz, nhdr_ptr->n_descsz);
				break;
			}
			real_sz += sz;
			nhdr_ptr = (Elf32_Nhdr*)((char*)nhdr_ptr + sz);
		}
		kfree(notes_section);
		phdr_ptr->p_memsz = real_sz;
		if (real_sz == 0) {
			pr_warn("Warning: Zero PT_NOTE entries found\n");
		}
	}

	return 0;
}

/**
 * get_note_number_and_size_elf32 - get the number of PT_NOTE program
 * headers and sum of real size of their ELF note segment headers and
 * data.
 *
 * @ehdr_ptr: ELF header
 * @nr_ptnote: buffer for the number of PT_NOTE program headers
 * @sz_ptnote: buffer for size of unique PT_NOTE program header
 *
 * This function is used to merge multiple PT_NOTE program headers
 * into a unique single one. The resulting unique entry will have
 * @sz_ptnote in its phdr->p_mem.
 *
 * It is assumed that program headers with PT_NOTE type pointed to by
 * @ehdr_ptr has already been updated by update_note_header_size_elf32
 * and each of PT_NOTE program headers has actual ELF note segment
 * size in its p_memsz member.
 */
static int __init get_note_number_and_size_elf32(const Elf32_Ehdr *ehdr_ptr,
						 int *nr_ptnote, u64 *sz_ptnote)
{
	int i;
	Elf32_Phdr *phdr_ptr;

	*nr_ptnote = *sz_ptnote = 0;

	phdr_ptr = (Elf32_Phdr *)(ehdr_ptr + 1);
	for (i = 0; i < ehdr_ptr->e_phnum; i++, phdr_ptr++) {
		if (phdr_ptr->p_type != PT_NOTE)
			continue;
		*nr_ptnote += 1;
		*sz_ptnote += phdr_ptr->p_memsz;
	}

	return 0;
}

/**
 * copy_notes_elf32 - copy ELF note segments in a given buffer
 *
 * @ehdr_ptr: ELF header
 * @notes_buf: buffer into which ELF note segments are copied
 *
 * This function is used to copy ELF note segment in the 1st kernel
 * into the buffer @notes_buf in the 2nd kernel. It is assumed that
 * size of the buffer @notes_buf is equal to or larger than sum of the
 * real ELF note segment headers and data.
 *
 * It is assumed that program headers with PT_NOTE type pointed to by
 * @ehdr_ptr has already been updated by update_note_header_size_elf32
 * and each of PT_NOTE program headers has actual ELF note segment
 * size in its p_memsz member.
 */
static int __init copy_notes_elf32(const Elf32_Ehdr *ehdr_ptr, char *notes_buf)
{
	int i, rc=0;
	Elf32_Phdr *phdr_ptr;

	phdr_ptr = (Elf32_Phdr*)(ehdr_ptr + 1);

	for (i = 0; i < ehdr_ptr->e_phnum; i++, phdr_ptr++) {
		u64 offset;
		if (phdr_ptr->p_type != PT_NOTE)
			continue;
		offset = phdr_ptr->p_offset;
		rc = elfcorehdr_read_notes(notes_buf, phdr_ptr->p_memsz,
					   &offset);
		if (rc < 0)
			return rc;
		notes_buf += phdr_ptr->p_memsz;
	}

	return 0;
}

/* Merges all the PT_NOTE headers into one. */
static int __init merge_note_headers_elf32(char *elfptr, size_t *elfsz,
					   char **notes_buf, size_t *notes_sz)
{
	int i, nr_ptnote=0, rc=0;
	char *tmp;
	Elf32_Ehdr *ehdr_ptr;
	Elf32_Phdr phdr;
	u64 phdr_sz = 0, note_off;

	ehdr_ptr = (Elf32_Ehdr *)elfptr;

	rc = update_note_header_size_elf32(ehdr_ptr);
	if (rc < 0)
		return rc;

	rc = get_note_number_and_size_elf32(ehdr_ptr, &nr_ptnote, &phdr_sz);
	if (rc < 0)
		return rc;

	*notes_sz = roundup(phdr_sz, PAGE_SIZE);
	*notes_buf = alloc_elfnotes_buf(*notes_sz);
	if (!*notes_buf)
		return -ENOMEM;

	rc = copy_notes_elf32(ehdr_ptr, *notes_buf);
	if (rc < 0)
		return rc;

	/* Prepare merged PT_NOTE program header. */
	phdr.p_type    = PT_NOTE;
	phdr.p_flags   = 0;
	note_off = sizeof(Elf32_Ehdr) +
			(ehdr_ptr->e_phnum - nr_ptnote +1) * sizeof(Elf32_Phdr);
	phdr.p_offset  = roundup(note_off, PAGE_SIZE);
	phdr.p_vaddr   = phdr.p_paddr = 0;
	phdr.p_filesz  = phdr.p_memsz = phdr_sz;
	phdr.p_align   = 0;

	/* Add merged PT_NOTE program header*/
	tmp = elfptr + sizeof(Elf32_Ehdr);
	memcpy(tmp, &phdr, sizeof(phdr));
	tmp += sizeof(phdr);

	/* Remove unwanted PT_NOTE program headers. */
	i = (nr_ptnote - 1) * sizeof(Elf32_Phdr);
	*elfsz = *elfsz - i;
	memmove(tmp, tmp+i, ((*elfsz)-sizeof(Elf32_Ehdr)-sizeof(Elf32_Phdr)));
	memset(elfptr + *elfsz, 0, i);
	*elfsz = roundup(*elfsz, PAGE_SIZE);

	/* Modify e_phnum to reflect merged headers. */
	ehdr_ptr->e_phnum = ehdr_ptr->e_phnum - nr_ptnote + 1;

	return 0;
}

/* Add memory chunks represented by program headers to vmcore list. Also update
 * the new offset fields of exported program headers. */
static int __init process_ptload_program_headers_elf64(char *elfptr,
						size_t elfsz,
						size_t elfnotes_sz,
						struct list_head *vc_list)
{
	int i;
	Elf64_Ehdr *ehdr_ptr;
	Elf64_Phdr *phdr_ptr;
	loff_t vmcore_off;
	struct vmcore *new;

	ehdr_ptr = (Elf64_Ehdr *)elfptr;
	phdr_ptr = (Elf64_Phdr*)(elfptr + sizeof(Elf64_Ehdr)); /* PT_NOTE hdr */

	/* Skip Elf header, program headers and Elf note segment. */
	vmcore_off = elfsz + elfnotes_sz;

	for (i = 0; i < ehdr_ptr->e_phnum; i++, phdr_ptr++) {
		u64 paddr, start, end, size;

		if (phdr_ptr->p_type != PT_LOAD)
			continue;

		paddr = phdr_ptr->p_offset;
		start = rounddown(paddr, PAGE_SIZE);
		end = roundup(paddr + phdr_ptr->p_memsz, PAGE_SIZE);
		size = end - start;

		/* Add this contiguous chunk of memory to vmcore list.*/
		new = get_new_element();
		if (!new)
			return -ENOMEM;
		new->paddr = start;
		new->size = size;
		list_add_tail(&new->list, vc_list);

		/* Update the program header offset. */
		phdr_ptr->p_offset = vmcore_off + (paddr - start);
		vmcore_off = vmcore_off + size;
	}
	return 0;
}

static int __init process_ptload_program_headers_elf32(char *elfptr,
						size_t elfsz,
						size_t elfnotes_sz,
						struct list_head *vc_list)
{
	int i;
	Elf32_Ehdr *ehdr_ptr;
	Elf32_Phdr *phdr_ptr;
	loff_t vmcore_off;
	struct vmcore *new;

	ehdr_ptr = (Elf32_Ehdr *)elfptr;
	phdr_ptr = (Elf32_Phdr*)(elfptr + sizeof(Elf32_Ehdr)); /* PT_NOTE hdr */

	/* Skip Elf header, program headers and Elf note segment. */
	vmcore_off = elfsz + elfnotes_sz;

	for (i = 0; i < ehdr_ptr->e_phnum; i++, phdr_ptr++) {
		u64 paddr, start, end, size;

		if (phdr_ptr->p_type != PT_LOAD)
			continue;

		paddr = phdr_ptr->p_offset;
		start = rounddown(paddr, PAGE_SIZE);
		end = roundup(paddr + phdr_ptr->p_memsz, PAGE_SIZE);
		size = end - start;

		/* Add this contiguous chunk of memory to vmcore list.*/
		new = get_new_element();
		if (!new)
			return -ENOMEM;
		new->paddr = start;
		new->size = size;
		list_add_tail(&new->list, vc_list);

		/* Update the program header offset */
		phdr_ptr->p_offset = vmcore_off + (paddr - start);
		vmcore_off = vmcore_off + size;
	}
	return 0;
}

/* Sets offset fields of vmcore elements. */
static void __init set_vmcore_list_offsets(size_t elfsz, size_t elfnotes_sz,
					   struct list_head *vc_list)
{
	loff_t vmcore_off;
	struct vmcore *m;

	/* Skip Elf header, program headers and Elf note segment. */
	vmcore_off = elfsz + elfnotes_sz;

	list_for_each_entry(m, vc_list, list) {
		m->offset = vmcore_off;
		vmcore_off += m->size;
	}
}

static void free_elfcorebuf(void)
{
	free_pages((unsigned long)elfcorebuf, get_order(elfcorebuf_sz_orig));
	elfcorebuf = NULL;
	vfree(elfnotes_buf);
	elfnotes_buf = NULL;
}

static int __init parse_crash_elf64_headers(void)
{
	int rc=0;
	Elf64_Ehdr ehdr;
	u64 addr;

	addr = elfcorehdr_addr;

	/* Read Elf header */
	rc = elfcorehdr_read((char *)&ehdr, sizeof(Elf64_Ehdr), &addr);
	if (rc < 0)
		return rc;

	/* Do some basic Verification. */
	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
		(ehdr.e_type != ET_CORE) ||
		!vmcore_elf64_check_arch(&ehdr) ||
		ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
		ehdr.e_ident[EI_VERSION] != EV_CURRENT ||
		ehdr.e_version != EV_CURRENT ||
		ehdr.e_ehsize != sizeof(Elf64_Ehdr) ||
		ehdr.e_phentsize != sizeof(Elf64_Phdr) ||
		ehdr.e_phnum == 0) {
		pr_warn("Warning: Core image elf header is not sane\n");
		return -EINVAL;
	}

	/* Read in all elf headers. */
	elfcorebuf_sz_orig = sizeof(Elf64_Ehdr) +
				ehdr.e_phnum * sizeof(Elf64_Phdr);
	elfcorebuf_sz = elfcorebuf_sz_orig;
	elfcorebuf = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
					      get_order(elfcorebuf_sz_orig));
	if (!elfcorebuf)
		return -ENOMEM;
	addr = elfcorehdr_addr;
	rc = elfcorehdr_read(elfcorebuf, elfcorebuf_sz_orig, &addr);
	if (rc < 0)
		goto fail;

	/* Merge all PT_NOTE headers into one. */
	rc = merge_note_headers_elf64(elfcorebuf, &elfcorebuf_sz,
				      &elfnotes_buf, &elfnotes_sz);
	if (rc)
		goto fail;
	rc = process_ptload_program_headers_elf64(elfcorebuf, elfcorebuf_sz,
						  elfnotes_sz, &vmcore_list);
	if (rc)
		goto fail;
	set_vmcore_list_offsets(elfcorebuf_sz, elfnotes_sz, &vmcore_list);
	return 0;
fail:
	free_elfcorebuf();
	return rc;
}

static int __init parse_crash_elf32_headers(void)
{
	int rc=0;
	Elf32_Ehdr ehdr;
	u64 addr;

	addr = elfcorehdr_addr;

	/* Read Elf header */
	rc = elfcorehdr_read((char *)&ehdr, sizeof(Elf32_Ehdr), &addr);
	if (rc < 0)
		return rc;

	/* Do some basic Verification. */
	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
		(ehdr.e_type != ET_CORE) ||
		!elf_check_arch(&ehdr) ||
		ehdr.e_ident[EI_CLASS] != ELFCLASS32||
		ehdr.e_ident[EI_VERSION] != EV_CURRENT ||
		ehdr.e_version != EV_CURRENT ||
		ehdr.e_ehsize != sizeof(Elf32_Ehdr) ||
		ehdr.e_phentsize != sizeof(Elf32_Phdr) ||
		ehdr.e_phnum == 0) {
		pr_warn("Warning: Core image elf header is not sane\n");
		return -EINVAL;
	}

	/* Read in all elf headers. */
	elfcorebuf_sz_orig = sizeof(Elf32_Ehdr) + ehdr.e_phnum * sizeof(Elf32_Phdr);
	elfcorebuf_sz = elfcorebuf_sz_orig;
	elfcorebuf = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
					      get_order(elfcorebuf_sz_orig));
	if (!elfcorebuf)
		return -ENOMEM;
	addr = elfcorehdr_addr;
	rc = elfcorehdr_read(elfcorebuf, elfcorebuf_sz_orig, &addr);
	if (rc < 0)
		goto fail;

	/* Merge all PT_NOTE headers into one. */
	rc = merge_note_headers_elf32(elfcorebuf, &elfcorebuf_sz,
				      &elfnotes_buf, &elfnotes_sz);
	if (rc)
		goto fail;
	rc = process_ptload_program_headers_elf32(elfcorebuf, elfcorebuf_sz,
						  elfnotes_sz, &vmcore_list);
	if (rc)
		goto fail;
	set_vmcore_list_offsets(elfcorebuf_sz, elfnotes_sz, &vmcore_list);
	return 0;
fail:
	free_elfcorebuf();
	return rc;
}

static int __init parse_crash_elf_headers(void)
{
	unsigned char e_ident[EI_NIDENT];
	u64 addr;
	int rc=0;

	addr = elfcorehdr_addr;
	rc = elfcorehdr_read(e_ident, EI_NIDENT, &addr);
	if (rc < 0)
		return rc;
	if (memcmp(e_ident, ELFMAG, SELFMAG) != 0) {
		pr_warn("Warning: Core image elf header not found\n");
		return -EINVAL;
	}

	if (e_ident[EI_CLASS] == ELFCLASS64) {
		rc = parse_crash_elf64_headers();
		if (rc)
			return rc;
	} else if (e_ident[EI_CLASS] == ELFCLASS32) {
		rc = parse_crash_elf32_headers();
		if (rc)
			return rc;
	} else {
		pr_warn("Warning: Core image elf header is not sane\n");
		return -EINVAL;
	}

	/* Determine vmcore size. */
	vmcore_size = get_vmcore_size(elfcorebuf_sz, elfnotes_sz,
				      &vmcore_list);

	return 0;
}

/* Init function for vmcore module. */
static int __init vmcore_init(void)
{
	int rc = 0;

	/* Allow architectures to allocate ELF header in 2nd kernel */
	rc = elfcorehdr_alloc(&elfcorehdr_addr, &elfcorehdr_size);
	if (rc)
		return rc;
	/*
	 * If elfcorehdr= has been passed in cmdline or created in 2nd kernel,
	 * then capture the dump.
	 */
	if (!(is_vmcore_usable()))
		return rc;
	rc = parse_crash_elf_headers();
	if (rc) {
		pr_warn("Kdump: vmcore not initialized\n");
		return rc;
	}
	elfcorehdr_free(elfcorehdr_addr);
	elfcorehdr_addr = ELFCORE_ADDR_ERR;

	proc_vmcore = proc_create("vmcore", S_IRUSR, NULL, &proc_vmcore_operations);
	if (proc_vmcore)
		proc_vmcore->size = vmcore_size;
	return 0;
}
fs_initcall(vmcore_init);

/* Cleanup function for vmcore module. */
void vmcore_cleanup(void)
{
	struct list_head *pos, *next;

	if (proc_vmcore) {
		proc_remove(proc_vmcore);
		proc_vmcore = NULL;
	}

	/* clear the vmcore list. */
	list_for_each_safe(pos, next, &vmcore_list) {
		struct vmcore *m;

		m = list_entry(pos, struct vmcore, list);
		list_del(&m->list);
		kfree(m);
	}
	free_elfcorebuf();
}
/************************************************************/
/* ../linux-3.17/fs/proc/vmcore.c */
/************************************************************/
/*
 *  linux/fs/proc/kmsg.c
 *
 *  Copyright (C) 1992  by Linus Torvalds
 *
 */

// #include <linux/types.h>
// #include <linux/errno.h>
// #include <linux/time.h>
// #include <linux/kernel.h>
// #include <linux/poll.h>
// #include <linux/proc_fs.h>
// #include <linux/fs.h>
#include <linux/syslog.h>

// #include <asm/uaccess.h>
// #include <asm/io.h>

extern wait_queue_head_t log_wait;

static int kmsg_open(struct inode * inode, struct file * file)
{
	return do_syslog(SYSLOG_ACTION_OPEN, NULL, 0, SYSLOG_FROM_PROC);
}

static int kmsg_release(struct inode * inode, struct file * file)
{
	(void) do_syslog(SYSLOG_ACTION_CLOSE, NULL, 0, SYSLOG_FROM_PROC);
	return 0;
}

static ssize_t kmsg_read(struct file *file, char __user *buf,
			 size_t count, loff_t *ppos)
{
	if ((file->f_flags & O_NONBLOCK) &&
	    !do_syslog(SYSLOG_ACTION_SIZE_UNREAD, NULL, 0, SYSLOG_FROM_PROC))
		return -EAGAIN;
	return do_syslog(SYSLOG_ACTION_READ, buf, count, SYSLOG_FROM_PROC);
}

static unsigned int kmsg_poll(struct file *file, poll_table *wait)
{
	poll_wait(file, &log_wait, wait);
	if (do_syslog(SYSLOG_ACTION_SIZE_UNREAD, NULL, 0, SYSLOG_FROM_PROC))
		return POLLIN | POLLRDNORM;
	return 0;
}


static const struct file_operations proc_kmsg_operations = {
	.read		= kmsg_read,
	.poll		= kmsg_poll,
	.open		= kmsg_open,
	.release	= kmsg_release,
	.llseek		= generic_file_llseek,
};

static int __init proc_kmsg_init(void)
{
	proc_create("kmsg", S_IRUSR, NULL, &proc_kmsg_operations);
	return 0;
}
fs_initcall(proc_kmsg_init);
/************************************************************/
/* ../linux-3.17/fs/proc/kmsg.c */
/************************************************************/
// #include <linux/bootmem.h>
#include <linux/compiler.h>
// #include <linux/fs.h>
// #include <linux/init.h>
#include <linux/ksm.h>
// #include <linux/mm.h>
// #include <linux/mmzone.h>
// #include <linux/proc_fs.h>
// #include <linux/seq_file.h>
// #include <linux/hugetlb.h>
#include <linux/kernel-page-flags.h>
// #include <asm/uaccess.h>
// #include "internal.h"

#define KPMSIZE sizeof(u64)
#define KPMMASK (KPMSIZE - 1)

/* /proc/kpagecount - an array exposing page counts
 *
 * Each entry is a u64 representing the corresponding
 * physical page count.
 */
static ssize_t kpagecount_read(struct file *file, char __user *buf,
			     size_t count, loff_t *ppos)
{
	u64 __user *out = (u64 __user *)buf;
	struct page *ppage;
	unsigned long src = *ppos;
	unsigned long pfn;
	ssize_t ret = 0;
	u64 pcount;

	pfn = src / KPMSIZE;
	count = min_t(size_t, count, (max_pfn * KPMSIZE) - src);
	if (src & KPMMASK || count & KPMMASK)
		return -EINVAL;

	while (count > 0) {
		if (pfn_valid(pfn))
			ppage = pfn_to_page(pfn);
		else
			ppage = NULL;
		if (!ppage || PageSlab(ppage))
			pcount = 0;
		else
			pcount = page_mapcount(ppage);

		if (put_user(pcount, out)) {
			ret = -EFAULT;
			break;
		}

		pfn++;
		out++;
		count -= KPMSIZE;
	}

	*ppos += (char __user *)out - buf;
	if (!ret)
		ret = (char __user *)out - buf;
	return ret;
}

static const struct file_operations proc_kpagecount_operations = {
	.llseek = mem_lseek,
	.read = kpagecount_read,
};

/* /proc/kpageflags - an array exposing page flags
 *
 * Each entry is a u64 representing the corresponding
 * physical page flags.
 */

static inline u64 kpf_copy_bit(u64 kflags, int ubit, int kbit)
{
	return ((kflags >> kbit) & 1) << ubit;
}

u64 stable_page_flags(struct page *page)
{
	u64 k;
	u64 u;

	/*
	 * pseudo flag: KPF_NOPAGE
	 * it differentiates a memory hole from a page with no flags
	 */
	if (!page)
		return 1 << KPF_NOPAGE;

	k = page->flags;
	u = 0;

	/*
	 * pseudo flags for the well known (anonymous) memory mapped pages
	 *
	 * Note that page->_mapcount is overloaded in SLOB/SLUB/SLQB, so the
	 * simple test in page_mapped() is not enough.
	 */
	if (!PageSlab(page) && page_mapped(page))
		u |= 1 << KPF_MMAP;
	if (PageAnon(page))
		u |= 1 << KPF_ANON;
	if (PageKsm(page))
		u |= 1 << KPF_KSM;

	/*
	 * compound pages: export both head/tail info
	 * they together define a compound page's start/end pos and order
	 */
	if (PageHead(page))
		u |= 1 << KPF_COMPOUND_HEAD;
	if (PageTail(page))
		u |= 1 << KPF_COMPOUND_TAIL;
	if (PageHuge(page))
		u |= 1 << KPF_HUGE;
	/*
	 * PageTransCompound can be true for non-huge compound pages (slab
	 * pages or pages allocated by drivers with __GFP_COMP) because it
	 * just checks PG_head/PG_tail, so we need to check PageLRU/PageAnon
	 * to make sure a given page is a thp, not a non-huge compound page.
	 */
	else if (PageTransCompound(page) && (PageLRU(compound_head(page)) ||
					     PageAnon(compound_head(page))))
		u |= 1 << KPF_THP;

	/*
	 * Caveats on high order pages: page->_count will only be set
	 * -1 on the head page; SLUB/SLQB do the same for PG_slab;
	 * SLOB won't set PG_slab at all on compound pages.
	 */
	if (PageBuddy(page))
		u |= 1 << KPF_BUDDY;

	u |= kpf_copy_bit(k, KPF_LOCKED,	PG_locked);

	u |= kpf_copy_bit(k, KPF_SLAB,		PG_slab);

	u |= kpf_copy_bit(k, KPF_ERROR,		PG_error);
	u |= kpf_copy_bit(k, KPF_DIRTY,		PG_dirty);
	u |= kpf_copy_bit(k, KPF_UPTODATE,	PG_uptodate);
	u |= kpf_copy_bit(k, KPF_WRITEBACK,	PG_writeback);

	u |= kpf_copy_bit(k, KPF_LRU,		PG_lru);
	u |= kpf_copy_bit(k, KPF_REFERENCED,	PG_referenced);
	u |= kpf_copy_bit(k, KPF_ACTIVE,	PG_active);
	u |= kpf_copy_bit(k, KPF_RECLAIM,	PG_reclaim);

	u |= kpf_copy_bit(k, KPF_SWAPCACHE,	PG_swapcache);
	u |= kpf_copy_bit(k, KPF_SWAPBACKED,	PG_swapbacked);

	u |= kpf_copy_bit(k, KPF_UNEVICTABLE,	PG_unevictable);
	u |= kpf_copy_bit(k, KPF_MLOCKED,	PG_mlocked);

#ifdef CONFIG_MEMORY_FAILURE
	u |= kpf_copy_bit(k, KPF_HWPOISON,	PG_hwpoison);
#endif

#ifdef CONFIG_ARCH_USES_PG_UNCACHED
	u |= kpf_copy_bit(k, KPF_UNCACHED,	PG_uncached);
#endif

	u |= kpf_copy_bit(k, KPF_RESERVED,	PG_reserved);
	u |= kpf_copy_bit(k, KPF_MAPPEDTODISK,	PG_mappedtodisk);
	u |= kpf_copy_bit(k, KPF_PRIVATE,	PG_private);
	u |= kpf_copy_bit(k, KPF_PRIVATE_2,	PG_private_2);
	u |= kpf_copy_bit(k, KPF_OWNER_PRIVATE,	PG_owner_priv_1);
	u |= kpf_copy_bit(k, KPF_ARCH,		PG_arch_1);

	return u;
};

static ssize_t kpageflags_read(struct file *file, char __user *buf,
			     size_t count, loff_t *ppos)
{
	u64 __user *out = (u64 __user *)buf;
	struct page *ppage;
	unsigned long src = *ppos;
	unsigned long pfn;
	ssize_t ret = 0;

	pfn = src / KPMSIZE;
	count = min_t(unsigned long, count, (max_pfn * KPMSIZE) - src);
	if (src & KPMMASK || count & KPMMASK)
		return -EINVAL;

	while (count > 0) {
		if (pfn_valid(pfn))
			ppage = pfn_to_page(pfn);
		else
			ppage = NULL;

		if (put_user(stable_page_flags(ppage), out)) {
			ret = -EFAULT;
			break;
		}

		pfn++;
		out++;
		count -= KPMSIZE;
	}

	*ppos += (char __user *)out - buf;
	if (!ret)
		ret = (char __user *)out - buf;
	return ret;
}

static const struct file_operations proc_kpageflags_operations = {
	.llseek = mem_lseek,
	.read = kpageflags_read,
};

static int __init proc_page_init(void)
{
	proc_create("kpagecount", S_IRUSR, NULL, &proc_kpagecount_operations);
	proc_create("kpageflags", S_IRUSR, NULL, &proc_kpageflags_operations);
	return 0;
}
fs_initcall(proc_page_init);
/************************************************************/
/* ../linux-3.17/fs/proc/page.c */
/************************************************************/
