#include "linux/gfp.h"
#include "linux/mm_types.h"
#include "linux/mmap_lock.h"
#include "linux/page_ref.h"
#include "linux/sched/task.h"
#include "linux/spinlock_types.h"
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <asm/pgtable.h>
#include <linux/hugetlb.h>
#include <asm/tlbflush.h>

#ifdef CONFIG_X86
#include "asm/pgtable_64_types.h"
#endif

#define VIRT_ADDR_END (1UL << 48)
#define FAKE_SUCCESS 1
#define ENTRIES_PER_PAGE 512

struct pagetable_layout_info {
       uint32_t pgdir_shift;
       uint32_t p4d_shift;
       uint32_t pud_shift;
       uint32_t pmd_shift;
       uint32_t page_shift;
};

struct expose_pgtbl_args {
       unsigned long fake_pgd;
       unsigned long fake_p4ds;
       unsigned long fake_puds;
       unsigned long fake_pmds;
       unsigned long page_table_addr;
       unsigned long begin_vaddr;
       unsigned long end_vaddr;
};

enum region_type {
       PGD_REGION,
       PUD_REGION,
       PMD_REGION,
       PGTBL_REGION
};

SYSCALL_DEFINE2(get_pagetable_layout,
		struct pagetable_layout_info __user *, pgtbl_info, int, size)
{
	static struct pagetable_layout_info kinfo = {
		.pgdir_shift = 0,
		.p4d_shift = P4D_SHIFT,
		.pud_shift = PUD_SHIFT,
		.pmd_shift = PMD_SHIFT,
		.page_shift = PAGE_SHIFT,
	};

	kinfo.pgdir_shift = PGDIR_SHIFT;
	if (!pgtbl_info || size < sizeof(struct pagetable_layout_info))
		return -EINVAL;
	if (copy_to_user(pgtbl_info, &kinfo, sizeof(kinfo)))
		return -EFAULT;
	return 0;
}

static inline size_t fake_pt_reserved_size(int shift, unsigned long va_begin,
					    unsigned long va_end)
{
	return ((va_end >> shift) - (va_begin >> shift) + 1) << PAGE_SHIFT;
}

/* Called with mm semaphore held. */
static int validate_vma_region(struct mm_struct *current_mm, unsigned long addr,
			       enum region_type type, size_t region_sz)
{
	struct vm_area_struct *vma = find_vma(current_mm, addr);

	if (!vma)
		return -EINVAL;
	if (vma->vm_end - addr < region_sz)
		return -EINVAL;
	if (type == PGTBL_REGION && vma->vm_flags & VM_WRITE)
		return -EINVAL;

	if (unlikely(addr != vma->vm_start)
			&& split_vma(current_mm, vma, addr, 1))
		return -EAGAIN;
	if (unlikely(addr + region_sz != vma->vm_end)
			&& split_vma(current_mm, vma, addr + region_sz, 0))
		return -EAGAIN;

	if (type == PGTBL_REGION)
		vma->vm_flags &= ~VM_MAYWRITE;

	vma->vm_flags |= VM_SPECIAL;
	return 0;
}

static struct task_struct *get_target_task(pid_t pid)
{
	struct task_struct *task;

	if (pid == 0 || pid < -1)
		return NULL;

	if (pid == -1)
		task = current;
	else {
		rcu_read_lock();
		task = find_task_by_vpid(pid);
		if (task)
			get_task_struct(task);
		rcu_read_unlock();
	}

	return task;
}

static int try_to_unmap_pte(struct mm_struct *mm, unsigned long dst)
{
	unsigned long pfn;
	struct page *page;
	pte_t *ptep;
	spinlock_t *ptl;
	int ret;

	ret = follow_pte(mm, dst, &ptep, &ptl);
	if (likely(ret)) {
		return 0;
	}

	pfn = pte_pfn(*ptep);
	if (pfn) {
		page = pfn_to_page(pfn);
		pte_clear(mm, dst, ptep);
		page_ref_dec(page);
	}
	spin_unlock(ptl);

	return 0;
}

static inline void fake_map_entry(unsigned long *map_base,
				  unsigned long index, unsigned long dst)
{
	map_base[index] = dst;
}

static int unmap_unused_region(unsigned long begin, unsigned long end)
{
	struct mm_struct *current_mm = current->mm;
	struct vm_area_struct *vma;
	int ret;

	mmap_write_lock(current_mm);
	vma = find_vma(current_mm, begin);
	if (unlikely(!vma)) {
		ret = -EINVAL;
		goto out;
	}
	vma->vm_flags &= ~VM_SPECIAL;
	ret = split_vma(current_mm, vma, begin, 0);
	if (ret)
		goto out;
	vma->vm_flags |= VM_SPECIAL;
	ret = do_munmap(current_mm, begin, end - begin, NULL);
out:
	mmap_write_unlock(current_mm);
	return ret;
}

static int expose_pte(unsigned long dst, unsigned long pfn)
{
	struct mm_struct *current_mm = current->mm;
	struct vm_area_struct *vma;
	int ret = 0;

	/* printk(KERN_ERR "%s: dst: %#lx pfn: %#lx\n", __func__, dst, pfn); */

	mmap_write_lock(current_mm);
	vma = find_vma(current_mm, dst);
	if (!vma)
		return -EINVAL;

	if (try_to_unmap_pte(current_mm, dst)) {
		ret = -EAGAIN;
		goto out;
	}

	ret = remap_pfn_range(vma, dst, pfn, PAGE_SIZE, vma->vm_page_prot);
	if (ret)
		goto out;

	flush_tlb_page(vma, dst);
	ret = FAKE_SUCCESS;

out:
	mmap_write_unlock(current_mm);
	return ret;
}

static int expose_pmd_range(struct mm_struct *target_mm,
			    pud_t *pudp,
			    unsigned long *fake_pmd_base,
			    unsigned long *cur_pgtbl_ptr,
			    unsigned long pgtbl_end,
			    unsigned long va_curr,
			    unsigned long va_end)
{
	unsigned long cur_pgtbl;
	int ret = 0;

	/* printk(KERN_ERR "%s: va: %#lx - %#lx\n", __func__, va_curr, va_end); */
	do {
		pmd_t *pmdp;
		unsigned long pfn;
		int index;
		cur_pgtbl = *cur_pgtbl_ptr;

		spin_lock(&target_mm->page_table_lock);
		pmdp = pmd_offset(pudp, va_curr);
		if (pmd_none(*pmdp) || (pmd_bad(*pmdp))
		    || pmd_huge(*pmdp) || pmd_trans_huge(*pmdp)) {
			va_curr = ((va_curr + PMD_SIZE) & PMD_MASK);
			spin_unlock(&target_mm->page_table_lock);
			continue;
		}
		spin_unlock(&target_mm->page_table_lock);

		pfn = (pmd_val(READ_ONCE(*pmdp)) & ((1UL << 48) - 1)) >> PAGE_SHIFT;
		ret = expose_pte(cur_pgtbl, pfn);
		if (ret < 0)
			goto out;

		if (ret == FAKE_SUCCESS) {
			index = pmd_index(va_curr);
			fake_map_entry(fake_pmd_base, index, cur_pgtbl);
			*cur_pgtbl_ptr = cur_pgtbl + PAGE_SIZE;
		}
		va_curr = ((va_curr + PMD_SIZE) & PMD_MASK);
	} while (va_curr <= va_end && cur_pgtbl < pgtbl_end);

out:
	return ret;
}

static int expose_pud_range(struct mm_struct *target_mm,
			    pgd_t *pgdp,
			    unsigned long *fake_pud_base,
			    unsigned long *cur_fake_pmd_ptr,
			    unsigned long fake_pmd_end,
			    unsigned long *cur_pgtbl_ptr,
			    unsigned long pgtbl_end,
			    unsigned long va_curr,
			    unsigned long va_end)
{
	unsigned long cur_fake_pmd;
	int ret = 0;

	/* printk(KERN_ERR "%s: va: %#lx - %#lx\n", __func__, va_curr, va_end); */
	do {
		pud_t *pudp;
		unsigned long *fake_pmd_base;
		unsigned long index;

		cur_fake_pmd = *cur_fake_pmd_ptr;
		fake_pmd_base = (void *)get_zeroed_page(GFP_KERNEL);
		if (!fake_pmd_base)
			return -ENOMEM;

		spin_lock(&target_mm->page_table_lock);
		pudp = pud_offset((p4d_t *)pgdp, va_curr);
		if (pud_none(*pudp) || pud_bad(*pudp)) {
			va_curr = (va_curr + PUD_SIZE) & PUD_MASK;
			spin_unlock(&target_mm->page_table_lock);
			continue;
		}
		spin_unlock(&target_mm->page_table_lock);

		ret = expose_pmd_range(target_mm, pudp, fake_pmd_base,
				       cur_pgtbl_ptr, pgtbl_end,
				       va_curr, va_end);
		if (ret < 0) {
			free_page((unsigned long)fake_pmd_base);
			goto out;
		}

		if (ret == FAKE_SUCCESS) {
			if (copy_to_user((void *)(cur_fake_pmd),
						fake_pmd_base, PAGE_SIZE)) {
				free_page((unsigned long)fake_pmd_base);
				return -EFAULT;
			}
			index = pud_index(va_curr);
			fake_map_entry(fake_pud_base, index, cur_fake_pmd);
			*cur_fake_pmd_ptr = cur_fake_pmd + PAGE_SIZE;
		}
		free_page((unsigned long)fake_pmd_base);

		va_curr = (va_curr + PUD_SIZE) & PUD_MASK;
	} while (va_curr <= va_end && *cur_fake_pmd_ptr < fake_pmd_end);

out:
	return ret;
}

static int expose_pgd_range(struct mm_struct *target_mm,
			    unsigned long *fake_pgd_base,
			    unsigned long *cur_fake_pud_ptr,
			    unsigned long fake_pud_end,
			    unsigned long *cur_fake_pmd_ptr,
			    unsigned long fake_pmd_end,
			    unsigned long *cur_pgtbl_ptr,
			    unsigned long pgtbl_end,
			    unsigned long va_curr,
			    unsigned long va_end)
{
	unsigned long cur_fake_pud;
	int ret = 0;

	/* printk(KERN_ERR "%s: va: %#lx - %#lx\n", __func__, va_curr, va_end); */

	do {
		pgd_t *pgdp;
		unsigned long *fake_pud_base;
		unsigned long index;

		cur_fake_pud = *cur_fake_pud_ptr;
		fake_pud_base = (void *)get_zeroed_page(GFP_KERNEL);
		if (!fake_pud_base)
			return -ENOMEM;

		spin_lock(&target_mm->page_table_lock);
		pgdp = pgd_offset(target_mm, va_curr);
		if (pgd_none(*pgdp) || pgd_bad(*pgdp)) {
			va_curr = (va_curr + PGDIR_SIZE) & PGDIR_MASK;
			spin_unlock(&target_mm->page_table_lock);
			continue;;
		}
		spin_unlock(&target_mm->page_table_lock);

		ret = expose_pud_range(target_mm, pgdp, fake_pud_base,
				       cur_fake_pmd_ptr, fake_pmd_end,
				       cur_pgtbl_ptr, pgtbl_end,
				       va_curr, va_end);
		if (ret < 0) {
			free_page((unsigned long)fake_pud_base);
			goto out;
		}

		if (ret == FAKE_SUCCESS) {
			if (copy_to_user((void *)(cur_fake_pud),
						fake_pud_base, PAGE_SIZE)) {
				free_page((unsigned long)fake_pud_base);
				return -EFAULT;
			}
			index = pgd_index(va_curr);
			fake_map_entry(fake_pgd_base, index, cur_fake_pud);
			*cur_fake_pud_ptr = cur_fake_pud + PAGE_SIZE;
		}
		free_page((unsigned long)fake_pud_base);

		va_curr = (va_curr + PGDIR_SIZE) & PGDIR_MASK;
	} while (va_curr <= va_end && *cur_fake_pud_ptr < fake_pud_end);

out:
	return ret;
}

static int expose_vm_region(struct mm_struct *target_mm,
			    const struct expose_pgtbl_args *kargs,
			    size_t p4d_sz, size_t pud_sz, size_t pmd_sz,
			    size_t pgtbl_sz)
{
	unsigned long cur_fake_pud = kargs->fake_puds;
	unsigned long fake_pud_end = kargs->fake_puds + pud_sz;
	unsigned long cur_fake_pmd = kargs->fake_pmds;
	unsigned long fake_pmd_end = kargs->fake_pmds + pmd_sz;
	unsigned long cur_pgtbl = kargs->page_table_addr;
	unsigned long pgtbl_end = kargs->page_table_addr + pgtbl_sz;
	unsigned long va_curr = kargs->begin_vaddr;
	unsigned long va_end = kargs->end_vaddr;
	unsigned long *fake_pgd_base;
	int ret;

	fake_pgd_base = (void *)get_zeroed_page(GFP_KERNEL);
	if (!fake_pgd_base)
		return -ENOMEM;

	ret = expose_pgd_range(target_mm, fake_pgd_base,
			       &cur_fake_pud, fake_pud_end,
			       &cur_fake_pmd, fake_pmd_end,
			       &cur_pgtbl, pgtbl_end,
			       va_curr, va_end);

	if (ret < 0)
		goto out;

	if (ret == FAKE_SUCCESS) {
		if (copy_to_user((void *)(kargs->fake_pgd),
					fake_pgd_base, PAGE_SIZE)) {
			ret = -EFAULT;
			goto out;
		}
		ret = 0;
	}

	if (cur_fake_pud < fake_pud_end) {
		ret = unmap_unused_region(cur_fake_pud, fake_pud_end);
		if (ret)
			goto out;
	}
	if (cur_fake_pmd < fake_pmd_end) {
		ret = unmap_unused_region(cur_fake_pmd, fake_pmd_end);
		if (ret)
			goto out;
	}
	if (cur_pgtbl < pgtbl_end)
		ret = unmap_unused_region(cur_pgtbl, pgtbl_end);

out:
	free_page((unsigned long)fake_pgd_base);
	return ret;
}

SYSCALL_DEFINE2(expose_page_table,
		pid_t, pid, struct expose_pgtbl_args __user *, args)
{
	struct mm_struct *target_mm, *current_mm;
	struct task_struct *target_task;
	struct expose_pgtbl_args kargs;
	size_t pud_sz, pmd_sz, pgtbl_sz;
	int ret;

	if (!args)
		return -EINVAL;
	if (copy_from_user(&kargs, args, sizeof(kargs)))
		return -EFAULT;

	if (!kargs.fake_pgd || !kargs.fake_puds || !kargs.fake_pmds
			|| !kargs.page_table_addr)
		return -EINVAL;
	if (kargs.fake_pgd & ~PAGE_MASK || kargs.fake_puds & ~PAGE_MASK
			|| kargs.fake_pmds & ~PAGE_MASK
			|| kargs.page_table_addr & ~PAGE_MASK)
		return -EINVAL;
	if (kargs.begin_vaddr > kargs.end_vaddr)
		return -EINVAL;
	if (kargs.end_vaddr > VIRT_ADDR_END)
		return -EINVAL;

	target_task = get_target_task(pid);
	if (!target_task)
		return -EINVAL;

	target_mm = get_task_mm(target_task);
	if (!target_mm) {
		ret = -EINVAL;
		goto out;
	}

	pud_sz = fake_pt_reserved_size(PGDIR_SHIFT, kargs.begin_vaddr, kargs.end_vaddr);
	pmd_sz = fake_pt_reserved_size(PUD_SHIFT, kargs.begin_vaddr, kargs.end_vaddr);
	pgtbl_sz = fake_pt_reserved_size(PMD_SHIFT, kargs.begin_vaddr, kargs.end_vaddr);

	current_mm = current->mm;
	mmap_write_lock(current_mm);
	ret = validate_vma_region(current_mm, kargs.fake_pgd,
				  PGD_REGION, PAGE_SIZE);
	if (ret)
		goto out_sem;
	ret = validate_vma_region(current_mm, kargs.fake_puds,
				  PUD_REGION, pud_sz);
	if (ret)
		goto out_sem;
	ret = validate_vma_region(current_mm, kargs.fake_pmds,
				  PMD_REGION, pmd_sz);
	if (ret)
		goto out_sem;
	ret = validate_vma_region(current_mm, kargs.page_table_addr,
				  PGTBL_REGION, pgtbl_sz);
	if (ret)
		goto out_sem;
	mmap_write_unlock(current_mm);

	ret = expose_vm_region(target_mm, &kargs, pud_sz,
			       pud_sz, pmd_sz, pgtbl_sz);
	mmput(target_mm);

out:
	if (target_task != current)
		put_task_struct(target_task);
	return ret;
out_sem:
	mmap_write_unlock(current_mm);
	return ret;
}

SYSCALL_DEFINE1(get_pa_contents, long, phys_addr)
{
	char *addr = (char *)__va(phys_addr);

	return *addr;
}
