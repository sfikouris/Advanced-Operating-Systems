#include <types.h>
#include <paging.h>

#include <kernel/mem.h>

struct boot_map_info {
	struct page_table *pml4;
	uint64_t flags;
	physaddr_t pa;
	uintptr_t base, end;
};

/* Stores the physical address and the appropriate permissions into the PTE and
 * increments the physical address to point to the next page.
 */
static int boot_map_pte(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	/* LAB 2: your code here. */
	struct boot_map_info *info = walker->udata;
	*entry = (physaddr_t) info->pa | info->flags;
	info->pa+=PAGE_SIZE;
	return 0;
}

/* Stores the physical address and the appropriate permissions into the PDE and
 * increments the physical address to point to the next huge page if the
 * physical address is huge page aligned and if the area to be mapped covers a
 * 2M area. Otherwise this function calls ptbl_split() to split down the huge
 * page or allocate a page table.
 */
static int boot_map_pde(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	struct boot_map_info *info = walker->udata;

	/* LAB 2: your code here. */
	*entry = (physaddr_t) info->pa | info->flags;
	info->pa+=PAGE_SIZE;
	return 0;
}

/*
 * Maps the virtual address space at [va, va + size) to the contiguous physical
 * address space at [pa, pa + size). Size is a multiple of PAGE_SIZE. The
 * permissions of the page to set are passed through the flags argument.
 *
 * This function is only intended to set up static mappings. As such, it should
 * not change the reference counts of the mapped pages.
 *
 * Hint: this function calls walk_page_range().
 */
void boot_map_region(struct page_table *pml4, void *va, size_t size,
    physaddr_t pa, uint64_t flags)
{
	/* LAB 2: your code here. */
	struct boot_map_info info = {
		.pa = pa,
		.flags = flags,
		.base = ROUNDDOWN((uintptr_t)va, PAGE_SIZE),
		.end = ROUNDUP((uintptr_t)va + size, PAGE_SIZE) - 1,
	};
	struct page_walker walker = {
		.get_pte = boot_map_pte,
		.get_pde = ptbl_alloc,
		.get_pdpte = ptbl_alloc,
		.get_pml4e = ptbl_alloc,
		.udata = &info,
	};

	walk_page_range(pml4, (void*)(info.base), (void *)(info.end), &walker);
}

/* Creates a mapping in the MMIO region to [pa, pa + size) for
 * memory-mapped I/O.
 */
void *mmio_map_region(physaddr_t pa, size_t size)
{
	static uintptr_t base = MMIO_BASE;
	void *ret;

	size = ROUNDUP(size, PAGE_SIZE);
	assert(base + size < MMIO_LIM);

	ret = (void *)base;
	boot_map_region(kernel_pml4, ret, size, pa, PAGE_PRESENT |
		PAGE_WRITE | PAGE_NO_EXEC | PAGE_WRITE_THROUGH | PAGE_NO_CACHE);
	base += size;

	return ret;
}

/* This function parses the program headers of the ELF header of the kernel
 * to map the regions into the page table with the appropriate permissions.
 *
 * First creates an identity mapping at the KERNEL_VMA of size BOOT_MAP_LIM
 * with permissions RW-.
 *
 * Then iterates the program headers to map the regions with the appropriate
 * permissions.
 *
 * Hint: this function calls boot_map_region().
 * Hint: this function ignores program headers below KERNEL_VMA (e.g. ".boot").
 */
void boot_map_kernel(struct page_table *pml4, struct elf *elf_hdr)
{
	struct elf_proghdr *prog_hdr =
	    (struct elf_proghdr *)((char *)elf_hdr + elf_hdr->e_phoff);
	uint64_t flags;
	uintptr_t va;
	size_t i;
	
	/* LAB 2: your code here. */
	boot_map_region(pml4, (void*)KERNEL_VMA,
				BOOT_MAP_LIM, 0, PAGE_WRITE | PAGE_NO_EXEC | PAGE_PRESENT );
	
	for (i = 0; i < elf_hdr->e_phnum; ++i, ++prog_hdr,flags=0) {
		if(prog_hdr->p_type == ELF_PROG_LOAD){
			flags = 0;
			va = prog_hdr->p_va;		
			
			if(va < KERNEL_VMA) continue;

			if(prog_hdr->p_flags & ELF_PROG_FLAG_WRITE){
				flags |= PAGE_WRITE | PAGE_NO_EXEC;
			}
			if(!(prog_hdr->p_flags & ELF_PROG_FLAG_EXEC)){
				flags |= PAGE_NO_EXEC;
			}
	
			boot_map_region(pml4, (void*)va, prog_hdr->p_memsz, prog_hdr->p_pa, flags | PAGE_PRESENT);
		}
	}
}

