#pragma once

#include <kernel/mem/boot.h>
#include <kernel/mem/buddy.h>
#include <kernel/mem/dump.h>
#include <kernel/mem/init.h>
#include <kernel/mem/insert.h>
#include <kernel/mem/kmem.h>
#include <kernel/mem/lookup.h>
#include <kernel/mem/map.h>
#include <kernel/mem/populate.h>
#include <kernel/mem/protect.h>
#include <kernel/mem/ptlb.h>
#include <kernel/mem/remove.h>
#include <kernel/mem/slab.h>
#include <kernel/mem/tlb.h>
#include <kernel/mem/user.h>
#include <kernel/mem/walk.h>

#define SECTORS_ADDR 0xfffff00000000000
#define ALL_SECTORS  ((128 * 1024 * 1024) / SECT_SIZE / 8)

struct sectors {
	void *pva;
	uint64_t id;
};

extern struct sectors *sectors;
extern struct list lru_list;
extern int lru_len;

void check_mem_pressure(void);
void sector_init(void);
void mem_pressure(void);
uint64_t get_free_sector_index(void*);
struct task *kernel_task_alloc();
uint64_t sector_hashfunc(uint64_t);
void sector_free(int);
int check_disk(void*);
