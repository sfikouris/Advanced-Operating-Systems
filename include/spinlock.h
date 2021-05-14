#pragma once

struct cpuinfo;

extern struct spinlock kernel_lock;
extern struct spinlock console_lock;
extern struct spinlock buddy_lock;
extern struct spinlock runq_lock;
extern struct spinlock lru_lock;

#define USE_BIG_KERNEL_LOCK
#define USE_BUDDY_LOCK
#define USE_CONSOLE_LOCK
#define USE_RUNQ_LOCK
#define USE_TASK_LOCK

struct spinlock {
	/* Is the lock held? */
	volatile unsigned locked;

#define DEBUG_SPINLOCK
	/* The name of the lock. */
	const char *name;

	/* The CPU that is holding the lock. */
	struct cpuinfo *cpu;

	/* The filename and line at which the last successful lock took
	 * place.
	 */
	const char *file;
	int line;
};

#define spin_lock(lock) __spin_lock(lock, __FILE__, __LINE__)
#define spin_trylock(lock) __spin_trylock(lock, __FILE__, __LINE__)
#define spin_unlock(lock) __spin_unlock(lock, __FILE__, __LINE__)

void spin_init(struct spinlock *lock, const char *name);
void __spin_lock(struct spinlock *lock, const char *file, int line);
int __spin_trylock(struct spinlock *lock, const char *file, int line);
void __spin_unlock(struct spinlock *lock, const char *file, int line);

