/*
 * Simple implementation of cprintf console output for the kernel, based on
 * printfmt() and the kernel console's cputchar().
 */

#include <types.h>
#include <cpu.h>
#include <spinlock.h>
#include <stdio.h>
#include <stdarg.h>

#ifdef USE_CONSOLE_LOCK
struct spinlock console_lock = {
#ifdef DEBUG_SPINLOCK
	.name = "console_lock",
#endif
};
#endif

static void putch(int ch, int *cnt)
{
	cputchar(ch);
	*cnt++;
}

int vcprintf(const char *fmt, va_list ap)
{
	int cnt = 0;

	vprintfmt((void*)putch, &cnt, fmt, ap);
	return cnt;
}

int cprintf(const char *fmt, ...)
{
	va_list ap;
	int cnt;

	#ifdef USE_CONSOLE_LOCK
		spin_lock(&console_lock);
	#endif
	va_start(ap, fmt);
	cnt = vcprintf(fmt, ap);
	va_end(ap);
	#ifdef USE_CONSOLE_LOCK
		spin_unlock(&console_lock);
	#endif
	return cnt;
}

