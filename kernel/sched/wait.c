#include <types.h>
#include <cpu.h>
#include <error.h>

#include <kernel/mem.h>
#include <kernel/sched.h>

extern struct list runq;

pid_t sys_wait(int *rstatus)
{
	/* LAB 5: your code here. */
	struct task *child_task;
    struct list *node;
	pid_t pid;

	if ( !list_is_empty(&(cur_task->task_children))){
        list_foreach(&cur_task->task_children, node) {
            child_task = container_of(node, struct task, task_node);
            if (child_task->task_status == TASK_DYING) {
                pid = child_task->task_pid;
                cprintf("[PID %5u] Reaping task with PID %u\n", cur_task->task_pid, pid);
                task_destroy(child_task);
                cur_task->task_wait = NULL;
                return pid;
			}
		}
		cur_task->task_status = TASK_WAITING;
        sched_yield();
	}
	return -ECHILD;
}

pid_t sys_waitpid(pid_t pid, int *rstatus, int opts)
{
	/* LAB 5: your code here. */	
	if(list_is_empty(&(cur_task->task_children))) return -ECHILD;

	struct task *child;

	child = pid2task(pid,0);
	if( child->task_status == TASK_DYING ){
        cprintf("[PID %5u] Reaping task with PID %u\n", cur_task->task_pid, pid);
		task_destroy(child);
		return pid;
	}

	cur_task->task_status = TASK_WAITING;
	cur_task->task_wait = child;
	sched_yield();

	return 0;
}

