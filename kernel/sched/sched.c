#include <types.h>
#include <cpu.h>
#include <list.h>
#include <stdio.h>

#include <x86-64/asm.h>
#include <x86-64/paging.h>

#include <kernel/mem.h>
#include <kernel/monitor.h>
#include <kernel/sched.h>

struct list runq;

#ifdef USE_RUNQ_LOCK
struct spinlock runq_lock = {
#ifdef DBEUG_SPINLOCK
	.name = "runq_lock",
#endif
};
#endif

extern size_t nuser_tasks;

void sched_init(void)
{
    list_init(&runq);
    sched_init_mp();
}

void sched_init_mp(void)
{
	/* LAB 6: your code here. */
    list_init(&(this_cpu->runq));
    // list_init(&(this_cpu->nextq));
    this_cpu->runq_len = 0;
}

struct cpuinfo *find_avail_cpu(void) {

    struct list *node;
    struct cpuinfo *cpu, *min_cid = NULL;
    unsigned min_len, cur_len = 0;

    for (cpu = cpus; cpu < cpus + ncpus; ++cpu) {
        if (!list_is_empty(&cpu->runq)) {
            list_foreach(&cpu->runq, node) ++cur_len;

            if( cpu == cpus){
                min_len = cur_len;
                min_cid = cpu;
                continue;
            }

            if (cur_len < min_len) {
                min_len = cur_len;
                min_cid = cpu;
            }
        } 
        return cpu;
    }
    return min_cid;
}


void sched_yield_cpu(void){
    struct list *tasknode;
    struct task *task_to_run;

    if(!list_is_empty(&(this_cpu->runq))){
        tasknode = list_pop(&(this_cpu->runq));
        task_to_run = container_of(tasknode,struct task,task_node);
        // assert(task_to_run->task_status == TASK_RUNNABLE);
        // ++this_cpu->runq_len;
        task_run(task_to_run);
    }

    if(cur_task && cur_task->task_status == TASK_RUNNING) task_run(cur_task);

    sched_halt();

}

/* Runs the next runnable task. */
void sched_yield(void)
{
    
    /* LAB 5: your code here. */
    struct list *tasknode;
    struct task *task_to_run;
    struct cpuinfo *cpu = NULL;

    spin_lock(&kernel_lock);
    if( !list_is_empty(&(runq)) ){
        while(!list_is_empty(&(runq))){
            tasknode = list_pop(&runq);
            task_to_run = container_of(tasknode, struct task, task_node);
            cpu = find_avail_cpu();
            list_push(&cpu->runq,&(task_to_run->task_node));
            xchg(&cpu->cpu_status, CPU_STARTED);
        }
    }
    spin_unlock(&kernel_lock);
    sched_yield_cpu();
}

/* For now jump into the kernel monitor. */
void sched_halt()
{
    struct cpuinfo *cpu;
    unsigned local_runqs = 0;

    if(this_cpu->cpu_id == (ncpus -1) && this_cpu != boot_cpu ){
        xchg(&this_cpu->cpu_status, CPU_HALTED);
        cprintf("CPU : %d halted \n",this_cpu->cpu_id);
        while (this_cpu->cpu_status != CPU_STARTED);
        cprintf("CPU : %d started \n",this_cpu->cpu_id);
        mem_pressure();
    }
    
    if ( cur_task ) sched_yield();

    spin_lock(&kernel_lock);
    
    if( list_is_empty(&runq) ){
        for (cpu = cpus; cpu < cpus + ncpus; ++cpu) {
            if (!list_is_empty(&cpu->runq) || (cpu->cpu_task)) {
                ++local_runqs;
                break;
            }
        }
        if(!local_runqs && this_cpu == boot_cpu ){
            cprintf("Destroyed the only task - nothing more to do!\n");
            while (1) {
                monitor(NULL);
            }
        }
    }


    spin_unlock(&kernel_lock);
    xchg(&boot_cpu->cpu_status, CPU_STARTED);

    xchg(&this_cpu->cpu_status, CPU_HALTED);
    while (this_cpu->cpu_status != CPU_STARTED);

    sched_yield();
}