#include "syscall.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d va = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	debugf("size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return size;
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}

uint64 sys_gettimeofday(TimeVal *val, int _tz) // TODO: implement sys_gettimeofday in pagetable. (VA to PA)
{
	// YOUR CODE
	if (!val) {
		return -1;
	}
	TimeVal tmp;
	uint64 cycle = get_cycle();
	tmp.sec = (cycle / CPU_FREQ);

	tmp.usec = (cycle % CPU_FREQ) * 1000000UL / CPU_FREQ;
	if (copyout(curr_proc()->pagetable, (uint64)val, (char*)&tmp, sizeof(tmp)) < 0) {
		return -1;
	}

	return 0;
}

// TODO: add support for mmap and munmap syscall.
// hint: read through docstrings in vm.c. Watching CH4 video may also help.
// Note the return value and PTE flags (especially U,X,W,R)
int sys_mmap(void* start, unsigned long long len, int port, int flag, int fd) {
	uint64 va0 = (uint64) start;

	if (len > (1UL << 30)) return -1;

	if (va0 % PAGE_SIZE != 0) return -1;

	if ((port & ~0x7) != 0) return -1;

	if ((port & 0x7) == 0) return -1;

	uint64 sz = PGROUNDUP(len);
	uint64 va_end = va0 + sz;

	struct proc *p = curr_proc();

	for (uint64 va = va0; va < va_end; va += PAGE_SIZE) {
		if (walkaddr(p->pagetable, va) != 0) {
			return -1;
		}
	}

	int permission_bits = PTE_U;

	if (port & 0x1) permission_bits |= PTE_R;
	if (port & 0x2) permission_bits |= PTE_W;
	if (port & 0x4) permission_bits |= PTE_X;
	
	
	for (uint64 va = va0; va < va_end; va += PAGE_SIZE) {
		void *pa = kalloc();
		if (!pa) return -1;

		memset(pa, 0, PAGE_SIZE);

		if (mappages(p->pagetable, va, PGSIZE, (uint64)pa, permission_bits) < 0) {
			return -1;
		}
	}
	return 0;
}
int sys_munmap(void* start, unsigned long long len) {
	uint64 va0 = (uint64) start;

	if (len == 0) return 0;

	if (va0 % PAGE_SIZE != 0) return -1;

	uint64 sz = PGROUNDUP(len);
	uint64 va_end = va0 + sz;

	struct proc *p = curr_proc();

	for (uint64 va = va0; va < va_end; va += PAGE_SIZE) {
		if (walkaddr(p->pagetable, va) == 0) {
			return -1;
		}
	}

	uint64 npages = sz / PAGE_SIZE;
	uvmunmap(p->pagetable, va0, npages, 1);

	return 0;
}
/*
=
* LAB1: you may need to define sys_task_info here
*/
int sys_task_info(TaskInfo *ti)
{
	if (!ti) {
		return -1;
	}

	TaskInfo tmp;
	struct proc *p = curr_proc();

	uint64 cycle = get_cycle();

	uint64 now = (cycle / CPU_FREQ) * 1000UL + (cycle % CPU_FREQ) * 1000UL / CPU_FREQ;
	tmp.status = p->info.status;

	if (p->info.status == UnInit) {
		tmp.time = 0;
		p->info.time = 0;
	}
	else {
		tmp.time = now - p->info.time;
	}
	for(int i = 0; i < MAX_SYSCALL_NUM; i++) {
		tmp.ti_syscall_times[i] = p->proc_syscall_times[i];
	}

	if (copyout(p->pagetable, (uint64)ti, (char*)&tmp, sizeof(tmp)) < 0) {
		return -1;
	}
	return 0;
}

extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);
	/*
	* LAB1: you may need to update syscall counter for task info here
	*/
	if (id >= 0 && id < MAX_SYSCALL_NUM) {
		curr_proc()->proc_syscall_times[id]++;

	}
	else {
		return;
	}
	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
		// __builtin_unreachable();
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday((TimeVal *)args[0], args[1]);
		break;
	/*
	* LAB1: you may need to add SYS_taskinfo case here
	*/
	case SYS_task_info:
		ret = sys_task_info((TaskInfo *)args[0]);
		break;
	/*
	* LAB2: I'm adding nmap and munmap here
	*/
	case SYS_mmap:
		ret = sys_mmap((void *)args[0], (unsigned long long)args[1], (int)args[2], (int)args[3], (int)args[4]);
		break;
	case SYS_munmap:
		ret = sys_munmap((void *)args[0], (unsigned long long)args[1]);
		break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}
