/*
 * Preemptive kernel simulation under Windows
 * 
 * Eran Duchan, 2008 (released 2011)
 * www.pavius.net
 *
 */

#include <windows.h>
#include <string>
#include <queue>
#include <inttypes.h> // For PRIu64

//#include "stdafx.h"

// ============================================================================
// helpers
// ============================================================================

// crash/assert macro
#define wcs_assert(condition) do {if (!(condition)) wcs_crash(0);} while (0)
#define wcs_crash do {__asm int 3} while

// check alignment
#define wcs_is_aligned( address, alignment ) ( !(((DWORD)address) & (alignment - 1)) )

// get offset of a structure member
#define wcs_offset_of(type, member) ( (DWORD) &( (type *) 0 )->member )

// ============================================================================
// simulated ukernel
// ============================================================================

typedef struct
{
    // pointer to the stack - updated on context switch
    byte *stack;
	byte *stack_base;
	uint64_t nr_thread_switches;

    // name, for debugging
    std::string name;
	// experimental
	CONTEXT ctx;
}
THREAD_CONTROL_BLOCK;

// offset of stack pointer into TCB (can't use offset_of)
#define WCS_THREAD_TCB_STACK_PTR_OFFSET (0)

// thread entry with a single argument
typedef void (*THREAD_PROC)(void *);

// fifo queue of ready threads
std::queue<THREAD_CONTROL_BLOCK *> ready_threads_queue;

// current running thread
THREAD_CONTROL_BLOCK *running_thread = nullptr;

// called when a thread exits
void wcs_thread_entry_return()
{
    // normally, you would want to deallocate the TCB, remove the thread
    // from the kernel lists
}

#define TIB_UserDataSlot 0x14

// PatrickvL : arrange for a thread to get to it's tcb
THREAD_CONTROL_BLOCK *wcs_get_running_thread_tcb()
{
	__asm {
		mov eax, fs:[TIB_UserDataSlot]
	}
}

// PatrickvL : arrange for a thread to get to it's tcb
void wcs_set_running_thread_tcb(THREAD_CONTROL_BLOCK *tcb)
{
	__asm {
		mov eax, tcb
		mov fs:[TIB_UserDataSlot], eax
	}
}

uint64_t total_nr_thread_switches = 0;

// create a thread
THREAD_CONTROL_BLOCK * wcs_thread_create(const char *name, const DWORD stack_size,
                       const THREAD_PROC entry, void *argument)
{
    // check stack alignment
    wcs_assert(wcs_is_aligned(stack_size, sizeof(DWORD)));

    // allocate a TCB
    THREAD_CONTROL_BLOCK *thread_tcb = new THREAD_CONTROL_BLOCK;
        
    // set thread name
    thread_tcb->name = name;

	thread_tcb->nr_thread_switches = 0;

    // allocate the thread stack
    byte *thread_stack = new byte[stack_size];
    wcs_assert(thread_stack != nullptr);

	thread_tcb->stack_base = thread_stack;

    // initialize it with some junk
    memset(thread_stack, 0xAB, stack_size);

    //
    // start shoving stuff into the stack
    //
    
    // set the thread stack in the TCB to the end of the stack block (since 
    // it grows upwards) and point to the first dword we can write to
    DWORD *current_stack_position = (DWORD *)((thread_stack + stack_size) - sizeof(DWORD));

    // push argument 
    *current_stack_position-- = (DWORD)argument;

    // this is the address of the routine to be called when a 
    // thread returns from its thread entry
    *current_stack_position-- = (DWORD)wcs_thread_entry_return;

    // push entry 
    *current_stack_position-- = (DWORD)entry;

    // push status word.
	// will be loaded by popdf
    *current_stack_position-- = 0x0202;

    // push 4 dummies - eax, ebx, ecx, edx.
	// will be loaded into registers by popad
    
    *current_stack_position--    = 0xaa;        // eax 
    *current_stack_position--    = 0xcc;        // ecx 
    *current_stack_position--    = 0xdd;        // edx 
    *current_stack_position--    = 0xbb;        // ebx 
    *current_stack_position--    = 0x0;        // skipped (esp) 
    *current_stack_position--    = 0xeb;        // ebp 
    *current_stack_position--    = 0xa0;        // esi 
    *current_stack_position      = 0xb0;        // edi 

    // set current position in stack 
    thread_tcb->stack = (byte *)current_stack_position;

    // shove thread to ready list
    ready_threads_queue.push(thread_tcb);

	return thread_tcb;
}

// reschedule the next ready thread
void interrupt_simulator_thread_reschedule()
{
    //
    // Get next thread to run
    //

    // shove current thread to back of queue
    if (running_thread != nullptr) 
		ready_threads_queue.push(running_thread);

    // get next available thread
    running_thread = ready_threads_queue.front();
    ready_threads_queue.pop();

	running_thread->nr_thread_switches++;
	total_nr_thread_switches++;

	//
    // Load new thread context
    //    
    __asm
    {
		// load stack register from the new thread 
        mov eax, running_thread
        mov esp, WCS_THREAD_TCB_STACK_PTR_OFFSET[eax]
		// PatrickvL : make sure wcs_get_running_thread_tcb() works :
		mov fs:[0x14], eax

        // pop 8 GPRs and the status word 
        popad
        popfd

        // stack now points to the entry. return to it 
        ret
    }
}

// simulated tick ISR, called in main thread context via thread hijack 
__declspec(naked) void hijacked_kernel_thread_tick_isr()
{
    //
    // Save running thread context
    //
    __asm
    {
        // push status word and all registers  
        pushfd
        pushad

        // push stack ptr to running thread
        mov edx, running_thread
        mov [edx + WCS_THREAD_TCB_STACK_PTR_OFFSET], esp
    }

    interrupt_simulator_thread_reschedule();

    // in this simplistic demo, we'll never get here. in the real world,
    // we may get here if the kernel has no ready thread to execute. we'd 
    // need to restore the thread we interrupted and continue
    wcs_crash(0);
}

// ============================================================================
// Interrupt simulator thread
// ============================================================================

// interrupt simulator message types
typedef enum
{
    MSG_RAISE_INTERRUPT        = WM_USER + 1,

    // must be last
    WCS_INTSIM_MSG_LAST
    
} WCS_INTSIM_MESSAGE_TYPE;

// raise interrupt 
// hijack the windows thread running our kernel - once
// it becomes ready it will jump to hijacked_kernel_thread_tick_isr
void interrupt_simulator_thread_handle_raised_interrupt(HANDLE kernel_thread_handle_to_interrupt)
{
    // initialize context flags 
    CONTEXT ctx;

    // suspend the kernel thread (this won't abort an active time-slice)
    SuspendThread(kernel_thread_handle_to_interrupt);

    // get the windows thread context of the kernel thread
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;
	// MSDN explains GetThreadContext cannot get a valid context for a running thread,
	// thus requires call to SuspendThread first, which implies the thread is guaranteed
	// to be suspended only after this call :
    GetThreadContext(kernel_thread_handle_to_interrupt, &ctx);

	if (running_thread)
		memcpy(&(running_thread->ctx), &ctx, sizeof(ctx));
	else
		ctx.ContextFlags = CONTEXT_FULL; // no-op for breakpoint purposes

    // push the address we want to return to (which is wherever the thread is now)
    // after our simulated ISR to the thread's stack
    ctx.Esp -= sizeof(DWORD);
    *((DWORD *)ctx.Esp) = ctx.Eip;

    // set the instruction pointer of the kernel thread to that of the ISR routine
    ctx.Eip = (DWORD)hijacked_kernel_thread_tick_isr;

    // set context of the kernel thread, effectively overriding the instruction pointer
    SetThreadContext(kernel_thread_handle_to_interrupt, &ctx);

    // resume the kernel thread
    ResumeThread(kernel_thread_handle_to_interrupt);
}

DWORD WINAPI interrupt_simulator_thread_proc(void *kernel_thread_handle)
{
    MSG interrupt_simulator_thread_message;

    // forever 
    while (1)
    {
		// TODO : An alternative to a timer posting messages,
		// interrupt frequency could be handled here using
		// self-tuning timing mechanism, using things like :
		// * if(!SwitchToThread()) Sleep(0); 
		// * spin-loop with QueryPerformanceCounter() / RDTSC
		// See http://www.windowstimestamp.com/description

        // get windows message 
        switch (GetMessage(&interrupt_simulator_thread_message, nullptr, MSG_RAISE_INTERRUPT, WCS_INTSIM_MSG_LAST))
        {
		case -1:
			// TODO : Handle error
            wcs_crash(0);
			break;
		case 0:
			// TODO : Handle WM_QUIT
			exit(0);
			break;
		default:
            // check which message we got 
            switch (interrupt_simulator_thread_message.message)
            {
                // [async] raise interrupt 
                case MSG_RAISE_INTERRUPT: 
					// supply the handle of the thread we'll need to interrupt
					interrupt_simulator_thread_handle_raised_interrupt((HANDLE)kernel_thread_handle);
					break;
				default:
					interrupt_simulator_thread_message.time++; // A no-op. Ignore this - just to be able to set a breakpoint
					break;
            }
        }
    }
}

// interrupt registered thread, called from periodic timer (executing in
// a thread, separate from kernel_thread and interrupt_simulator_thread)
void CALLBACK interrupt_simulator_periodic_timer_expiration(void *param, BOOLEAN dummy)
{
	DWORD interrupt_simulator_thread_id = (DWORD)param;

    // send a message, don't wait 
	PostThreadMessage(interrupt_simulator_thread_id, MSG_RAISE_INTERRUPT, 0, 0);
}

void initialize_interrupt_simulator()
{
	// get a duplicate handle for the current thread, to gain suspend/resume rights
	HANDLE kernel_thread_handle;
	DuplicateHandle(GetCurrentProcess(),
		GetCurrentThread(),
		GetCurrentProcess(),
		&kernel_thread_handle,
		0,
		TRUE,
		DUPLICATE_SAME_ACCESS);

    // spawn interrupt thread 
	/*static*/ HANDLE interrupt_simulator_thread_handle;
	/*static*/ DWORD interrupt_simulator_thread_id;
    interrupt_simulator_thread_handle = CreateThread(
		nullptr, 
		0, 
		interrupt_simulator_thread_proc,
        /*Parameter=*/kernel_thread_handle,
        0,
		&interrupt_simulator_thread_id);

    // make sure the interrupt thread has highest priority so it can preempt the kernel thread
    BOOL result = SetThreadPriority(interrupt_simulator_thread_handle, THREAD_PRIORITY_HIGHEST);

    // start the periodic timer interrupt using a periodically expiring timer, simulating a round robin time-slicing
	HANDLE periodic_timer_handle; // timer handle (no need for it)
	result = CreateTimerQueueTimer(&periodic_timer_handle, 
										CreateTimerQueue(), 
										(WAITORTIMERCALLBACK)interrupt_simulator_periodic_timer_expiration,
										/*Parameter=*/(void *)interrupt_simulator_thread_id,
										/*DueTime=*/100, // wait a bit to allow wcs_intsim_thread_handle to create messages
		// TODO : Low values (high frequencies) lead to exceptions - why?
		// See https://github.com/pavius/preemptive-kernel-in-win-thread/issues/1
										10, // ms, was 500
										0);

	/* make sure */
	wcs_assert(result == TRUE);
}

// ============================================================================
// Demo
// ============================================================================

THREAD_CONTROL_BLOCK *t1, *t2, *t3, *t4;

// incrementor thread
void thread_entry(void *argument)
{
	uint64_t Prev = -1;
	THREAD_CONTROL_BLOCK *tcb = wcs_get_running_thread_tcb();

    // increment a number
    while (1)
    {

		uint64_t Curr = total_nr_thread_switches;// tcb->nr_thread_switches;
		if (Prev != Curr)
		{
			Prev = Curr;
			// print the argument repeatedly
			printf("\n%s %" PRIu64 "", (const char *)argument, Curr);

			printf("  stack sizes : t1 = %d", t1->stack - t1->stack_base);
			printf(" t2 = %d", t2->stack - t2->stack_base);
			printf(" t3 = %d", t3->stack - t3->stack_base);
			printf(" t4 = %d", t4->stack - t4->stack_base);
		}
    }
}

int main(int argc, char* argv[])
{
    // create threads
    t1 = wcs_thread_create("t1", 64 * 1024, thread_entry, (void *)" t1    ");
    t2 = wcs_thread_create("t2", 64 * 1024, thread_entry, (void *)" t 2   ");
    t3 = wcs_thread_create("t3", 64 * 1024, thread_entry, (void *)" t  3  ");
    t4 = wcs_thread_create("t4", 64 * 1024, thread_entry, (void *)" t   4 ");

	initialize_interrupt_simulator();

    // start threads
    interrupt_simulator_thread_reschedule();

    // no error
    return 0;
}