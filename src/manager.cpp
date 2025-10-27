#pragma warning(disable : 5040)

#include <manager.hpp>
#include <kstl/ksystem_info.hpp>
#include <kstl/kpe_parse.hpp>
#include <utils.hpp>
#include <intrin.h>

#define OFFSET_KPCR_CURRENT_THREAD  0x188
#define OFFSET_KPCR_RSP_BASE        0x1A8
#define OFFSET_KTHREAD_SYSTEM_CALL_NUMBER 0x80

EtwHookManager* EtwHookManager::_instance = 0;
EtwHookManager::HalCollectPmcCountersProc EtwHookManager::_originalHalCollectPmcCounters;

EtwHookManager* EtwHookManager::GetInstance()
{
	if (!_instance)
		_instance = new EtwHookManager;

	return _instance;
}

NTSTATUS EtwHookManager::Initialize(HOOK_CALLBACK hookCallback)
{
	//Check whether the memory of the singleton is allocated
	if (!_instance)
		return STATUS_MEMORY_NOT_ALLOCATED;

	if (_isInitialized)
		return STATUS_SUCCESS;

	auto status = STATUS_UNSUCCESSFUL;

	//This method does not support win7
	auto sysInfo = kstd::SysInfoManager::getInstance();

	if (!sysInfo)
		return STATUS_INSUFFICIENT_RESOURCES;

	if (sysInfo->getBuildNumber() <= 7601)
	{
		return STATUS_NOT_SUPPORTED;
	}

	do {
		status = _initilizer.StartTrace();
		if (!NT_SUCCESS(status))
			break;

		/*set value above 1*/
		status = _initilizer.OpenPmcCounter();
		if (!NT_SUCCESS(status))
			break;

		UINT_PTR* halPrivateDispatchTable = _initilizer.GetHalPrivateDispatchTable();
		if (!halPrivateDispatchTable)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		_disable();
		_originalHalCollectPmcCounters = reinterpret_cast<HalCollectPmcCountersProc>(halPrivateDispatchTable[_halCollectPmcCountersIndex]);
		halPrivateDispatchTable[_halCollectPmcCountersIndex] = reinterpret_cast<ULONG_PTR>(HalCollectPmcCountersHook);
		_enable();

		_hookCallback = hookCallback;
		_isInitialized = true;

	} while (false);

	return status;
}


NTSTATUS EtwHookManager::Destory()
{
	if (!_instance)
		return STATUS_MEMORY_NOT_ALLOCATED;

	delete _instance;
	_instance = 0;

	return STATUS_SUCCESS;
}


void EtwHookManager::HalCollectPmcCountersHook(void* context, ULONGLONG traceBufferEnd)
{
	// Sometimes the interrupt will call this function at IRQL > DISPATCH_LEVEL.
	// This is not syscall processing, so we will skip it.
	if (KeGetCurrentIrql() <= DISPATCH_LEVEL)
	{
		if (_instance)
			_instance->TraceStackToSyscall();
	}

	return _originalHalCollectPmcCounters(context, traceBufferEnd);
}

EtwHookManager::EtwHookManager()
	:
	_isInitialized(false),
	_hookCallback(nullptr)
{

	void* kernelImageBase = FindModuleBase(L"ntoskrnl.exe", 0);

	//KiSystemServiceRepeat:
	//	4C 8D 15 85 6F 9F 00          lea     r10, KeServiceDescriptorTable
	//	4C 8D 1D FE 20 8F 00          lea     r11, KeServiceDescriptorTableShadow
	//	F7 43 78 80 00 00 00          test    dword ptr[rbx + 78h], 80h; GuiThread
	//KiSystemServiceRepeat must be located in KiSystemCall64, which directly searches for the signature code

	_kiSystemServiceRepeat = kstd::PatternFindSections(kernelImageBase,
		"\x4c\x8d\x15\x00\x00\x00\x00\x4c\x8d\x1d\x00\x00\x00\x00\xf7\x43",
		"xxx????xxx????xx", ".text");
}


EtwHookManager::~EtwHookManager()
{
	_initilizer.EndTrace();

	if (_originalHalCollectPmcCounters)
	{
		_disable();
		_initilizer.GetHalPrivateDispatchTable()[_halCollectPmcCountersIndex] = reinterpret_cast<ULONG_PTR>(_originalHalCollectPmcCounters);
		_enable();
	}
}

void EtwHookManager::TraceStackToSyscall() {
	if (ExGetPreviousMode() == KernelMode)
		return;

	const ULONG64 currentThread = __readgsqword(OFFSET_KPCR_CURRENT_THREAD);
	const unsigned syscallIndex = *reinterpret_cast<unsigned*>(currentThread + OFFSET_KTHREAD_SYSTEM_CALL_NUMBER);

	if (syscallIndex == 0 || syscallIndex >= 0x0200)
		return;

	if (!_kiSystemServiceRepeat || !MmIsAddressValid(_kiSystemServiceRepeat))
		return;

	/*
	* 25h2 fix documentation
		after logging everything, patterns structs offsets etc. it was all correct but after debugging with windbg
	
		kd> bp nt!NtCreateFile
		kd> dps @rsp L30
		ffffa887`4fd3f3e8 fffff801`f0eb3944 nt!KiSystemServiceExitPico+0x499
		ffffa887`4fd3f458 fffff801`f0eb2e3b nt!KiSystemServiceUser+0x59
	
		look at those addresses from the stack:
		nt!KiSystemServiceExitPico+0x499
		nt!KiSystemServiceUser+0x59
	
		kd> ? nt!KiSystemServiceExitPico - nt!KiSystemServiceRepeat
		kd> ? nt!KiSystemServiceUser - nt!KiSystemServiceRepeat
	
		these are syscall exit paths that are outside the 4KB range from
		(cant really see that they are out of range, didnt include full logs bcs too much)
	
		we can see both are out of range since we were on 0x1000 (PAGE_SIZE)
		increased the page size by * 4 so we can get 16kb which fixed the issue
	*/

	const ULONG_PTR base = reinterpret_cast<ULONG_PTR>(PAGE_ALIGN(_kiSystemServiceRepeat));
	const ULONG_PTR end = base + (PAGE_SIZE * 4);  // increased for 25h2

	PVOID* stackPos = reinterpret_cast<PVOID*>(_AddressOfReturnAddress());
	PVOID* stackLimit = reinterpret_cast<PVOID*>(__readgsqword(OFFSET_KPCR_RSP_BASE));

	__try {
		for (; stackPos < stackLimit; ++stackPos) {
			const ULONG_PTR retAddr = reinterpret_cast<ULONG_PTR>(*stackPos);
			if (retAddr >= base && retAddr < end) {
				ProcessSyscall(syscallIndex, stackPos);
				break;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return;
	}
}

static void* g_HookedSyscalls[0x200] = { nullptr };
static void* g_OriginalSyscalls[0x200] = { nullptr };

void EtwHookManager::ProcessSyscall(unsigned systemCallIndex, void** stackPos) {
	if (!_hookCallback) {
		return;
	}

	/*
	* crash fix documentation
		(Bug Check 0x3B - SYSTEM_SERVICE_EXCEPTION)
		during debugging the stack trace i found that PerfInfoLogSysCallEntry
		rip rsp rbp is corrupt
	
		-------------------
		kd> .trap 0xFFFFFC021C506900
		NOTE: The trap frame does not contain all registers.
		Unable to get program counter
		rax=00001f800010001f rbx=0000000000000000 rcx=0053002b002b0010
		rdx=000502820018002b rsi=0000000000000000 rdi=0000000000000000
		rip=0000000000000000 rsp=0000000000000000 rbp=0000000000000000
		r8=0000000000000000  r9=fffffc021c507370 r10=ffffbb8bc391a000
		r11=ffffbb8bc379ba10 r12=0000000000000000 r13=0000000000000000
		r14=0000000000000000 r15=0000000000000000
		iopl=0         nv up di pl nz na pe nc
		6420:0000 ??              ???
		-------------------
	*/

	PVOID* stackLimit = reinterpret_cast<PVOID*>(__readgsqword(OFFSET_KPCR_RSP_BASE));
	if (!stackLimit || (stackPos + 9) >= stackLimit)
		return;

	__try {
		void* currentSyscallFunc = stackPos[9];

		if (g_HookedSyscalls[systemCallIndex] != nullptr) {
			if (currentSyscallFunc == g_OriginalSyscalls[systemCallIndex]) {
				stackPos[9] = g_HookedSyscalls[systemCallIndex];
			}
			return;
		}

		void* syscallFuncCopy = currentSyscallFunc;
		_hookCallback(systemCallIndex, &syscallFuncCopy);

		if (syscallFuncCopy != currentSyscallFunc) {
			g_OriginalSyscalls[systemCallIndex] = currentSyscallFunc;
			g_HookedSyscalls[systemCallIndex] = syscallFuncCopy;

			stackPos[9] = syscallFuncCopy;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return;
	}
}