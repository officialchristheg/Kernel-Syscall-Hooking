#pragma warning(disable : 5040)
#include <cstdint>
#include <init.hpp>
#include <manager.hpp>

#define _countof(arr) (sizeof(arr) / sizeof(arr[0]))
#define POOL_TAG 'TSET'

static volatile LONG gHooksActive = 0;
static volatile LONG gCallStats[0x0200] = { 0 };
static void* gStatsThread = nullptr;

static NTSTATUS DetourNtCreateFile(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_ ULONG EaLength)
{

	if (ObjectAttributes &&
		ObjectAttributes->ObjectName &&
		ObjectAttributes->ObjectName->Buffer)
	{
		wchar_t* name = reinterpret_cast<wchar_t*>
			(ExAllocatePoolWithTag(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t), POOL_TAG));

		if (name)
		{
			RtlCopyMemory(name, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);
			name[ObjectAttributes->ObjectName->Length / sizeof(wchar_t)] = 0;

			if (wcsstr(name, L"oxygen.txt"))
			{
				ExFreePoolWithTag(name, POOL_TAG);
				InterlockedDecrement(&gHooksActive);
				return STATUS_ACCESS_DENIED;
			}

			ExFreePoolWithTag(name, POOL_TAG);
		}
	}


	NTSTATUS status = NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
		IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
		CreateDisposition, CreateOptions, EaBuffer, EaLength);

	InterlockedDecrement(&gHooksActive);

	return status;
}

static void __fastcall mainHooks(_In_ unsigned int systemCallIndex, _Inout_ void** systemCallFunction)
{
    UNREFERENCED_PARAMETER(systemCallIndex);
    InterlockedIncrement(gCallStats + systemCallIndex);

    if (*systemCallFunction == NtCreateFile) {
        InterlockedIncrement(&gHooksActive);
        *systemCallFunction = DetourNtCreateFile;
    }
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING)
{
    kstd::Logger::Initialize("Driver");

    EtwHookManager* manager = EtwHookManager::GetInstance();

    if (manager)
    {
        manager->Initialize(mainHooks);
    }

    OBJECT_ATTRIBUTES objectAttributes = { 0 };
    InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    return STATUS_SUCCESS;
}
