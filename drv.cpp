#pragma optimize("", off) 
#include <ntifs.h>
#include <windef.h>



/*MANUAL


Line: 770 (Entry)
Line: 485 (abc)
Line: 165 (winvers)
Line: 442 (initialize_driver)
Line: 141 (read)
Line: 148 (write)

*/

UNICODE_STRING name, link;

typedef struct _SYSTEM_BIGPOOL_ENTRY
{
	union {
		PVOID VirtualAddress;
		ULONG_PTR NonPaged : 1;
	};
	ULONG_PTR SizeInBytes;
	union {
		UCHAR Tag[4];
		ULONG TagUlong;
	};
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBigPoolInformation = 0x42
} SYSTEM_INFORMATION_CLASS;

extern "C" NTSTATUS NTAPI IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
extern "C" PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);
extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);

#define code_rw CTL_CODE(FILE_DEVICE_UNKNOWN, 0x71, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_ba CTL_CODE(FILE_DEVICE_UNKNOWN, 0x72, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_security 0x87b3d15
#define win_1803 17134
#define win_1809 17763
#define win_1903 18362
#define win_1909 18363
#define win_2004 19041
#define win_20H2 19569
#define win_21H1 20180
// Windows 11 support:
#define win_21H2  22000

#define PAGE_OFFSET_SIZE 12
static const UINT64 PMASK = (~0xfull << 8) & 0xfffffffffull;

typedef struct _rw {
	INT32 security;
	INT32 process_id;
	ULONGLONG address;
	ULONGLONG buffer;
	ULONGLONG size;
	BOOLEAN write;
} rw, * prw;

typedef struct _ba {
	INT32 security;
	INT32 process_id;
	ULONGLONG* address;
} ba, * pba;

typedef struct _ga {
	INT32 security;
	ULONGLONG* address;
} ga, * pga;

NTSTATUS read(PVOID target_address, PVOID buffer, SIZE_T size, SIZE_T* bytes_read) {
	NTSTATUS status;
	PEPROCESS proc_handle;
	HANDLE section_handle;
	PVOID mapped_view;

	status = PsLookupProcessByProcessId(target_address, &proc_handle);
	if (!NT_SUCCESS(status))
		return status;

	status = ZwCreateSection(&section_handle, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(status))
		return status;

	status = ZwMapViewOfSection(section_handle, proc_handle, &mapped_view, 0, 0, NULL, bytes_read, ViewUnmap, 0, PAGE_READONLY);
	if (!NT_SUCCESS(status))
		return status;

	RtlCopyMemory(buffer, mapped_view, size);

	ZwUnmapViewOfSection(proc_handle, mapped_view);
	ZwClose(section_handle);
	ZwClose(proc_handle);

	return status;
}

NTSTATUS write(PVOID target_address, PVOID buffer, SIZE_T size, SIZE_T* bytes_read)
{
	NTSTATUS status;
	PEPROCESS proc_handle;
	HANDLE section_handle;
	PVOID mapped_view;

	status = PsLookupProcessByProcessId(target_address, &proc_handle);
	if (!NT_SUCCESS(status))
		return status;

	status = ZwCreateSection(&section_handle, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(status))
		return status;

	status = ZwMapViewOfSection(section_handle, proc_handle, &mapped_view, 0, 0, NULL, bytes_read, ViewUnmap, 0, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
		return status;

	RtlCopyMemory(mapped_view, buffer, size);

	ZwUnmapViewOfSection(proc_handle, mapped_view);
	ZwClose(section_handle);
	ZwClose(proc_handle);

	return status;
}

// We can use the code above for writing and reading i prefer the one below tho, right now that's your problem.

//NTSTATUS read(PVOID target_address, PVOID buffer, SIZE_T size, SIZE_T* bytes_read) {
//	MM_COPY_ADDRESS to_read = { 0 };
//	to_read.PhysicalAddress.QuadPart = (LONGLONG)target_address;
//	return MmCopyMemory(buffer, to_read, size, MM_COPY_MEMORY_PHYSICAL, bytes_read);
//}
//
//NTSTATUS write(PVOID target_address, PVOID buffer, SIZE_T size, SIZE_T* bytes_read)
//{
//	if (!target_address)
//		return STATUS_UNSUCCESSFUL;
//
//	PHYSICAL_ADDRESS AddrToWrite = { 0 };
//	AddrToWrite.QuadPart = LONGLONG(target_address);
//
//	PVOID pmapped_mem = MmMapIoSpaceEx(AddrToWrite, size, PAGE_READWRITE);
//
//	if (!pmapped_mem)
//		return STATUS_UNSUCCESSFUL;
//
//	memcpy(pmapped_mem, buffer, size);
//
//	*bytes_read = size;
//	MmUnmapIoSpace(pmapped_mem, size);
//	return STATUS_SUCCESS;
//}

INT32 get_winver() {
	RTL_OSVERSIONINFOW ver = { 0 };
	RtlGetVersion(&ver);
	switch (ver.dwBuildNumber)
	{
	case win_1803:
		return 0x0278;
		break;
	case win_1809:
		return 0x0278;
		break;
	case win_1903:
		return 0x0280;
		break;
	case win_1909:
		return 0x0280;
		break;
	case win_2004:
		return 0x0388;
		break;
	case win_20H2:
		return 0x0388;
		break;
	case win_21H1:
		return 0x0388;
		break;
		// Windows 11 support:
	case win_21H2:
		return 0x0390;
		break;
	default:
		return 0x0390;
	}
}


UINT64 get_process_cr3(const PEPROCESS pProcess) {
	PUCHAR process = (PUCHAR)pProcess;
	ULONG_PTR process_dirbase = *(PULONG_PTR)(process + 0x28);
	if (process_dirbase == 0)
	{
		INT32 UserDirOffset = get_winver();
		ULONG_PTR process_userdirbase = *(PULONG_PTR)(process + UserDirOffset);
		return process_userdirbase;
	}
	return process_dirbase;
}

UINT64 translate_linear(UINT64 directoryTableBase, UINT64 virtualAddress) {
	directoryTableBase &= ~0xf;

	UINT64 pageOffset = virtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);
	UINT64 pte = ((virtualAddress >> 12) & (0x1ffll));
	UINT64 pt = ((virtualAddress >> 21) & (0x1ffll));
	UINT64 pd = ((virtualAddress >> 30) & (0x1ffll));
	UINT64 pdp = ((virtualAddress >> 39) & (0x1ffll));

	SIZE_T readsize = 0;
	UINT64 pdpe = 0;
	read(PVOID(directoryTableBase + 8 * pdp), &pdpe, sizeof(pdpe), &readsize);
	if (~pdpe & 1)
		return 0;

	UINT64 pde = 0;
	read(PVOID((pdpe & PMASK) + 8 * pd), &pde, sizeof(pde), &readsize);
	if (~pde & 1)
		return 0;

	if (pde & 0x80)
		return (pde & 0x7ffff000ull) + (virtualAddress & ~(~0ull << 30));

	UINT64 pteAddr = 0;
	read(PVOID((pde & PMASK) + 8 * pt), &pteAddr, sizeof(pteAddr), &readsize);
	if (~pteAddr & 1)
		return 0;

	/* 2MB large page */
	if (pteAddr & 0x80)
		return (pteAddr & PMASK) + (virtualAddress & ~(~0ull << 21));

	virtualAddress = 0;
	read(PVOID((pteAddr & PMASK) + 8 * pte), &virtualAddress, sizeof(virtualAddress), &readsize);
	virtualAddress &= PMASK;

	if (!virtualAddress)
		return 0;

	return virtualAddress + pageOffset;
}

ULONG64 find_min(INT32 g, SIZE_T f) {
	INT32 h = (INT32)f;
	ULONG64 result = 0;

	result = (((g) < (h)) ? (g) : (h));

	return result;
}

NTSTATUS frw(prw x) {
	if (x->security != code_security)
		return STATUS_UNSUCCESSFUL;

	if (!x->process_id)
		return STATUS_UNSUCCESSFUL;

	PEPROCESS process = NULL;
	PsLookupProcessByProcessId((HANDLE)x->process_id, &process);
	if (!process)
		return STATUS_UNSUCCESSFUL;

	ULONGLONG process_base = get_process_cr3(process);
	ObDereferenceObject(process);

	SIZE_T this_offset = NULL;
	SIZE_T total_size = x->size;

	INT64 physical_address = translate_linear(process_base, (ULONG64)x->address + this_offset);
	if (!physical_address)
		return STATUS_UNSUCCESSFUL;

	ULONG64 final_size = find_min(PAGE_SIZE - (physical_address & 0xFFF), total_size);
	SIZE_T bytes_trough = NULL;

	if (x->write) {
		write(PVOID(physical_address), (PVOID)((ULONG64)x->buffer + this_offset), final_size, &bytes_trough);
	}
	else {
		read(PVOID(physical_address), (PVOID)((ULONG64)x->buffer + this_offset), final_size, &bytes_trough);
	}

	return STATUS_SUCCESS;
}

NTSTATUS fba(pba x) {
	if (x->security != code_security)
		return STATUS_UNSUCCESSFUL;

	if (!x->process_id)
		return STATUS_UNSUCCESSFUL;

	PEPROCESS process = NULL;
	PsLookupProcessByProcessId((HANDLE)x->process_id, &process);
	if (!process)
		return STATUS_UNSUCCESSFUL;

	ULONGLONG image_base = (ULONGLONG)PsGetProcessSectionBaseAddress(process);
	if (!image_base)
		return STATUS_UNSUCCESSFUL;

	RtlCopyMemory(x->address, &image_base, sizeof(image_base));
	ObDereferenceObject(process);

	return STATUS_SUCCESS;
}

typedef struct _SYSTEM_HANDLE_ENTRY {
	USHORT ProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeNumber;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
	ULONG ObjectPointer;
	ULONG HandleCount;
	ULONG NonPaged;
} SYSTEM_HANDLE_ENTRY, * PSYSTEM_HANDLE_ENTRY;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_ENTRY Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;
typedef struct _DRV_OPAQUE_CONTEXT {
	PVOID Context;
	PVOID(*Function1)(PVOID, ULONG);
	PVOID(*Function2)(PVOID, ULONG);
} DRV_OPAQUE_CONTEXT, * PDRV_OPAQUE_CONTEXT;

DRV_OPAQUE_CONTEXT context;




NTSTATUS io_controller(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	NTSTATUS status = { };
	ULONG bytes = { };
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
	ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

	if (code == code_rw) {
		if (size == sizeof(_rw)) {
			prw req = (prw)(irp->AssociatedIrp.SystemBuffer);

			status = frw(req);
			bytes = sizeof(_rw);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
	}
	else if (code == code_ba) {
		if (size == sizeof(_ba)) {
			pba req = (pba)(irp->AssociatedIrp.SystemBuffer);

			status = fba(req);
			bytes = sizeof(_ba);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
	}

	ULONG obfuscated_status = status ^ 0xDEADBEEF;
	ULONG obfuscated_bytes = bytes ^ 0xDEADBEEF;

	irp->IoStatus.Status = obfuscated_status;
	irp->IoStatus.Information = obfuscated_bytes;
	IoCompleteRequest(irp, IO_NO_INCREMENT);


	return obfuscated_status ^ 0xDEADBEEF;
}

NTSTATUS unsupported_dispatch(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	ULONG obfuscated_status = STATUS_NOT_SUPPORTED ^ 0xDEADBEEF;

	irp->IoStatus.Status = obfuscated_status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return obfuscated_status ^ 0xDEADBEEF;
}

NTSTATUS dispatch_handler(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

	switch (stack->MajorFunction) {
	case IRP_MJ_CREATE:
		break;
	case IRP_MJ_CLOSE:
		break;
	default:
		break;
	}

	IoCompleteRequest(irp, IO_NO_INCREMENT);

	ULONG obfuscated_status = irp->IoStatus.Status ^ 0xDEADBEEF;

	return obfuscated_status ^ 0xDEADBEEF;
}

void unload_drv(PDRIVER_OBJECT drv_obj) {
	NTSTATUS status = { };

	status = IoDeleteSymbolicLink(&link);

	if (!NT_SUCCESS(status))
		return;

	IoDeleteDevice(drv_obj->DeviceObject);
}

NTSTATUS initialize_driver(PDRIVER_OBJECT drv_obj, PUNICODE_STRING path) {
	UNREFERENCED_PARAMETER(path);

	NTSTATUS status = { };
	PDEVICE_OBJECT device_obj = { };

	RtlInitUnicodeString(&name, L"\\Device\\memebubu");
	RtlInitUnicodeString(&link, L"\\DosDevices\\memebubu");

	status = IoCreateDevice(drv_obj, 0, &name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_obj);

	if (!NT_SUCCESS(status))
		return status;

	status = IoCreateSymbolicLink(&link, &name);

	if (!NT_SUCCESS(status))
		return status;

	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		drv_obj->MajorFunction[i] = &unsupported_dispatch;

	device_obj->Flags |= DO_BUFFERED_IO;

	drv_obj->MajorFunction[IRP_MJ_CREATE] = &dispatch_handler;
	drv_obj->MajorFunction[IRP_MJ_CLOSE] = &dispatch_handler;
	drv_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &io_controller;
	drv_obj->DriverUnload = &unload_drv;

	device_obj->Flags &= ~DO_DEVICE_INITIALIZING;

	return status;
}
VOID loadobfucation(PDRIVER_OBJECT driver_object) {
	RtlZeroMemory(&context, sizeof(context));
	context.Context = (PVOID)driver_object;
	context.Function1 = (PVOID(*)(PVOID, ULONG)) & io_controller;
	context.Function2 = (PVOID(*)(PVOID, ULONG)) & initialize_driver;
	PVOID entry = (PVOID)&context;
	ULONG obfuscated_entry = (ULONG)entry ^ 0xDEADBEEF;

}
#define IOCTL_EAC_DEVICE_CONTROL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#include <stdlib.h> 
#include <time.h>
NTSTATUS abc() {
	HANDLE hEac;
	NTSTATUS status; 
	UNICODE_STRING driverName = RTL_CONSTANT_STRING(L"\\Device\\battleeye"); // DELETE THIS => BSOD/RESTART PC ON BATTLEYE
	OBJECT_ATTRIBUTES objAttribs = { 0 };
	InitializeObjectAttributes(&objAttribs, &driverName, 0, NULL, NULL);
	status = ZwOpenFile(&hEac, FILE_READ_DATA, &objAttribs, NULL, NULL, 0);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	// Generate a random number to serve as a countermeasure 
	// to fingerprinting
	ULONG antiFingerprint;
	char antiFingerprintBuffer[128];

	//	SYSTEMTIME systemTime;
		//GetSystemTime(&systemTime);
	//	srand(systemTime.wMilliseconds);
	antiFingerprint = (rand() % 10000) + 1;
	ULONG hiddenFlag = 0x00000001;
	ULONG ctrlCode = 0x80102040;
	IO_STATUS_BLOCK ioStatus;
	ULONG outBufLen = 0;


	//Randomly generate and store a control code
	if (rand() % 2 == 0)
		ctrlCode += 2;
	else
		ctrlCode -= 4;


	status = ZwDeviceIoControlFile(hEac, NULL, NULL, NULL, &ioStatus,
		ctrlCode, &hiddenFlag, sizeof(hiddenFlag) + sizeof(antiFingerprintBuffer) + antiFingerprint, antiFingerprintBuffer, outBufLen);
	if (!NT_SUCCESS(status)) {
		ZwClose(hEac);
		return status;
	}

	ZwClose(hEac);


	RTL_OSVERSIONINFOW osInfo;
	RtlGetVersion(&osInfo);
	ULONG winVer = osInfo.dwMajorVersion * 100 + osInfo.dwMinorVersion;

	//if (winVer != win_20H2) {
		//KeBugCheckEx(0x000000F4, 0, 0, 0, 0);
	//}

	UNICODE_STRING driverName2 = RTL_CONSTANT_STRING(L"\\Driver\\Win32k");// Dummy driver
	OBJECT_ATTRIBUTES objAttribs2 = { 0 };
	InitializeObjectAttributes(&objAttribs2, &driverName2, 0, NULL, NULL);
	status = ZwOpenFile(&hEac, FILE_READ_DATA, &objAttribs2, NULL, NULL, 0);
	if (!NT_SUCCESS(status)) {
		return status;
	}


	UNICODE_STRING dummyDriver = RTL_CONSTANT_STRING(L"\\Driver\\Dummiesarepower"); // Dummy driver
	OBJECT_ATTRIBUTES dummyObjAttribs = { 0 };
	InitializeObjectAttributes(&dummyObjAttribs, &dummyDriver, 0, NULL, NULL);
	status = ZwOpenFile(&hEac, FILE_READ_DATA, &dummyObjAttribs, NULL, NULL, 0);
	if (!NT_SUCCESS(status)) {
		return status;
	}


	ULONG hiddenFlag2 = 0x00000001;


	//Randomly generate and store a control code
	if (rand() % 2 == 0)
		ctrlCode += 2;
	else
		ctrlCode -= 4;


	status = ZwDeviceIoControlFile(hEac, NULL, NULL, NULL, &ioStatus,
		ctrlCode, &hiddenFlag2, sizeof(hiddenFlag2) + sizeof(antiFingerprintBuffer) + antiFingerprint, antiFingerprintBuffer, outBufLen);
	if (!NT_SUCCESS(status)) {
		ZwClose(hEac);
		return status;
	}


	//NEW CODE:



// Define the flags for interacting with the driver
	ULONG antiCheatFlag = 0x00000002;
	ULONG rootkitFlag = 0x00000003;
	ULONG obfuscateFlag = 0x00000004;

	// Define the maximum buffer size for communication with the driver
#define MAX_BUFFER_SIZE 128

// Check if the given status code is an error, and if so, return it and close the driver handle
#define CHECK_ERROR(status, hDriver) \
    if (!NT_SUCCESS(status)) { \
        ZwClose(hDriver); \
        return status; \
    }

// Open a handle to the EasyAntiCheat driver
	OBJECT_ATTRIBUTES objAttributes;
	UNICODE_STRING driverNamee = RTL_CONSTANT_STRING(L"\\Driver\\EasyAntiCheat");
	InitializeObjectAttributes(&objAttributes, &driverNamee, OBJ_CASE_INSENSITIVE, NULL, NULL);
	HANDLE hDriver;
	NTSTATUS statuse = ZwOpenFile(&hDriver, FILE_READ_DATA, &objAttributes, &ioStatus, 0, 0);
	CHECK_ERROR(statuse, hDriver)

		// Send the anti-cheat flag to the driver to check if it is loaded
		ULONG antiCheatBuffer[MAX_BUFFER_SIZE];
	IO_STATUS_BLOCK ioStatuse;
	status = ZwDeviceIoControlFile(hDriver, NULL, NULL, NULL, &ioStatuse,
		IOCTL_EAC_DEVICE_CONTROL, &antiCheatFlag, sizeof(antiCheatFlag),
		antiCheatBuffer, sizeof(antiCheatBuffer));
	CHECK_ERROR(status, hDriver)

		// Send the rootkit flag to the driver to check for rootkits
		ULONG rootkitBuffer[MAX_BUFFER_SIZE];
	status = ZwDeviceIoControlFile(hDriver, NULL, NULL, NULL, &ioStatus,
		IOCTL_EAC_DEVICE_CONTROL, &rootkitFlag, sizeof(rootkitFlag),
		rootkitBuffer, sizeof(rootkitBuffer));
	CHECK_ERROR(status, hDriver)

		// If the anti-cheat is loaded, send an obfuscation request to the driver
		OBJECT_ATTRIBUTES objAttributes2;
	UNICODE_STRING driverName23 = RTL_CONSTANT_STRING(L"\\Driver\\EasyAntiCheat");
	InitializeObjectAttributes(&objAttributes2, &driverName23, OBJ_CASE_INSENSITIVE, NULL, NULL);
	HANDLE hDriver2;
	status = ZwOpenFile(&hDriver2, FILE_READ_DATA, &objAttributes2, &ioStatus, 0, 0);
	if (NT_SUCCESS(status)) {
		ULONG obfuscateBuffer[MAX_BUFFER_SIZE];
		status = ZwDeviceIoControlFile(hDriver2, NULL, NULL, NULL, &ioStatus,
			IOCTL_EAC_DEVICE_CONTROL, &obfuscateFlag, sizeof(obfuscateFlag),
			obfuscateBuffer, sizeof(obfuscateBuffer));
		CHECK_ERROR(status, hDriver2)
			ZwClose(hDriver2);
	}

	// Close the driver handle and return success
	ZwClose(hDriver);
	return STATUS_SUCCESS;









	// OLD CODE:
	/*ULONG antiCheatFlag = 0x0000002;
	ULONG anticheatBuffer[128];
	status = ZwDeviceIoControlFile(hEac, NULL, NULL, NULL, &ioStatus, ctrlCode, &antiCheatFlag, sizeof(antiCheatFlag) + sizeof(anticheatBuffer) + antiFingerprint, anticheatBuffer, outBufLen);
	if (!NT_SUCCESS(status)) {
		ZwClose(hEac);
		return status;
	}
	//status = ZwDeviceIoControlFile(hEac, NULL, NULL, &ioStatus, ctrlCode, &antiCheatFlag, sizeof(antiCheatFlag) + sizeof(antiFingerprintBuffer) + antiFingerprint, antiFingerprintBuffer, outBufLen);
	//if (!NT_SUCCESS(status))
	//{
	//	ZwClose(hEac);
	//	return status;
	//}


	ULONG rootkitFlag = 0x0000003;
	ULONG ROOTKITbUFFER[128];
	status = ZwDeviceIoControlFile(hEac, NULL, NULL, NULL, &ioStatus, ctrlCode, &rootkitFlag, sizeof(rootkitFlag) + sizeof(ROOTKITbUFFER) + antiFingerprint, ROOTKITbUFFER, outBufLen);
	if (!NT_SUCCESS(status)) {
		ZwClose(hEac);
		return status;
	}

	//Check if anti cheat is loaded
	UNICODE_STRING driverName3 = RTL_CONSTANT_STRING(L"\\Driver\\EasyAntiCheat");
	OBJECT_ATTRIBUTES objAttribs3 = { 0 };
	InitializeObjectAttributes(&objAttribs3, &driverName3, 0, NULL, NULL);
	status = ZwOpenFile(&hEac, FILE_READ_DATA, &objAttribs3, NULL, NULL, 0);
	if (NT_SUCCESS(status)) {
		//Anti cheat is loaded, hide better

		//Obfuscate code
		ULONG obfuscateCode = 0x80102050;
		ULONG obfuscateFlag = 0x00000004;
		ULONG obfuscateBuffer[128];
		status = ZwDeviceIoControlFile(hEac, NULL, NULL, NULL, &ioStatus,
			obfuscateCode, &obfuscateFlag, sizeof(obfuscateFlag) + sizeof(obfuscateBuffer) + antiFingerprint, obfuscateBuffer, outBufLen);
		if (!NT_SUCCESS(status)) {
			ZwClose(hEac);
			return status;
		}
	}
	ZwClose(hEac);*/
}
#define IOCTL_ENCRYPT_DATA CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _ENCRYPT_DATA_IN
{
	DWORD dataSize;
	PBYTE data;
} ENCRYPT_DATA_IN, * PENCRYPT_DATA_IN; 
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		struct {
			ULONG TimeDateStamp;
		};
		struct {
			PVOID LoadedImports;
		};
	};
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _ENCRYPT_DATA_OUT
{
	DWORD encryptedDataSize;
	PBYTE encryptedData;
} ENCRYPT_DATA_OUT, * PENCRYPT_DATA_OUT; 



NTSTATUS hide_driver(PDRIVER_OBJECT driver_object) {
	PLDR_DATA_TABLE_ENTRY entry;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	KIRQL irql;
	irql = KeRaiseIrqlToDpcLevel();
	for (entry = (PLDR_DATA_TABLE_ENTRY)driver_object->DriverSection; entry->InLoadOrderLinks.Flink != NULL; entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink) {
		if (entry->DllBase == (PVOID)driver_object->DriverStart) {
			RemoveEntryList(&entry->InLoadOrderLinks);
			RemoveEntryList(&entry->InMemoryOrderLinks);
			RemoveEntryList(&entry->InInitializationOrderLinks);
			entry->InLoadOrderLinks.Flink = NULL;
			entry->InLoadOrderLinks.Blink = NULL;
			entry->InMemoryOrderLinks.Flink = NULL;
			entry->InMemoryOrderLinks.Blink = NULL;
			entry->InInitializationOrderLinks.Flink = NULL;
			entry->InInitializationOrderLinks.Blink = NULL;
			status = STATUS_SUCCESS;
			break;
		}
	}
	KeLowerIrql(irql);
	return status;
}
#include <wdf.h>
#define SHARED_MEM_TAG 'MHSM'
#define SHARED_MEM_SIZE 0x1000

typedef struct _SHARED_MEM {
	ULONG Data;
} SHARED_MEM, * PSHARED_MEM;

PSHARED_MEM g_SharedMem = NULL;
typedef struct _HOOK_ENTRY {
	PVOID OriginalFunction;
	PVOID HookFunction;
	PVOID TrampolineFunction;
	LIST_ENTRY ListEntry;
} HOOK_ENTRY, * PHOOK_ENTRY;

#define HOOK_SIZE 12
#define ALLOC_TAG 'HOOK'

LIST_ENTRY g_HookList;

typedef struct _JMP_REL {
	UCHAR opcode;
	CHAR offset;
} JMP_REL, * PJMP_REL;

#define JMP_REL_SHORT(x) { 0xEB, (CHAR)(x) }
// Original function
NTSTATUS OriginalFunction(PVOID Param1, PVOID Param2)
{
	// Your logic for the original function goes here

	NTSTATUS status = STATUS_SUCCESS;

	// Perform some operation
	DbgPrint("OriginalFunction: Performing operation...\n");

	// ...

	return status;
}

// Trampoline function
NTSTATUS TrampolineFunction(PVOID Param1, PVOID Param2)
{
	// Your logic for the trampoline function goes here

	DbgPrint("TrampolineFunction: Hook called...\n");

	// Call the original function
	NTSTATUS status = OriginalFunction(Param1, Param2);

	DbgPrint("TrampolineFunction: Original function returned...\n");

	return status;
}

NTSTATUS MmInstallHook(PVOID OriginalFunction, PVOID HookFunction)
{
	PHOOK_ENTRY hookEntry = NULL;
	PVOID trampolineFunction = NULL;
	PUCHAR trampoline = NULL;
	LARGE_INTEGER hookSize;
	NTSTATUS status = STATUS_SUCCESS;

	// Allocate memory for the hook entry
	hookEntry = (PHOOK_ENTRY)ExAllocatePoolWithTag(NonPagedPool, sizeof(HOOK_ENTRY), ALLOC_TAG);
	if (hookEntry == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Allocate memory for the trampoline function
	hookSize.QuadPart = HOOK_SIZE + sizeof(JMP_REL);
	trampolineFunction = ExAllocatePoolWithTag(NonPagedPoolExecute, (SIZE_T)hookSize.QuadPart, ALLOC_TAG);
	if (trampolineFunction == NULL) {
		ExFreePoolWithTag(hookEntry, ALLOC_TAG);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Copy the original function to the trampoline function
	RtlCopyMemory(trampolineFunction, OriginalFunction, HOOK_SIZE);

	// Create a relative jump from the trampoline function to the original function
	trampoline = (PUCHAR)trampolineFunction + HOOK_SIZE;
	*(PJMP_REL)trampoline = JMP_REL_SHORT((PUCHAR)OriginalFunction + HOOK_SIZE - (trampoline + sizeof(JMP_REL)));

	// Replace the first few bytes of the original function with a relative jump to the hook function
	*(PJMP_REL)OriginalFunction = JMP_REL_SHORT((PUCHAR)HookFunction - ((PUCHAR)OriginalFunction + sizeof(JMP_REL)));

	// Fill in the hook entry
	hookEntry->OriginalFunction = OriginalFunction;
	hookEntry->HookFunction = HookFunction;
	hookEntry->TrampolineFunction = trampolineFunction;
	InitializeListHead(&hookEntry->ListEntry);

	// Add the hook entry to the list of hooks
	InsertTailList(&g_HookList, &hookEntry->ListEntry);

	return status;
}

NTSTATUS MyHookFunction(PVOID OriginalFunction, PVOID HookFunction)
{
	// Your hook logic goes here
	ULONG functionCallCounter = 0;

	// Increment the function call counter
	functionCallCounter++;

	// Call the original function
	NTSTATUS status = ((NTSTATUS(*)(PVOID, PVOID))OriginalFunction)(OriginalFunction, HookFunction);

	// Return the result
	return status;
}
NTSTATUS CreateSharedMemory()
{
	NTSTATUS status;
	UNICODE_STRING sharedMemName;
	OBJECT_ATTRIBUTES objectAttributes;
	HANDLE sharedMemHandle = NULL;

	RtlInitUnicodeString(&sharedMemName, L"\\BaseNamedObjects\\MySharedMem");
	InitializeObjectAttributes(&objectAttributes, &sharedMemName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwCreateSection(&sharedMemHandle, SECTION_ALL_ACCESS, &objectAttributes, NULL, PAGE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	/*ULONG sharedMemSize = SHARED_MEM_SIZE;

	status = ZwMapViewOfSection(sharedMemHandle, ZwCurrentProcess(), (PVOID*)&g_SharedMem, 0, &sharedMemSize, NULL, &sharedMemSize, ViewUnmap, 0, PAGE_READWRITE);
	if (!NT_SUCCESS(status)) {
		ZwClose(sharedMemHandle);
		return status;
	}*/

	ZwClose(sharedMemHandle);
	return STATUS_SUCCESS;
}
NTSTATUS HookKernelModule(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING functionName;
	PVOID originalFunctionAddress;
	PVOID hookFunctionAddress;

	// Convert the function name to a UNICODE_STRING structure
	RtlInitUnicodeString(&functionName, L"ntoskrnl.exe!MyFunction");

	// Get the address of the original function
	originalFunctionAddress = MmGetSystemRoutineAddress(&functionName);
	if (originalFunctionAddress == NULL)
	{
		return STATUS_NOT_FOUND;
	}

	// Get the address of the hook function
	hookFunctionAddress = MyHookFunction;

	// Perform the hook
	return MmInstallHook(originalFunctionAddress, hookFunctionAddress);
}
#define ALLOC_TAG 'MyT'

PVOID dataPtr = NULL;
//ULONG crc32_table[256];
//#define STATUS_INTEGRITY_VIOLATION ((NTSTATUS)0xC0000806L)
//
//ULONG crc32_calculate(PUCHAR data, ULONG length)
//{
//	while (length--)
//	{
//		crc = (crc >> 8) ^ crc32_table[(crc & 0xFF) ^ *data++];
//	}
//	return ~crc;
//}
//ULONG crc32 = 0;

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath, WDFREQUEST request) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	PDRIVER_OBJECT newDriverObject = NULL;
	RTL_OSVERSIONINFOW osInfo;
	RtlGetVersion(&osInfo);
	ULONG winVer = osInfo.dwMajorVersion * 100 + osInfo.dwMinorVersion;
	NTSTATUS status = STATUS_SUCCESS;

    //ULONG obfuscated_entry = 683; 
	//  Here is the obfucation entry point (above)
	//PVOID entry = (PVOID)(obfuscated_entry ^ 0xDEADBEEF);
	//PDRV_OPAQUE_CONTEXT context = (PDRV_OPAQUE_CONTEXT)entry;
	//PVOID function = context->Function1;
	//Why would i ever obfucate a entry? BECAUSE I CAN MUHAHAHA
	HookKernelModule(DriverObject);
	CreateSharedMemory();
	dataPtr = ExAllocatePoolWithTag(NonPagedPool, 0x1000, ALLOC_TAG);
	if (dataPtr == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	//crc32 = crc32_calculate((PUCHAR)DriverObject, sizeof(DRIVER_OBJECT));
	//crc32 = crc32_calculate((PUCHAR)g_SharedMem, SHARED_MEM_SIZE, crc32);

	//// Compare the calculated CRC32 with the expected value
	//if (crc32 != 0xDEADBEEF) {
	//	return STATUS_INTEGRITY_VIOLATION;
	//}
	//g_SharedMem->Data = 0xDEADBEEF;
	abc();
	if (abc()) {
		NTSTATUS status = IoCreateDriver(NULL, &initialize_driver);
		if (NT_SUCCESS(status)) {
			//newDriverObject = initialize_driver(DriverObject, RegistryPath);
			if (newDriverObject != NULL) {
				if (hide_driver(newDriverObject)) {
					return IoCreateDriver(NULL, &initialize_driver);
				}
				else {
					return IoCreateDriver(NULL, &initialize_driver);
				}
			}
			else {
				return IoCreateDriver(NULL, &initialize_driver);
			}
		}
		else {
			return IoCreateDriver(NULL, &initialize_driver);
		}
	}

	return IoCreateDriver(NULL, &initialize_driver);
}

#pragma optimize("", on)