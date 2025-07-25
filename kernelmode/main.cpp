#include <ntifs.h>
extern "C" {
	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName,
		PDRIVER_INITIALIZE InitializationFunction);

	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress,
		PEPROCESS TargetProcess, PVOID TargetAddress,
		SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode,
		PSIZE_T ReturnSize);
}

void D_DbgPrint(PCSTR text) {
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, text));
}

namespace driver {
	namespace codes {
		// Attaches driver to target process
		constexpr ULONG attach = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); // all CTL_CODE codes under 0x800 are reserved for windows 
		// Read Memory
		constexpr ULONG read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
		// Write Memory
		constexpr ULONG write = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		constexpr ULONG write_ignore_read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	}

	// Request (structure shared between usermode and kernel)
	struct Request {
		HANDLE process_id;

		PVOID target_address;
		PVOID buffer;

		SIZE_T size;
		SIZE_T returnsize;
	};

	NTSTATUS create(PDEVICE_OBJECT device_object, PIRP irp) { // IRP Handler for IRP_MJ_CREATE. called when a usermode application tries to open a handle to the device
		UNREFERENCED_PARAMETER(device_object);

		// Signals to teh Iomanager that the irp request has been processed and completed
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return irp->IoStatus.Status;
	}
	NTSTATUS close(PDEVICE_OBJECT device_object, PIRP irp) { // IRP Handler for IRP_MJ_CLOSE. called when the handle to the device is closed.
		UNREFERENCED_PARAMETER(device_object);

		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return irp->IoStatus.Status;
	}
	NTSTATUS device_control(PDEVICE_OBJECT device_object, PIRP irp) { // IRP Handler for IRP_MJ_DEVICE_CONTROL sent be DeviceIoControl (from usermode). (allows custom operations)
		UNREFERENCED_PARAMETER(device_object);

		D_DbgPrint("[DEBUG] DEVICE CONTROLL CALLED\n");

		NTSTATUS status = STATUS_UNSUCCESSFUL;
		// Gets the location of the Irps stack location. (IRP has its own stack)
		PIO_STACK_LOCATION stack_irp = IoGetCurrentIrpStackLocation(irp);
		//Access request object sent from usermode by accessing the buffer, associatedIrp.SystemBuffer and casting that into our request object;
		auto request_object = reinterpret_cast<Request*>(irp->AssociatedIrp.SystemBuffer);
		
		if (stack_irp == nullptr && request_object == nullptr) {
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return status;
		}
		// target process to access
		static PEPROCESS target_process = nullptr;

		// Control code sent in the Irp
		const ULONG control_code = stack_irp->Parameters.DeviceIoControl.IoControlCode;
		switch (control_code)
		{
		case codes::attach:
			status = PsLookupProcessByProcessId(request_object->process_id, &target_process);
			break;

		case codes::read:
			if (target_process != nullptr) { // MmCopyVirtualmemomry requires 2 EPROCESS structures, the target PROCESS and the source PROCESS (kernel driver) to write memory to
				status = MmCopyVirtualMemory(target_process, request_object->target_address,
											 PsGetCurrentProcess(), request_object->buffer ,
											 request_object->size, KernelMode, &request_object->returnsize
										    );
			}
			break;
		case codes::write:
			if (target_process != nullptr) {
				status = MmCopyVirtualMemory(PsGetCurrentProcess(), request_object->buffer,
					target_process, request_object->target_address,
					request_object->size, KernelMode, &request_object->returnsize
				);
			}
			break;
		case codes::write_ignore_read:
			if (target_process != nullptr) {
				KAPC_STATE apc;
				KeStackAttachProcess(target_process, &apc);

				PMDL mdl = IoAllocateMdl(request_object->target_address, request_object->size, FALSE, FALSE, NULL);
				if (!mdl)
					return false;
				MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
				PVOID Mapping = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
				MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);

				status = MmCopyVirtualMemory(PsGetCurrentProcess(), request_object->buffer,
					target_process, request_object->target_address,
					request_object->size, KernelMode, &request_object->returnsize
				);

				MmUnmapLockedPages(Mapping, mdl);
				MmUnlockPages(mdl);
				IoFreeMdl(mdl);
				KeUnstackDetachProcess(&apc);
			}
			break;
		default:
			break;
		}

		irp->IoStatus.Status = status;
		irp->IoStatus.Information = sizeof(Request);
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return status;
	}
}

NTSTATUS main(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) { // Real entry
	UNREFERENCED_PARAMETER(registry_path);

	// create a device for our kernel driver for i/o communication with usermode
	UNICODE_STRING device_name = {};
	RtlInitUnicodeString(&device_name, L"\\Device\\BigBallsDriver");
	// Create a device object
	PDEVICE_OBJECT device_object = nullptr;
	NTSTATUS status = IoCreateDevice(driver_object, 0, &device_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_object);

	if (status != STATUS_SUCCESS) {
		D_DbgPrint("[ERROR] FAILED TO CREATE DRIVER\n");
		return status;
	}
	D_DbgPrint("[DEBUG] DEVICE OBJECT CREATED SUCCESFULLY\n");

	// Create a symbolic link which is used to expose a name/alias of the device that is accessable from usermode
	UNICODE_STRING symbolic_link = {};
	RtlInitUnicodeString(&symbolic_link, L"\\DosDevices\\BigBallsDriver");
	status = IoCreateSymbolicLink(&symbolic_link, &device_name);

	if (status != STATUS_SUCCESS) {
		D_DbgPrint("[ERROR] FAILED TO CREATE SYMBOLIC LINK\n");
		return status;
	}
	D_DbgPrint("[DEBUG] SYMBOLIC LINK ESTABLISHED SUCCESFULLY\n");
	// Add a flag to the device object which allows buffered io communication between usermode and kernelmode
	SetFlag(device_object->Flags, DO_BUFFERED_IO);
	//Setup the driver io request handler functions to our functions.
	driver_object->MajorFunction[IRP_MJ_CREATE] = driver::create;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = driver::close;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver::device_control;

	// This flag is cleared as it signals to the Io manager that device initialisation is done by removing teh flag that marks initialising as not done
	ClearFlag(device_object->Flags, DO_DEVICE_INITIALIZING);
	D_DbgPrint("[DEBUG] DEVICE INITIALISATION FINISHED\n");
	return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) { // Driver Entry for mappper (parameters are unsued)
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	D_DbgPrint("[DEBUG] SYNTAX DRIVER RUNNING\n");

	// Create a proper driver and specify real entrypoint
	UNICODE_STRING driver_name = {};
	RtlInitUnicodeString(&driver_name, L"\\Driver\\BigBallsDriver");
	return IoCreateDriver(&driver_name,&main);
}