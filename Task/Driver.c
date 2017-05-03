#include "util.h"


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath);
void DriverUnload(PDRIVER_OBJECT pDriverObject);
NTSTATUS DriverHandler(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS DriverCreateClose(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
 NTSTATUS DriverDefaultHandler(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);


static void DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING uDeviceSymbol = RTL_CONSTANT_STRING(L"\\??\\TaskManager");
	IoDeleteSymbolicLink(&uDeviceSymbol);
	IoDeleteDevice(pDriverObject->DeviceObject);
	DbgPrint("DriverUnload\n");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	INT i = 0;
	NTSTATUS status;
	PDEVICE_OBJECT pDeviceObject = NULL;
	UNICODE_STRING uDeviceName = RTL_CONSTANT_STRING(L"\\Device\\TaskManager");
	UNICODE_STRING uDeviveSymbol = RTL_CONSTANT_STRING(L"\\??\\TaskManager");


	for (; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		pDriverObject->MajorFunction[i] = DriverDefaultHandler;
	}
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverHandler;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
	pDriverObject->DriverUnload = DriverUnload;

	status = IoCreateDevice(pDriverObject, 0, &uDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("IoCreateDevice Error\n");
		return status;
	}
	pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	
	treatPspCildTable(getHandleTable(getPspClidTable()));
	return status;
}

static NTSTATUS DriverDefaultHandler(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return pIrp->IoStatus.Status;
}

static NTSTATUS DriverHandler(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	PIO_STACK_LOCATION pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);
	ULONG uControlCode = pIoStackLocation->Parameters.DeviceIoControl.IoControlCode;
	switch (uControlCode)
	{
		return STATUS_SUCCESS;
	default:
	{
		pIrp->IoStatus.Information = 0;
		pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
		IoCompleteRequest(pIrp,IO_NO_INCREMENT);
		return pIrp->IoStatus.Status;
	}
	break;
	}
}

static NTSTATUS DriverCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}