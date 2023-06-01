#include"file_utils.h"

//filePathΪDLL�ļ��ڵ����ϵ�·��

//ppebufferΪδ�����PE��������

NTSTATUS GetPeFileToBuffer(CONST IN PCHAR filePath, OUT PVOID* pPeBuffer)
{
	NTSTATUS status;

	HANDLE hfile;

	UNICODE_STRING unicodeFilePath = { 0 };

	OBJECT_ATTRIBUTES objectAttributes = { 0 };

	IO_STATUS_BLOCK iostatus = { 0 };

	FILE_STANDARD_INFORMATION fileInfo = { 0 };

	STRING strTemp = { 0 };

	RtlInitString(&strTemp, filePath);

	//���ļ�·��ת��ΪUNICODE_STRING

	RtlAnsiStringToUnicodeString(&unicodeFilePath, &strTemp, TRUE);

	InitializeObjectAttributes(&objectAttributes,

		&unicodeFilePath,

		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,

		NULL,

		NULL);

	// ���ļ�
	status = ZwCreateFile(&hfile,

		GENERIC_READ | GENERIC_WRITE,

		&objectAttributes,

		&iostatus,

		NULL,

		FILE_ATTRIBUTE_NORMAL,

		FILE_SHARE_READ,

		FILE_OPEN_IF,

		FILE_NON_DIRECTORY_FILE | FILE_RANDOM_ACCESS | FILE_SYNCHRONOUS_IO_NONALERT,

		NULL,

		0);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = ZwQueryInformationFile(hfile,

		&iostatus,

		&fileInfo,

		sizeof(FILE_STANDARD_INFORMATION),

		FileStandardInformation);

	if (!NT_SUCCESS(status))
	{
		ZwClose(hfile);

		return status;
	}


	if (!(ULONG)fileInfo.EndOfFile.QuadPart)
	{
		ZwClose(hfile);

		DbgPrint("������Ҫ������ļ�!\n");

		return STATUS_UNSUCCESSFUL;
	}


	//Ϊ��ȡ���ļ����仺����

	PVOID peBuffer = (PUCHAR)ExAllocatePool(PagedPool, (ULONG)fileInfo.EndOfFile.QuadPart);

	//���ļ�

	if (!peBuffer)
	{
		ZwClose(hfile);

		return STATUS_UNSUCCESSFUL;
	}

	RtlZeroMemory(peBuffer, (ULONG)fileInfo.EndOfFile.QuadPart);

	LARGE_INTEGER  nFileLen = { 0 };

	nFileLen.QuadPart = 0;

	ULONG FileLen = 0;

	FileLen = (ULONG)fileInfo.EndOfFile.QuadPart;

	status = ZwReadFile(hfile,

		NULL,

		NULL,

		NULL,

		&iostatus,

		peBuffer,

		FileLen,

		&nFileLen,

		NULL);


	if (!NT_SUCCESS(status))
	{
		ZwClose(hfile);

		ExFreePool(peBuffer);

		return status;
	}


	ZwClose(hfile);

	*pPeBuffer = peBuffer;

	return status;
}
