//
// structs
//
#pragma pack(push, 1)
typedef struct _BUFFER_STATS
{
	volatile LONG64 LostLogCount;   
	volatile LONG64 ReadLogCount;      
	volatile LONG64 WrittenLogCount;   
	volatile LONG64 OverwrittenCount; 
	volatile LONG64 TooBigErrorCount;
	volatile LONG64 TryZeroWriteCount;
	volatile LONG64 MissingDataCount;
	volatile LONG64 WrapedCount;
} BUFFER_STATS, * PBUFFER_STATS;

typedef struct _BUFFER_HEADER
{
	volatile LONG WriteOffset;
	volatile LONG ReadOffset;
	SIZE_T BufferSize;
	BUFFER_STATS Stats;
} BUFFER_HEADER, * PBUFFER_HEADER;

typedef struct _SHARED_MEMORY
{
	BUFFER_HEADER Header;
	UCHAR Data[1];
} SHARED_MEMORY, * PSHARED_MEMORY;

typedef struct _RING_BUFFER_CONTEXT
{
	PSHARED_MEMORY SharedMemoryKernelVA;
	PSHARED_MEMORY SharedMemoryUserVA;
	SIZE_T TotalSize;
} RING_BUFFER_CONTEXT, * PRING_BUFFER_CONTEXT;

typedef struct _RING_BUFFER_CONTEXTS
{
	SIZE_T ProcessorCount;
	RING_BUFFER_CONTEXT ProcessorBuffer[32];
} RING_BUFFER_CONTEXTS, * PRING_BUFFER_CONTEXTS;

typedef struct _LOG_ENTRY
{
	UINT64 Timestamp;     
	UINT64 Index;         
	UINT32 Processor;       
	UINT32 LogLevel;        
	UINT32 Length;      
	UINT32 Remarks;
	CHAR Data[1];         
} LogEntry, * PLOG_ENTRY;
#pragma pack(pop)

//
// variables
//
extern PRING_BUFFER_CONTEXTS g_LoggerMemorys;
extern volatile LONG64 g_GlobalIndexNumber;

//
// functions
//
extern NTSTATUS LogMessage(
	_In_ PCHAR Format,
	...
);

extern NTSTATUS SendData(
	_In_ UINT32 Type,
	_In_ UINT32 Remarks,
	_In_ PUCHAR Buffer,
	_In_ SIZE_T Len
);

extern NTSTATUS CreateSharedMemory(
	_In_ HANDLE ProcessId,
	_Out_ PSHARED_MEMORY_CONTEXT Context
);

extern NTSTATUS InitializeRingBufferEx(
	_Out_ PRING_BUFFER_CONTEXTS* Context,
	_In_ SIZE_T BufferSize,
	_Out_ PRING_BUFFER_CONTEXTS* UserVa
);

// CreateSharedMemory
// 	ProcessId: 	The process id
// 	Context: 	The shared memory context will be stored here
NTSTATUS
CreateSharedMemory(
	_In_ HANDLE ProcessId,
	_Out_ PSHARED_MEMORY_CONTEXT Context
)
{
	NTSTATUS status;
	PHYSICAL_ADDRESS lowAddress, highAddress;
	lowAddress.QuadPart = 0;
	highAddress.QuadPart = MAXLONGLONG;

	// Allocate memory from NonPaged pool
	Context->KernelVirtualAddress = MmAllocateContiguousMemorySpecifyCache(
		Context->Size,
		lowAddress,
		highAddress,
		lowAddress,
		MmCached);

	if (!Context->KernelVirtualAddress)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Create and build MDL
	Context->Mdl = IoAllocateMdl(
		Context->KernelVirtualAddress,
		(ULONG)Context->Size,
		FALSE,
		FALSE,
		NULL);

	if (!Context->Mdl)
	{
		MmFreeContiguousMemorySpecifyCache(
			Context->KernelVirtualAddress,
			Context->Size,
			MmCached);
		Context->KernelVirtualAddress = NULL;
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	MmBuildMdlForNonPagedPool(Context->Mdl);

	// Map the memory for user mode access
	__try
	{
		Context->UserVirtualAddress = MmMapLockedPagesSpecifyCache(
			Context->Mdl,
			UserMode,
			MmCached,
			NULL,
			FALSE,
			NormalPagePriority);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(Context->Mdl);
		Context->Mdl = NULL;
		MmFreeContiguousMemorySpecifyCache(
			Context->KernelVirtualAddress,
			Context->Size,
			MmCached);
		Context->KernelVirtualAddress = NULL;
		return STATUS_UNSUCCESSFUL;
	}

	Context->ProcessId = ProcessId;
	return STATUS_SUCCESS;
}

// InitializeRingBufferEx
// 	Context: 	The ring buffer context will be stored here
// 	BufferSize: The buffer size
// 	UserVa: 	The user mode virtual address will be stored here
NTSTATUS InitializeRingBufferEx(
	_Out_ PRING_BUFFER_CONTEXTS* Context,
	_In_ SIZE_T BufferSize,
	_Out_ PRING_BUFFER_CONTEXTS* UserVa
)
{
	SHARED_MEMORY_CONTEXT _ = {};
	RtlZeroMemory(&_, sizeof(SHARED_MEMORY_CONTEXT));

	_.Size = SIZE_ALIGN(sizeof(RING_BUFFER_CONTEXTS));
	_.ProcessId = processid;

	while(1)
	{
		if (NT_SUCCESS(CreateSharedMemory(processid, &_)))
		{
			RtlZeroMemory(_.KernelVirtualAddress, _.Size);
			break;
		}
		else
		{
			Sleep(1000);
		}
	}

	auto ctx = (PRING_BUFFER_CONTEXTS)_.KernelVirtualAddress;
	ULONG processorCount = KeQueryMaximumProcessorCount();
	ctx->ProcessorCount = processorCount;

	for (int i = 0; i < processorCount; i++)
	{
		SHARED_MEMORY_CONTEXT shmem = {};
		RtlZeroMemory(&shmem, sizeof(SHARED_MEMORY_CONTEXT));

		PHYSICAL_ADDRESS physAddr;
		physAddr.QuadPart = 0;

		auto aligned_size = SIZE_ALIGN(sizeof(BUFFER_HEADER) + BufferSize);

		shmem.Size = aligned_size;
		shmem.ProcessId = processid;

		while(1)
		{
			if (NT_SUCCESS(CreateSharedMemory(processid, &shmem)))
			{
				RtlZeroMemory(shmem.KernelVirtualAddress, shmem.Size);
				break;
			}

			if (shmem.KernelVirtualAddress && shmem.UserVirtualAddress)
			{
				break;
			}
		}

		ctx->ProcessorBuffer[i].SharedMemoryKernelVA = (PSHARED_MEMORY)shmem.KernelVirtualAddress;
		ctx->ProcessorBuffer[i].TotalSize = BufferSize;
		ctx->ProcessorBuffer[i].SharedMemoryUserVA = (PSHARED_MEMORY)shmem.UserVirtualAddress;
		if (!ctx->ProcessorBuffer[i].SharedMemoryKernelVA || !ctx->ProcessorBuffer[i].SharedMemoryUserVA)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		ctx->ProcessorBuffer[i].SharedMemoryKernelVA->Header.BufferSize = BufferSize;
	}

	*Context = ctx;
	*UserVa = (PRING_BUFFER_CONTEXTS)(_.UserVirtualAddress);

	return STATUS_SUCCESS;
}

// WriteToRingBuffer
// 	Context: 	The ring buffer context
// 	Data: 		The data to write
// 	Length: 	The data length
NTSTATUS WriteToRingBuffer(
	_In_ PRING_BUFFER_CONTEXT Context,
	_In_reads_bytes_(Length) PLOG_ENTRY Data,
	_In_ SIZE_T Length
)
{
	KIRQL oldIrql;
	KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);  // IRQL up to DISPATCH_LEVEL

	if (!Context)
	{
		KeLowerIrql(oldIrql);  // IRQL restore
		return STATUS_UNSUCCESSFUL;
	}

	if (!Context->SharedMemoryKernelVA)
	{
		KeLowerIrql(oldIrql);  // IRQL restore
		return STATUS_UNSUCCESSFUL;
	}
	
	if (!Data)
	{
		InterlockedIncrement64(&Context->SharedMemoryKernelVA->Header.Stats.MissingDataCount);
		InterlockedIncrement64(&Context->SharedMemoryKernelVA->Header.Stats.LostLogCount);
		KeLowerIrql(oldIrql);  // IRQL restore

		return STATUS_INVALID_PARAMETER;
	}

	if (Length == 0) 
	{
		InterlockedIncrement64(&Context->SharedMemoryKernelVA->Header.Stats.TryZeroWriteCount);
		InterlockedIncrement64(&Context->SharedMemoryKernelVA->Header.Stats.LostLogCount);
		KeLowerIrql(oldIrql);  // IRQL restore

		return STATUS_INVALID_PARAMETER;
	}

	if (Length > Context->SharedMemoryKernelVA->Header.BufferSize)
	{
		InterlockedIncrement64(&Context->SharedMemoryKernelVA->Header.Stats.TooBigErrorCount);
		InterlockedIncrement64(&Context->SharedMemoryKernelVA->Header.Stats.LostLogCount);
		KeLowerIrql(oldIrql);  // IRQL restore

		return STATUS_BUFFER_TOO_SMALL;
	}

	LONG currentWrite, currentRead, newWriteOffset;
	LONG expectedWrite;
	BOOLEAN success = FALSE;

	Data->Index = _InterlockedIncrement64(&g_GlobalIndexNumber);

	do
	{
		currentWrite = Context->SharedMemoryKernelVA->Header.WriteOffset;
		currentRead = Context->SharedMemoryKernelVA->Header.ReadOffset;
		expectedWrite = currentWrite;
		newWriteOffset = (currentWrite + Length) % Context->SharedMemoryKernelVA->Header.BufferSize;

		if (currentRead > currentWrite)
		{
			if (newWriteOffset >= currentRead)
			{
				InterlockedIncrement64(&Context->SharedMemoryKernelVA->Header.Stats.OverwrittenCount);
			}
		}
		else // currentRead <= currentWrite
		{
			if (newWriteOffset < currentWrite && newWriteOffset >= currentRead)
			{
				InterlockedIncrement64(&Context->SharedMemoryKernelVA->Header.Stats.OverwrittenCount);
			}
		}

		if (currentWrite + Length <= Context->SharedMemoryKernelVA->Header.BufferSize)
		{
			RtlCopyMemory(&Context->SharedMemoryKernelVA->Data[currentWrite], Data, Length);
		}
		else
		{
			// The data to be written is larger than the remaining space, so write as much as possible first, then overwrite from the beginning of the log buffer.
			SIZE_T firstPart = Context->SharedMemoryKernelVA->Header.BufferSize - currentWrite;
			RtlCopyMemory(&Context->SharedMemoryKernelVA->Data[currentWrite], Data, firstPart);
			RtlCopyMemory(&Context->SharedMemoryKernelVA->Data[0], (PUCHAR)Data + firstPart, Length - firstPart);
			InterlockedIncrement64(&Context->SharedMemoryKernelVA->Header.Stats.WrapedCount);
		}

		success = (InterlockedCompareExchange(
			&Context->SharedMemoryKernelVA->Header.WriteOffset,
			newWriteOffset,
			expectedWrite) == expectedWrite);

	} while (!success);

	InterlockedIncrement64(&Context->SharedMemoryKernelVA->Header.Stats.WrittenLogCount);
	KeLowerIrql(oldIrql);
	return STATUS_SUCCESS;
}

// SendData
// 	Type: 		The log type (LogLevel)
// 	Remarks: 	The remarks
// 	Buffer: 	The data buffer
// 	Len: 		The data buffer length
NTSTATUS SendData(
	_In_ UINT32 Type,
	_In_ UINT32 Remarks,
	_In_ PUCHAR Buffer,
	_In_ SIZE_T Len
)
{
	// TODO:
	// Clean this shit
	if (!g_LoggerMemorys || !g_LoggerMemorys->ProcessorBuffer[KeGetCurrentProcessorIndex()].SharedMemoryKernelVA ||
		!g_LoggerMemorys->ProcessorBuffer[KeGetCurrentProcessorIndex()].TotalSize)
	{
		return 0;
	}

	NTSTATUS status;
	SIZE_T messageLength = Len;

	// Get current system time
	auto perfCounter = KeQueryPerformanceCounter(NULL);

	// Calculate total entry size
	SIZE_T entrySize = sizeof(LogEntry) + messageLength;
	PLOG_ENTRY entry = (PLOG_ENTRY)ExAllocatePoolWithTag(NonPagedPool, entrySize, 'goLK');
	if (!entry)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Fill the entry
	entry->Timestamp = perfCounter.QuadPart;
	entry->LogLevel = Type;
	entry->Length = (UINT32)messageLength;
	entry->Processor = KeGetCurrentProcessorIndex();
	entry->Remarks = Remarks;
	RtlCopyMemory(entry->Data, Buffer, messageLength);

	status = WriteToRingBuffer(&g_LoggerMemorys->ProcessorBuffer[entry->Processor], entry, entrySize);

	ExFreePoolWithTag(entry, 'goLK');
	return status;
}

// LogMessage
// 	Format: 	The format string
// 	...: 		The arguments
NTSTATUS LogMessage(
	_In_ PCHAR Format,
	...
)
{
	if (!g_LoggerMemorys || !g_LoggerMemorys->ProcessorBuffer[KeGetCurrentProcessorIndex()].SharedMemoryKernelVA ||
		!g_LoggerMemorys->ProcessorBuffer[KeGetCurrentProcessorIndex()].TotalSize)
	{
		return 0;
	}

	NTSTATUS status;
	va_list args;
	SIZE_T messageLength;
	CHAR tempBuffer[0x1000];

	// Get current system time
	auto perfCounter = KeQueryPerformanceCounter(NULL);

	// Format the message
	va_start(args, Format);
	messageLength = _vsnprintf(tempBuffer, sizeof(tempBuffer) - 1, Format, args);
	va_end(args);

	if (messageLength == -1)
	{
		messageLength = sizeof(tempBuffer) - 1;
	}
	tempBuffer[messageLength] = '\0';

	// Calculate total entry size
	SIZE_T entrySize = sizeof(LogEntry) + messageLength;
	PLOG_ENTRY entry = (PLOG_ENTRY)ExAllocatePoolWithTag(NonPagedPool, entrySize, 'goLK');
	if (!entry)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Fill the entry
	entry->Timestamp = perfCounter.QuadPart;
	entry->LogLevel = 1;
	entry->Length = (UINT32)messageLength;
	entry->Processor = KeGetCurrentProcessorIndex();
	RtlCopyMemory(entry->Data, tempBuffer, messageLength);

	status = WriteToRingBuffer(&g_LoggerMemorys->ProcessorBuffer[entry->Processor], entry, entrySize);
	
	ExFreePoolWithTag(entry, 'goLK');
	return status;
}

// initialization example
//
void handler(void* info_struct)
{
	if (!info_struct || !MmIsAddressValid((PVOID)info_struct))
		return;

	INFO_STRUCT info = {};
	memcpy(&info, info_struct, sizeof(INFO_STRUCT));

	if (info.code == CODE_ENABLE_LOGGER)
	{
		while (true)
		{
			auto size = info.size;
			auto threadid = info.process_id;

			PRING_BUFFER_CONTEXTS userVa = 0;
			if (NT_SUCCESS(InitializeRingBufferEx(&g_LoggerMemorys, size, &userVa)) && g_LoggerMemorys)
			{
				LogMessage("Hello World!\n");

				*(PRING_BUFFER_CONTEXTS*)(info.address) = (PRING_BUFFER_CONTEXTS)userVa;
				return;
			}
		}
	}
	return;
}
