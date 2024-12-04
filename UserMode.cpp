//
// structures
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
	UINT64 Timestamp;        // QPC value
    UINT64 Index;         
    UINT32 Processor;         
    UINT32 LogLevel;        
    UINT32 Length;
    UINT32 Remarks;
    CHAR Data[1];        
} LOG_ENTRY, * PLOG_ENTRY;
#pragma pack(pop)

typedef struct _READ_CONTEXT
{
	UINT64 LastSeenIndex;
	BOOL FoundNext;
} READ_CONTEXT, * PREAD_CONTEXT;

struct EntryLocation
{
    const LOG_ENTRY* entry;
    size_t entrySize;
    bool operator<(const EntryLocation& other) const
    {
        return entry->Index < other.entry->Index;
    }
};

typedef void (*LogCallback)(PLOG_ENTRY Entry, SIZE_T Length);

// 
// functions
//

void LogCallbackFunc(PLOG_ENTRY entry, SIZE_T Length)
{
	if (entry->LogLevel == 1)
		{
			printf("[CPU%d][%lld] [%lld] Level %d: %.*s",
				entry->Processor,
				entry->Index,
				entry->Timestamp,
				entry->LogLevel,
				entry->Length,
				entry->Data);
		}
}

NTSTATUS ReadNextLogEntry(
	_In_ PRING_BUFFER_CONTEXTS Contexts,
	_In_ PREAD_CONTEXT ReadCtx,
	_In_ LogCallback Callback
)
{
	static PLOG_ENTRY tempEntry = (PLOG_ENTRY)malloc(sizeof(LOG_ENTRY));
	__try
	{
		ReadCtx->FoundNext = FALSE;
		PLOG_ENTRY bestEntry = NULL;
		SIZE_T bestEntrySize = 0;
		PSHARED_MEMORY bestSharedMem = NULL;
		LONG bestReadOffset = 0;

		// Check all processor buffers for the next index
		for (SIZE_T i = 0; i < Contexts->ProcessorCount; i++)
		{
			PRING_BUFFER_CONTEXT procBuffer = &Contexts->ProcessorBuffer[i];
			PSHARED_MEMORY sharedMem = procBuffer->SharedMemoryUserVA;

			if (!sharedMem)
			{
				continue;
			}

			LONG currentRead = sharedMem->Header.ReadOffset;
			LONG currentWrite = sharedMem->Header.WriteOffset;

			// Skip if no new data
			if (currentRead == currentWrite)
			{
				continue;
			}

			// Check current buffer for next log entry
			LONG readPos = currentRead;
			while (readPos != currentWrite)
			{
				PLOG_ENTRY entry;
				BOOL isWrapped = FALSE;
				SIZE_T entryTotalSize;

				// Handle wrapped entry
				if (readPos + sizeof(LOG_ENTRY) > sharedMem->Header.BufferSize)
				{
					RtlZeroMemory(tempEntry, sizeof(LOG_ENTRY));
					// Allocate temp buffer for header
					entry = (PLOG_ENTRY)tempEntry;

					// Copy split header
					SIZE_T firstPart = sharedMem->Header.BufferSize - readPos;
					memcpy(entry, &sharedMem->Data[readPos], firstPart);
					memcpy((PUCHAR)entry + firstPart, &sharedMem->Data[0],
						sizeof(LOG_ENTRY) - firstPart);

					isWrapped = TRUE;
				}
				else
				{
					entry = (PLOG_ENTRY)&sharedMem->Data[readPos];
				}

				entryTotalSize = sizeof(LOG_ENTRY) + entry->Length;

				// Found a candidate for next index
				if (entry->Index == ReadCtx->LastSeenIndex + 1)
				{
					if (!bestEntry || entry->Index < bestEntry->Index)
					{
						bestEntry = entry;
						bestEntrySize = entryTotalSize;
						bestSharedMem = sharedMem;
						bestReadOffset = readPos;
					}
				}

				// Move to next entry
				if (isWrapped)
				{
					readPos = (sizeof(LOG_ENTRY) -
						(sharedMem->Header.BufferSize - readPos));
				}
				else
				{
					readPos = (readPos + entryTotalSize) %
						sharedMem->Header.BufferSize;
				}
			}
		}

		// Process best entry found (if any)
		if (bestEntry)
		{
			// Handle wrapped entry
			if (bestReadOffset + bestEntrySize > bestSharedMem->Header.BufferSize)
			{
				PLOG_ENTRY tempEntry = (PLOG_ENTRY)malloc(bestEntrySize);
				if (!tempEntry)
				{
					return STATUS_NO_MEMORY;
				}

				// Copy wrapped data
				SIZE_T firstPart = bestSharedMem->Header.BufferSize - bestReadOffset;
				memcpy(tempEntry, &bestSharedMem->Data[bestReadOffset], firstPart);
				memcpy((PUCHAR)tempEntry + firstPart, &bestSharedMem->Data[0],
					bestEntrySize - firstPart);

				Callback(tempEntry, bestEntrySize);
				free(tempEntry);

				// Update read offset
				bestSharedMem->Header.ReadOffset = bestEntrySize - firstPart;
			}
			else
			{
				Callback(bestEntry, bestEntrySize);
				bestSharedMem->Header.ReadOffset =
					(bestReadOffset + bestEntrySize) %
					bestSharedMem->Header.BufferSize;
			}

			InterlockedIncrement64(&bestSharedMem->Header.Stats.ReadLogCount);
			ReadCtx->LastSeenIndex = bestEntry->Index;
			ReadCtx->FoundNext = TRUE;
			return 0;
		}
		return 3;
	}
	__except (1)
	{
		return 3;
	}
}

NTSTATUS ReadLogs(
	_In_ PRING_BUFFER_CONTEXTS Contexts,
	_In_ LogCallback Callback,
	_In_ BOOL ContinuousRead
)
{
	__try
	{
		if (!Contexts || !Callback)
		{
			return STATUS_INVALID_PARAMETER;
		}

		READ_CONTEXT readCtx = { 0 };

		do
		{
			NTSTATUS status = ReadNextLogEntry(Contexts, &readCtx, Callback);

			if (status == 3)
			{
				if (ContinuousRead)
				{
					Sleep(10); // Prevent pc fire
					continue;
				}
				break;
			}

			if (!NT_SUCCESS(status))
			{
				return status;
			}
		} while (ContinuousRead || readCtx.FoundNext);

		MessageBoxA(NULL, "ReadLogs End", "", MB_OK);
	}
	__except (1)
	{

	}

	return 0;
}

int main()
{
	__try
	{
		PRING_BUFFER_CONTEXTS contexts = (PRING_BUFFER_CONTEXTS)driver_control::enable_logger((1024 * 1024) * 10);
		if (!contexts)
		{
			MessageBoxA(NULL, "Failed to enable logger", "Error", MB_OK);
			return -1;
		}

		// Read logs continuously
		while(1)
		{
			ReadLogs(contexts, LogCallbackFunc, TRUE);
		}
	}
	__except (1)
	{

	}
	return 0;
}
