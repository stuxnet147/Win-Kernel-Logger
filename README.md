# Win-Kernel-Logger
A lock-free, high-performance logging system designed for Windows kernel drivers that enables efficient data transfer between kernel and user mode. This implementation provides thread-safe logging with guaranteed ordering while minimizing performance impact.

## The reason why I made it
DbgView is a really great app, but I experienced multiple crashes while using it. That was quite frustrating for me...

## Key Features

- **Lock-Free Design**: Per-processor ring buffers eliminate inter-processor contention
- **Zero-Copy Architecture**: Direct memory sharing between kernel and user mode
- **Guaranteed Ordering**: Global atomic indexing ensures sequential consistency
- **High Performance**: Optimized for minimal overhead in kernel mode
- **Robust Error Handling**: Comprehensive statistics and wraparound handling
- **Thread Safety**: Safe for concurrent access from any IRQL

## Technical Implementation

### Memory Architecture

The system allocates separate ring buffers for each CPU processor, using shared memory mapped to both kernel and user mode:

```cpp
typedef struct _RING_BUFFER_CONTEXTS {
    SIZE_T ProcessorCount;
    RING_BUFFER_CONTEXT ProcessorBuffer[32];
} RING_BUFFER_CONTEXTS;
```

Each buffer is managed through a header containing read/write offsets and statistics:

```cpp
typedef struct _BUFFER_HEADER {
    volatile LONG WriteOffset;
    volatile LONG ReadOffset;
    SIZE_T BufferSize;
    BUFFER_STATS Stats;
} BUFFER_HEADER;
```

### Log Entry Format

Each log entry includes metadata for ordering and identification:

```cpp
typedef struct _LOG_ENTRY {
    UINT64 Timestamp;      // QPC timestamp
    UINT64 Index;          // Global sequential index
    UINT32 Processor;      // CPU ID
    UINT32 LogLevel;       // Log severity
    UINT32 Length;         // Data length
    UINT32 Remarks;        // Additional metadata
    CHAR Data[1];         // Variable-length log data
} LOG_ENTRY;
```

## Usage Guide

### 1. Initialization

Initialize the logging system with desired buffer size:

```cpp
PRING_BUFFER_CONTEXTS contexts = (PRING_BUFFER_CONTEXTS)driver_control::enable_logger((1024 * 1024) * 10);
```

### 2. Writing Logs (Kernel Mode)

Simple logging with formatted message:

```cpp
LogMessage("[Module] Message: %s", message);
```

Raw data logging with custom type:

```cpp
SendData(TYPE_CUSTOM, remarks, buffer, length);
```

### 3. Reading Logs (User Mode)

Set up a callback function:

```cpp
void LogCallback(PLOG_ENTRY entry, SIZE_T Length) {
    // Process log entry
    printf("[CPU%d][%lld] %.*s",
           entry->Processor,
           entry->Index,
           entry->Length,
           entry->Data);
}
```

Start reading logs:

```cpp
ReadLogs(contexts, LogCallback, TRUE); // TRUE for continuous reading
```

## Implementation Details

### Write Process

1. Raises IRQL to DISPATCH_LEVEL to prevent preemption
2. Atomically increments global index
3. Handles buffer wraparound if necessary
4. Uses InterlockedCompareExchange for thread-safe offset updates
5. Updates statistics

### Read Process

1. Scans all processor buffers
2. Finds entries with next sequential index
3. Handles wrapped entries
4. Updates read offset after successful processing
5. Maintains ordering using global index

## Performance Considerations

- Zero contention between processors during writes
- Minimal synchronization overhead
- Direct memory access without system calls
- Efficient handling of buffer wraparound
- No memory allocation during normal operation

## Statistics and Monitoring

The system maintains comprehensive statistics:

```cpp
typedef struct _BUFFER_STATS {
    volatile LONG64 LostLogCount;      // Write failures
    volatile LONG64 ReadLogCount;      // Successfully read
    volatile LONG64 WrittenLogCount;   // Successfully written
    volatile LONG64 OverwrittenCount;  // Overwritten logs
    volatile LONG64 TooBigErrorCount;  // Size limit exceeded
    volatile LONG64 WrapedCount;       // Buffer wraps
} BUFFER_STATS;
```

## Use Cases

This logging system is particularly useful for:

1. Kernel-mode debugging and diagnostics
2. High-performance event logging
3. **Kernel-to-user mode data transfer**
4. Network packet capture
5. System monitoring and profiling

## Best Practices

1. Size buffers appropriately for your workload
2. Monitor statistics to detect buffer overflow
3. Process logs promptly in user mode
4. Handle wraparound conditions properly
5. Consider log levels for filtering

## Error Handling

The system includes robust error handling for:

- Buffer overflow conditions
- Invalid parameters
- Memory allocation failures
- Wraparound scenarios
- Missing or corrupted data

## Limitations and Considerations

- Maximum 32 processors supported by default
- Buffer size must be pre-allocated
- Older logs may be overwritten if not read quickly enough
- Memory usage scales with processor count
