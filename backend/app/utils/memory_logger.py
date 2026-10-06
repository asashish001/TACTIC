"""Memory usage tracking and logging utilities for forensic analysis pipelines."""
import logging
import sys
import tracemalloc

logger = logging.getLogger("tactic.memory_logger")

try:
    tracemalloc.start()
except Exception:
    pass


def get_process_memory_mb() -> float:
    """Return process resident set size (RSS) memory usage in megabytes."""
    try:
        current, _peak = tracemalloc.get_traced_memory()
        if current > 0:
            return current / (1024 * 1024)
    except Exception:
        pass

    if sys.platform == "win32":
        try:
            import ctypes
            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", ctypes.c_ulong),
                    ("PageFaultCount", ctypes.c_ulong),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t)
                ]
            counters = PROCESS_MEMORY_COUNTERS()
            ctypes.windll.psapi.GetProcessMemoryInfo(
                ctypes.windll.kernel32.GetCurrentProcess(),
                ctypes.byref(counters),
                ctypes.sizeof(counters)
            )
            return counters.WorkingSetSize / (1024 * 1024)
        except Exception:
            pass

    try:
        import resource
        usage = resource.getrusage(resource.RUSAGE_SELF)
        multiplier = 1.0 / 1024 if sys.platform != "darwin" else 1.0 / (1024 * 1024)
        return usage.ru_maxrss * multiplier
    except Exception:
        pass

    return 0.0


def log_memory_usage(tag: str = "Pipeline Step") -> float:
    """Log process RSS memory usage and return value in MB."""
    mem_mb = get_process_memory_mb()
    logger.info("[MEMORY-LOG] %s | Process Memory RSS: %.2f MB", tag, mem_mb)
    return mem_mb
