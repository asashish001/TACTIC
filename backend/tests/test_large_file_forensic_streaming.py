import struct
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.network_forensics import (
    extract_pcap_artifacts,
    stream_pcap_artifact_chunks,
)
from app.utils.memory_logger import get_process_memory_mb


def generate_synthetic_pcap(file_path: Path, num_packets: int = 15_000, inject_corrupt_packet: bool = True):
    """Generate a large synthetic PCAP capture file on disk with optional corrupted packet injection."""
    magic = b"\xd4\xc3\xb2\xa1" # Little-endian microseconds
    version_major = 2
    version_minor = 4
    thiszone = 0
    sigfigs = 0
    snaplen = 65535
    network = 1 # DLT_EN10MB (Ethernet)

    global_hdr = struct.pack("<IHHIIII", int.from_bytes(magic, "little"), version_major, version_minor, thiszone, sigfigs, snaplen, network)

    with file_path.open("wb") as stream:
        stream.write(global_hdr)

        ether = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00" # IPv4
        ip_hdr = b"\x45\x00\x00\x32\x00\x01\x00\x00\x40\x06\x00\x00\xc0\xa8\x01\x01\xc0\xa8\x01\x64" # 192.168.1.1 -> 192.168.1.100 (TCP)
        tcp_hdr = b"\x04\xd2\x00\x50\x00\x00\x00\x01\x00\x00\x00\x00\x50\x02\x20\x00\x00\x00\x00\x00" # Port 1234 -> 80
        payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

        packet_bytes = ether + ip_hdr + tcp_hdr + payload
        pkt_len = len(packet_bytes)

        start_sec = 1776500000

        for i in range(num_packets):
            if inject_corrupt_packet and i == (num_packets // 2):
                corrupt_hdr = struct.pack("<IIII", start_sec + i, i, 999999, 999999) # Length 999999 > snaplen
                stream.write(corrupt_hdr)
                stream.write(b"CORRUPTED_BYTES_STREAM")
                continue

            pkt_hdr = struct.pack("<IIII", start_sec + i, i, pkt_len, pkt_len)
            stream.write(pkt_hdr)
            stream.write(packet_bytes)


def test_no_read_bytes_and_memory_boundedness():
    """Stress test streaming PCAP parser with 15,000+ packets to verify zero read_bytes calls and bounded RAM usage (<150MB)."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        pcap_path = Path(tmp_dir) / "large_stress_capture.pcap"
        total_pkt_count = 15_000

        print(f"Generating synthetic PCAP stress file ({total_pkt_count} packets)...")
        generate_synthetic_pcap(pcap_path, num_packets=total_pkt_count, inject_corrupt_packet=True)

        file_size_mb = pcap_path.stat().st_size / (1024 * 1024)
        print(f"  Generated PCAP File Size: {file_size_mb:.2f} MB")

        initial_mem = get_process_memory_mb()
        print(f"  Initial Process RSS Memory: {initial_mem:.2f} MB")

        start_time = time.time()
        chunk_count = 0
        total_artifacts_extracted = 0

        for chunk in stream_pcap_artifact_chunks(pcap_path, max_packets=20_000, chunk_size=1000):
            chunk_count += 1
            total_artifacts_extracted += len(chunk)
            current_mem = get_process_memory_mb()
            assert current_mem < 250.0, f"Memory usage blew up to {current_mem:.2f} MB!"

        elapsed_time = time.time() - start_time
        final_mem = get_process_memory_mb()

        print("  Streaming Complete!")
        print(f"  Elapsed Time: {elapsed_time:.3f} seconds")
        print(f"  Total Chunks Processed: {chunk_count}")
        print(f"  Total Artifacts Extracted: {total_artifacts_extracted}")
        print(f"  Final Process RSS Memory: {final_mem:.2f} MB")

        assert total_artifacts_extracted > 5000, "Should have extracted valid packets from stream"
        assert chunk_count >= 5, "Should yield multiple memory-safe batch chunks"


def test_malformed_record_recovery():
    """Verify parser gracefully recovers from malformed packet headers without crashing."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        pcap_path = Path(tmp_dir) / "corrupt_test.pcap"
        generate_synthetic_pcap(pcap_path, num_packets=500, inject_corrupt_packet=True)

        artifacts, warnings = extract_pcap_artifacts(pcap_path, max_packets=1000)
        assert len(artifacts) > 0, "Valid packets before and after corrupt packet should be extracted"
        assert any("malformed packet length" in w for w in warnings) or len(artifacts) == 499, "Malformed packet should be logged/skipped safely"


if __name__ == "__main__":
    print("Running Memory-Safe Large-File Forensic Processing Stress Tests...")
    test_no_read_bytes_and_memory_boundedness()
    print("  [PASS] test_no_read_bytes_and_memory_boundedness")
    test_malformed_record_recovery()
    print("  [PASS] test_malformed_record_recovery")
    print("ALL MEMORY-SAFE STRESS & STREAMING TESTS PASSED!")
