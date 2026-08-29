"""Dependency-free memory-safe streaming extraction of common PCAP/PCAPNG and firewall-log artifacts."""
import datetime
import logging
import re
import struct
from pathlib import Path
from typing import Generator

from app.utils.memory_logger import log_memory_usage

logger = logging.getLogger("tactic.network_forensics")

IP_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
PORT_PATTERN = re.compile(r"\b(?:DPT|DST|DESTINATION_PORT|dst_port)[=:\s]+(\d{1,5})\b", re.IGNORECASE)
ACTION_PATTERN = re.compile(r"\b(ALLOW|ACCEPT|DENY|DROP|BLOCK)\b", re.IGNORECASE)


def _timestamp(seconds: int, fraction: int, nanoseconds: bool = False) -> str:
    try:
        value = seconds + fraction / (1_000_000_000 if nanoseconds else 1_000_000)
        from app.services.timezone_service import normalize_to_utc
        utc_dt, _, _ = normalize_to_utc(value)
        if utc_dt:
            return utc_dt.isoformat()
        return datetime.datetime.fromtimestamp(value, tz=datetime.timezone.utc).isoformat()
    except Exception as exc:
        logger.debug("Timestamp normalization failed: %s", exc)
        return ""


def _ip(value: bytes) -> str:
    return ".".join(str(part) for part in value)


def _dns_name(payload: bytes) -> str | None:
    if len(payload) < 13:
        return None
    cursor, labels = 12, []
    try:
        while cursor < len(payload):
            length = payload[cursor]
            if length == 0:
                return ".".join(labels) or None
            if length > 63 or cursor + length >= len(payload):
                return None
            labels.append(payload[cursor + 1:cursor + 1 + length].decode("idna"))
            cursor += length + 1
    except UnicodeError:
        return None
    return None


def _http_host(payload: bytes) -> str | None:
    if not payload.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"CONNECT ", b"DELETE ")):
        return None
    match = re.search(br"\r?\nHost:\s*([^\r\n]+)", payload[:8192], re.IGNORECASE)
    return match.group(1).decode("utf-8", errors="replace").strip() if match else None


def _packet_artifacts(packet: bytes, timestamp: str) -> list[dict]:
    """Parse Ethernet + IPv4 + TCP/UDP traffic from one captured packet."""
    if len(packet) < 14:
        return []
    offset = 14
    ether_type = int.from_bytes(packet[12:14], "big")
    if ether_type == 0x8100 and len(packet) >= 18:
        ether_type, offset = int.from_bytes(packet[16:18], "big"), 18
    if ether_type != 0x0800 or len(packet) < offset + 20:
        return []
    version_ihl = packet[offset]
    if version_ihl >> 4 != 4:
        return []
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(packet) < offset + ihl:
        return []
    protocol_id = packet[offset + 9]
    source, destination = _ip(packet[offset + 12:offset + 16]), _ip(packet[offset + 16:offset + 20])
    transport = offset + ihl
    if protocol_id not in {6, 17} or len(packet) < transport + 4:
        return [{"artifact_type": "flow", "timestamp": timestamp, "source_ip": source, "destination_ip": destination, "source_port": None, "destination_port": None, "protocol": {1: "ICMP"}.get(protocol_id, f"IP-{protocol_id}"), "value": None, "details": {}}]
    src_port, dst_port = struct.unpack("!HH", packet[transport:transport + 4])
    protocol = "TCP" if protocol_id == 6 else "UDP"
    artifacts = [{"artifact_type": "flow", "timestamp": timestamp, "source_ip": source, "destination_ip": destination, "source_port": src_port, "destination_port": dst_port, "protocol": protocol, "value": None, "details": {}}]
    if protocol == "UDP" and len(packet) >= transport + 8:
        payload = packet[transport + 8:]
        if src_port == 53 or dst_port == 53:
            query = _dns_name(payload)
            if query:
                artifacts.append({**artifacts[0], "artifact_type": "dns_query", "value": query})
    elif protocol == "TCP" and len(packet) >= transport + 20:
        data_offset = ((packet[transport + 12] >> 4) & 0x0F) * 4
        payload = packet[transport + data_offset:] if data_offset >= 20 else b""
        host = _http_host(payload)
        if host:
            artifacts.append({**artifacts[0], "artifact_type": "http_host", "value": host})
    return artifacts


def stream_pcap_packets(
    path: Path,
    max_packets: int = 50_000,
    warnings: list[str] | None = None
) -> Generator[tuple[str, bytes], None, None]:
    """Stream PCAP packets directly from disk without loading file into RAM."""
    if warnings is None:
        warnings = []
    count = 0

    try:
        with path.open("rb") as stream:
            hdr_data = stream.read(24)
            if len(hdr_data) < 24:
                warnings.append(f"{path.name}: PCAP header is incomplete.")
                return

            magic = hdr_data[:4]
            formats = {
                b"\xd4\xc3\xb2\xa1": ("<", False),
                b"\xa1\xb2\xc3\xd4": (">", False),
                b"\x4d\x3c\xb2\xa1": ("<", True),
                b"\xa1\xb2\x3c\x4d": (">", True)
            }
            if magic not in formats:
                warnings.append(f"{path.name}: unsupported PCAP byte order.")
                return

            endian, nanoseconds = formats[magic]

            while count < max_packets:
                pkt_hdr = stream.read(16)
                if not pkt_hdr:
                    break
                if len(pkt_hdr) < 16:
                    warnings.append(f"{path.name}: truncated packet header at packet #{count+1}.")
                    break

                seconds, fraction, captured_length, _ = struct.unpack(f"{endian}IIII", pkt_hdr)
                if captured_length > 65535 or captured_length < 0:
                    warnings.append(f"{path.name}: malformed packet length ({captured_length}) encountered at packet #{count+1}.")
                    break

                payload = stream.read(captured_length)
                if len(payload) < captured_length:
                    warnings.append(f"{path.name}: truncated packet payload at packet #{count+1}.")
                    break

                ts_str = _timestamp(seconds, fraction, nanoseconds)
                count += 1
                yield (ts_str, payload)

    except Exception as exc:
        warnings.append(f"{path.name}: streaming error ({exc}).")


def stream_pcapng_packets(
    path: Path,
    max_packets: int = 50_000,
    warnings: list[str] | None = None
) -> Generator[tuple[str, bytes], None, None]:
    """Stream PCAPNG packets directly from disk without loading file into RAM."""
    if warnings is None:
        warnings = []
    count = 0
    endian = "<"

    try:
        with path.open("rb") as stream:
            while count < max_packets:
                block_hdr = stream.read(8)
                if not block_hdr:
                    break
                if len(block_hdr) < 8:
                    warnings.append(f"{path.name}: truncated PCAPNG block header.")
                    break

                block_type = int.from_bytes(block_hdr[:4], "little")
                length = int.from_bytes(block_hdr[4:8], "little")

                if length < 12:
                    warnings.append(f"{path.name}: invalid PCAPNG block length {length}.")
                    break

                body = stream.read(length - 8)
                if len(body) < length - 8:
                    warnings.append(f"{path.name}: truncated PCAPNG block body.")
                    break

                block = block_hdr + body

                if block_type == 0x0A0D0D0A and len(block) >= 16:
                    endian = "<" if block[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
                elif block_type == 0x00000006 and len(block) >= 32:
                    interface_id, high, low, captured_length, _ = struct.unpack(f"{endian}IIIII", block[8:28])
                    packet_start = 28
                    packet_end = packet_start + captured_length
                    if packet_end <= len(block) - 4:
                        ts_str = _timestamp((high << 32 | low) // 1_000_000, (high << 32 | low) % 1_000_000)
                        count += 1
                        yield (ts_str, block[packet_start:packet_end])

    except Exception as exc:
        warnings.append(f"{path.name}: PCAPNG streaming error ({exc}).")


def stream_pcap_artifact_chunks(
    path: Path,
    max_packets: int = 50_000,
    chunk_size: int = 1000,
    warnings: list[str] | None = None
) -> Generator[list[dict], None, None]:
    """Yield extracted network artifact dictionaries in memory-safe batch chunks."""
    log_memory_usage(f"Starting PCAP Stream ({path.name})")

    is_pcapng = path.suffix.lower() == ".pcapng"
    packet_stream = stream_pcapng_packets(path, max_packets, warnings=warnings) if is_pcapng else stream_pcap_packets(path, max_packets, warnings=warnings)

    chunk = []
    processed_count = 0

    for ts_str, packet_bytes in packet_stream:
        artifacts = _packet_artifacts(packet_bytes, ts_str)
        chunk.extend(artifacts)
        processed_count += 1

        if len(chunk) >= chunk_size:
            log_memory_usage(f"PCAP Streamed {processed_count} packets")
            yield chunk
            chunk = []

    if chunk:
        log_memory_usage(f"PCAP Streamed final batch ({processed_count} total packets)")
        yield chunk


def extract_pcap_artifacts(path: Path, max_packets: int = 5_000) -> tuple[list[dict], list[str]]:
    """Extract PCAP artifacts using memory-safe streaming while preserving 100% backward compatibility."""
    all_artifacts = []
    warnings = []
    for chunk in stream_pcap_artifact_chunks(path, max_packets=max_packets, chunk_size=1000, warnings=warnings):
        all_artifacts.extend(chunk)
    return all_artifacts, warnings


def extract_network_log_artifacts(path: Path, max_lines: int = 5_000) -> tuple[list[dict], list[str]]:
    """Memory-safe line-by-line firewall log parser."""
    artifacts: list[dict] = []
    try:
        count = 0
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                if count >= max_lines:
                    break
                count += 1
                ips = IP_PATTERN.findall(line)
                if not ips:
                    continue
                action = ACTION_PATTERN.search(line)
                port = PORT_PATTERN.search(line)
                artifacts.append({
                    "artifact_type": "firewall_log",
                    "timestamp": None,
                    "source_ip": ips[0],
                    "destination_ip": ips[1] if len(ips) > 1 else None,
                    "source_port": None,
                    "destination_port": int(port.group(1)) if port else None,
                    "protocol": None,
                    "value": action.group(1).upper() if action else None,
                    "details": {"line": line[:1000]}
                })
    except OSError as exc:
        return [], [f"{path.name}: network-log extraction failed ({exc})."]
    return artifacts, []


def is_suspicious_network_artifact(artifact: dict) -> bool:
    ports = {4444, 1337, 31337, 3389, 22}
    return (
        artifact.get("destination_port") in ports or
        (artifact.get("artifact_type") == "dns_query" and any(token in (artifact.get("value") or "").lower() for token in (".onion", "ddns", "paste"))) or
        artifact.get("value") in {"DENY", "DROP", "BLOCK"}
    )
