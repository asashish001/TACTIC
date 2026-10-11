"""Dedicated Memory Forensics Extractor utilizing Volatility 3."""
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

def extract_memory_artifacts(file_path: Path) -> tuple[list[dict], list[str]]:
    """Extract processes, network connections, and indicators from a RAM dump.
    
    Attempts to use volatility3 (`vol` command). If unavailable, falls back 
    to returning a warning so the generalized NLP extractor can take over string carving.
    """
    artifacts = []
    warnings = []
    
    # Check if volatility 3 is available in system PATH
    vol_available = False
    try:
        res = subprocess.run(["vol", "-h"], capture_output=True, text=True)
        if res.returncode == 0 or "Volatility 3" in res.stdout or "volatility" in res.stdout.lower():
            vol_available = True
    except FileNotFoundError:
        pass

    if vol_available:
        try:
            logger.info("Volatility 3 found. Running windows.pslist on %s", file_path.name)
            # Extract running processes (windows.pslist.PsList)
            ps_res = subprocess.run(
                ["vol", "-f", str(file_path), "windows.pslist.PsList"], 
                capture_output=True, text=True, timeout=180
            )
            if ps_res.returncode == 0:
                for line in ps_res.stdout.splitlines():
                    if not line.strip() or "PID" in line or "Offset" in line:
                        continue
                    parts = line.split()
                    if len(parts) >= 4:
                        pid = parts[0]
                        name = parts[1]
                        artifacts.append({
                            "artifact_type": "PROCESS",
                            "value": name,
                            "confidence": 0.95,
                            "extractor": "volatility3-pslist",
                            "details": {"pid": pid, "source": "windows.pslist"}
                        })
            
            logger.info("Running windows.netscan on %s", file_path.name)
            # Extract network connections (windows.netscan.NetScan)
            net_res = subprocess.run(
                ["vol", "-f", str(file_path), "windows.netscan.NetScan"], 
                capture_output=True, text=True, timeout=180
            )
            if net_res.returncode == 0:
                for line in net_res.stdout.splitlines():
                    if not line.strip() or "Offset" in line or "LocalAddr" in line:
                        continue
                    parts = line.split()
                    if len(parts) >= 5:
                        proto = parts[1]
                        local = parts[2]
                        foreign = parts[3]
                        state = parts[4] if len(parts) > 4 else "UNKNOWN"
                        
                        foreign_ip = foreign.split(':')[0] if ':' in foreign else foreign
                        if foreign_ip and foreign_ip not in ("0.0.0.0", "*", "::"):
                            artifacts.append({
                                "artifact_type": "IP_ADDRESS",
                                "value": foreign_ip,
                                "confidence": 0.95,
                                "extractor": "volatility3-netscan",
                                "details": {"protocol": proto, "local_ip": local, "state": state, "source": "windows.netscan"}
                            })
        except subprocess.TimeoutExpired:
            warnings.append("Volatility 3 analysis timed out (exceeded 3 minutes).")
            logger.warning("Volatility 3 timed out on %s", file_path.name)
        except Exception as exc:
            warnings.append(f"Volatility 3 analysis failed: {exc}")
            logger.error("Volatility 3 error: %s", exc)
    else:
        warnings.append("Volatility 3 ('vol' command) is not installed on the system path. Deep RAM parsing skipped; generalized string extraction will be used instead.")
        logger.info("Volatility 3 missing. Falling back to generalized NLP text extraction for %s", file_path.name)

    return artifacts, warnings
