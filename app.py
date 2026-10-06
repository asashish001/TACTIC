
"""FastAPI development launcher for the AI Digital Forensics Assistant."""
import socket
import sys
from pathlib import Path


def main() -> None:
    """Launch the single supported application runtime: FastAPI via Uvicorn."""
    host, port = "127.0.0.1", 8000

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.2)
        if probe.connect_ex((host, port)) == 0:
            print(f"T.A.C.T.I.C. is already running at http://{host}:{port}/")
            print("Open that address in your browser, or stop the existing server before starting app.py again.")
            return

    backend_dir = Path(__file__).resolve().parent / "backend"
    sys.path.insert(0, str(backend_dir))

    sys.modules.pop("app", None)

    import uvicorn
    from app.main import app

    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
