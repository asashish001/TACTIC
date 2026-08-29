
"""FastAPI development launcher for the AI Digital Forensics Assistant."""
import socket
import sys
from pathlib import Path


def main() -> None:
    """Launch the single supported application runtime: FastAPI via Uvicorn."""
    host, port = "127.0.0.1", 8000

    # Give a useful answer when a developer runs the launcher twice. Without
    # this check Uvicorn prints a low-level WinError 10048 after initialising
    # the whole application, which makes a healthy already-running instance
    # look like an application failure.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.2)
        if probe.connect_ex((host, port)) == 0:
            print(f"T.A.C.T.I.C. is already running at http://{host}:{port}/")
            print("Open that address in your browser, or stop the existing server before starting app.py again.")
            return

    backend_dir = Path(__file__).resolve().parent / "backend"
    sys.path.insert(0, str(backend_dir))

    # This launcher is itself named app.py. Remove any top-level module with
    # that name before importing backend/app so it cannot shadow the package.
    sys.modules.pop("app", None)

    import uvicorn
    from app.main import app

    # Pass the already imported ASGI app so the root launcher also works on
    # Windows without relying on a reloader child process to rebuild sys.path.
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
