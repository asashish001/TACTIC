"""Automate updating the YouTube video link in README.md.

Usage:
    python scripts/update_readme_video.py <YOUTUBE_URL>

Example:
    python scripts/update_readme_video.py https://youtu.be/dQw4w9WgXcQ
"""

import re
import sys
from pathlib import Path

README_PATH = Path(__file__).resolve().parent.parent / "README.md"


def update_youtube_url(new_url: str):
    if not README_PATH.exists():
        print(f"Error: Could not find README at {README_PATH}")
        sys.exit(1)

    content = README_PATH.read_text(encoding="utf-8")

    # Replace badge link and video link
    # Matches patterns like <a href="https://www.youtube.com">
    updated = re.sub(
        r'<a href="https://(?:www\.)?youtube\.com[^"]*">',
        f'<a href="{new_url}">',
        content,
    )

    if updated != content:
        README_PATH.write_text(updated, encoding="utf-8")
        print(f"Successfully updated YouTube URL in README.md to:\n  {new_url}")
    else:
        print("Note: YouTube URL is already up to date or pattern did not match.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/update_readme_video.py <YOUTUBE_URL>")
        sys.exit(1)
    update_youtube_url(sys.argv[1].strip())

