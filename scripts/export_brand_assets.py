"""Export Switch Manager brand assets from base64 sources."""
from __future__ import annotations

import base64
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent / "assets" / "brand" / "switch_manager"

ASSETS = {
    "icon.png": "icon.png.b64",
    "icon@2x.png": "icon@2x.png.b64",
    "logo.png": "logo.png.b64",
    "logo@2x.png": "logo@2x.png.b64",
    "dark_icon.png": "dark_icon.png.b64",
    "dark_icon@2x.png": "dark_icon@2x.png.b64",
    "dark_logo.png": "dark_logo.png.b64",
    "dark_logo@2x.png": "dark_logo@2x.png.b64",
}


def main() -> None:
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    for output_name, source_name in ASSETS.items():
        source_path = BASE_DIR / source_name
        output_path = BASE_DIR / output_name
        data = base64.b64decode(source_path.read_text().encode("ascii"))
        output_path.write_bytes(data)
        print(f"Wrote {output_path.relative_to(Path.cwd())} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
