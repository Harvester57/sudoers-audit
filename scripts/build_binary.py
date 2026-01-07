import PyInstaller.__main__
from pathlib import Path


def build():
    # Get the project root directory
    project_root = Path(__file__).parent.parent
    src_path = project_root / "src"

    print(f"Building from root: {project_root}")

    # Define PyInstaller arguments
    # Use the shim entry point to ensure package context is preserved
    entry_point = project_root / "scripts" / "entry_point.py"

    args = [
        str(entry_point),  # Entry point
        "--name",
        "sudoers-audit",  # Name of the executable
        "--onefile",  # Single executable file
        "--clean",  # Clean cache
        "--paths",
        str(src_path),  # Add src to path
        "--distpath",
        str(project_root / "dist"),  # Output directory
        "--workpath",
        str(project_root / "build"),  # Build directory
    ]

    print(f"Running PyInstaller with args: {args}")

    # Run PyInstaller
    PyInstaller.__main__.run(args)

    print("Build complete.")


if __name__ == "__main__":
    build()
