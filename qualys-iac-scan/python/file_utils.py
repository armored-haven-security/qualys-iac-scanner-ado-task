# qualys_iac_scanner/file_utils.py
import logging
import zipfile
from pathlib import Path
from typing import List, Tuple
import re

# Supported IaC file extensions
SUPPORTED_EXTENSIONS: Tuple[str, ...] = (".tf", ".json", ".yaml", ".yml", ".template")

IAC_REGEX = re.compile(r"(main|infra|template|cloudformation|terraform|cdk|stack)", re.IGNORECASE)

def is_likely_iac_file(file: Path) -> bool:
    return bool(IAC_REGEX.search(file.name))

def find_iac_templates(root_dir: Path) -> List[Path]:
    """
    Recursively finds supported IaC template files in a directory, 
    filtering out generic JSON/YAML files using naming heuristics.
    """
    if not root_dir.is_dir():
        raise FileNotFoundError(f"The specified directory does not exist: {root_dir}")

    logging.info(f"Searching for IaC templates in '{root_dir}'...")

    found_files = [
        file
        for file in root_dir.rglob("*")
        if file.is_file()
        and file.suffix.lower() in SUPPORTED_EXTENSIONS
        and is_likely_iac_file(file)
    ]

    for file in found_files:
        logging.info(f"Found: {file}")

    logging.info(f"Found {len(found_files)} likely IaC template files.")
    return found_files


def create_zip_archive(output_path: Path, files: List[Path], base_dir: Path) -> None:
    """
    Creates a zip archive containing the specified files.

    The paths inside the zip archive will be relative to the base_dir.

    Args:
        output_path: The path where the zip archive will be created.
        files: A list of Path objects to include in the archive.
        base_dir: The directory to which file paths in the archive will be relative.
    """
    logging.info(f"Creating zip archive at '{output_path}'...")
    try:
        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_path in files:
                # arcname ensures paths in zip are relative to the template dir
                arcname = file_path.relative_to(base_dir)
                zf.write(file_path, arcname)
        logging.info("Zip archive created successfully.")
    except Exception as e:
        logging.error(f"Failed to create zip archive: {e}")
        raise

