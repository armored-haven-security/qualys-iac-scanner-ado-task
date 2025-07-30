# qualys_iac_scanner/main.py
import json
import logging
import os
import ssl
import sys
from datetime import datetime
from pathlib import Path

from config import load_config, AppConfig
from file_utils import find_iac_templates, create_zip_archive
from qualys_client import QualysApiClient

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def run_scan_workflow(config: AppConfig) -> None:
    """
    Executes the full IaC scanning workflow.

    Args:
        config: The application configuration.
    """
    template_dir = Path(config.iac_template_dir)
    zip_file_path = None
    
    try:
        # 1. Find IaC template files
        template_files = find_iac_templates(template_dir)
        if not template_files:
            logging.warning("No IaC template files found. Exiting.")
            return

        # 2. Create a zip archive
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        zip_file_name = f".iac-scan-{timestamp}.zip"
        zip_file_path = Path(zip_file_name)
        create_zip_archive(zip_file_path, template_files, template_dir)

        # 3. Initialize API client with all config, including optional SSL context
        client = QualysApiClient(
            config.qualys_base_url, 
            config.qualys_username, 
            config.qualys_password,
            config.qualys_custom_ca_bundle  # Pass the custom CA bundle path
        )

        # 4. Initiate scan
        scan_name = f"iac-scan-{timestamp}"
        scan_uuid = client.initiate_scan(zip_file_path, scan_name)

        # 5. Poll for results
        results = client.poll_scan_results(
            scan_uuid, 
            config.poll_interval, 
            config.poll_timeout
        )

        # 6. Save results
        results_file = Path("results.json")

        # 7. Get Sarif results
        client.get_sarif_results(scan_uuid)
        
        with open(results_file, "w") as f:
            json.dump(results, f, indent=4)
        logging.info(f"Scan results saved to '{results_file}'")

    except (ValueError, FileNotFoundError, TimeoutError, ssl.SSLError) as e:
        logging.error(f"A critical error occurred: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)
    finally:
        # 7. Cleanup the temporary zip file
        if zip_file_path and zip_file_path.exists():
            logging.info(f"Cleaning up temporary file: {zip_file_path}")
            os.remove(zip_file_path)

if __name__ == "__main__":
    try:
        app_config = load_config()
        run_scan_workflow(app_config)
    except ValueError as e:
        logging.error(f"Configuration error: {e}")
        logging.error("Please ensure your .env file is correctly configured.")
        sys.exit(1)
