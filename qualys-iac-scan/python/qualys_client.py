# qualys_iac_scanner/qualys_client.py
import logging
import ssl
import time
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from requests.auth import HTTPBasicAuth


class SSLContextAdapter(HTTPAdapter):
    """
    An HTTP adapter that allows for a custom SSLContext.
    
    This is used to inject a custom CA bundle for verifying SSL certificates,
    which is common in enterprise environments with TLS inspection.
    """
    def __init__(self, ssl_context: Optional[ssl.SSLContext] = None, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        """Initializes the connection pool manager with the custom SSL context."""
        if self.ssl_context:
            kwargs['ssl_context'] = self.ssl_context
        return super().init_poolmanager(*args, **kwargs)


class QualysApiClient:
    """A client for interacting with the Qualys CloudView IaC Scan API."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        custom_ca_bundle: Optional[str] = None
    ):
        """
        Initializes the Qualys API client.

        Args:
            base_url: The base URL for the Qualys API endpoint.
            username: The username for authentication.
            password: The password for authentication.
            custom_ca_bundle: Optional path to a custom CA bundle file for SSL verification.
        """
        self.base_url = base_url.rstrip('/')
        self._auth = HTTPBasicAuth(username, password)
        self._session = requests.Session()
        self._session.headers.update({"Accept": "application/json"})
        
        self._configure_ssl(custom_ca_bundle)

    def _configure_ssl(self, custom_ca_bundle: Optional[str]) -> None:
        """
        Configures the session for SSL/TLS, optionally using a custom CA bundle.
        
        Note: While `requests` supports a simpler method for custom CAs (`session.verify = path`),
        the SSLContextAdapter approach is used here as requested, because it offers more granular
        control over SSL/TLS settings if needed in the future.

        Args:
            custom_ca_bundle: Path to a custom CA bundle file.
        
        Raises:
            FileNotFoundError: If the custom_ca_bundle path is provided but does not exist.
            ssl.SSLError: If the CA bundle cannot be loaded.
        """
        if not custom_ca_bundle:
            logging.info("Using system's default CA bundle for SSL verification.")
            return

        ca_path = Path(custom_ca_bundle)
        if not ca_path.is_file():
            raise FileNotFoundError(f"Custom CA bundle not found at: {custom_ca_bundle}")

        logging.info(f"Using custom CA bundle for SSL verification: {custom_ca_bundle}")

        try:
            # Create an SSL context and load the custom CA bundle.
            context = ssl.create_default_context(cafile=str(ca_path))
            context.verify_flags &= ~ssl.VERIFY_X509_STRICT
            
            # Mount a custom adapter that uses our SSL context for all HTTPS requests.
            adapter = SSLContextAdapter(ssl_context=context)
            self._session.mount('https://', adapter)

        except ssl.SSLError as e:
            logging.error(f"Failed to load the custom CA bundle. Please ensure it's a valid PEM file. Error: {e}")
            raise

    def initiate_scan(self, zip_file_path: Path, scan_name: str) -> str:
        """
        Initiates an IaC scan by uploading a zip file.

        Args:
            zip_file_path: The path to the zip archive of IaC templates.
            scan_name: A descriptive name for the scan.

        Returns:
            The scan UUID returned by the API.
            
        Raises:
            requests.HTTPError: If the API returns an error status code.
        """
        scan_url = f"{self.base_url}/cloudview-api/rest/v1/iac/scan"
        logging.info(f"Initiating scan with name '{scan_name}'...")
        
        try:
            with open(zip_file_path, "rb") as f:
                files = {
                    "file": (zip_file_path.name, f, "application/zip"),
                    "name": (None, scan_name),
                }
                # The session's auth and SSL context are automatically used here.
                response = self._session.post(scan_url, auth=self._auth, files=files)
                response.raise_for_status()

            response_data = response.json()
            scan_uuid = response_data.get("scanUuid")
            if not scan_uuid:
                raise ValueError("API response did not contain a 'scanUuid'.")
            
            logging.info(f"Scan initiated successfully. Scan UUID: {scan_uuid}")
            return scan_uuid
        except requests.RequestException as e:
            logging.error(f"API request to initiate scan failed: {e}")
            raise

    def poll_scan_results(self, scan_uuid: str, interval: int, timeout: int) -> Dict[str, Any]:
        """
        Polls the API for scan results until they are finished or a timeout occurs.

        Args:
            scan_uuid: The UUID of the scan to check.
            interval: The number of seconds to wait between polls.
            timeout: The total number of seconds to poll before giving up.

        Returns:
            The final scan results from the API.
            
        Raises:
            TimeoutError: If the scan does not finish within the timeout period.
            requests.HTTPError: If the API returns an error status code during polling.
        """
        results_url = f"{self.base_url}/cloudview-api/rest/v1/iac/scanResult"
        params = {"scanUuid": scan_uuid}
        start_time = time.time()

        logging.info(f"Polling for results for scan {scan_uuid}...")
        while time.time() - start_time < timeout:
            try:
                # The session's auth and SSL context are automatically used here.
                response = self._session.get(results_url, auth=self._auth, params=params)
                response.raise_for_status()
                
                data = response.json()
                status = data.get("status", "UNKNOWN")
                
                if status == "FINISHED":
                    logging.info("Scan finished. Results retrieved.")
                    return data
                
                logging.info(f"Scan status is '{status}'. Polling again in {interval}s...")
                time.sleep(interval)
                
            except requests.RequestException as e:
                logging.error(f"API request to poll results failed: {e}")
                raise
        
        raise TimeoutError(f"Scan did not finish within the {timeout}s timeout period.")

    def get_sarif_results(self, scan_uuid: str) -> None:
        """
        Retrieves SARIF-formatted scan results and saves them to a file.
        """
        results_url = f"{self.base_url}/cloudview-api/rest/v1/iac/scanResult"
        params = {"scanUuid": scan_uuid}
        headers = {"responseFormat": "sarif"}

        try:
            response = self._session.get(
                results_url,
                auth=self._auth,
                params=params,
                headers=headers,
            )
            response.raise_for_status()
            sarif_data = response.text  # SARIF is JSON, but we keep it as text for direct saving.

            results_file = Path("results.sarif")
            results_file.write_text(sarif_data)

            logging.info("SARIF results saved to results.sarif")

        except requests.RequestException as e:
            logging.error(f"Failed to retrieve SARIF results: {e}")
            raise