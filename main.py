"""Utility script for post-provisioning automation."""

import yaml
import json

import settings
import utils.log_handler as logger
from utils.auth_handler import Auth
import utils.data_utils as data_utils
from pathlib import Path

log = logger.log

import api


def import_reports(auth: Auth, folder: str) -> None:
    """
    Import all ``.ptrac`` files in ``report_to_import`` under their matching client found in the instance
    
    All .ptrac files in this folder will be imported during script execution. Any .ptrac can be added and will import.

    .ptrac files will be imported into clients. If a client doesn't exist that matches the client in the .ptrac,
    it will be imported with the option to Keep Original Client Details checked which creates a new client for
    the report to be imported to.
    """
    path = Path(folder)
    if not path.is_dir():
        log.error(f"{folder} is not a valid directory")
        return

    ptrac_files = sorted(path.glob("*.ptrac"))
    if not ptrac_files:
        log.warning(f"No .ptrac files found in {folder}")
        return

    for file_path in ptrac_files:
        log.info(f"Processing file: {file_path}")

        existing_client = False
        existing_client_id = None
        clients = []
        if not data_utils.get_page_of_clients(clients=clients, auth=auth):
            log.exception("Failed to retrieve clients from Plextrac instance. Skipping...")
            continue

        try:
            with open(file_path, "rb") as f:
                # Check if the client already exists
                file_json = json.load(f)
                client_name = file_json.get("client_info", {}).get("name", "")
                report_name = file_json.get("report_info", {}).get("name", "")
                f.seek(0)  # Reset file pointer to the beginning after reading JSON
                for client in clients:
                    if client.get("name") == client_name:
                        existing_client = True
                        existing_client_id = client.get("client_id")
                        break

                if not existing_client:
                    # Import the report and create a new client
                    try:
                        files = {
                            "file": (file_path.name, f, "application/octet-stream")
                        }
                        response = api.reports.import_ptrac_report_keep_client_details(
                            auth.base_url, auth.get_auth_headers(), files
                        )
                        log.success(f"Imported report '{report_name}' for new client '{client_name}'")
                    except Exception as e:
                        log.exception(f"Failed to import report '{report_name}' for new client {client_name}: {e}")
                        continue
                else:
                    # Import the report to an existing client
                    try:
                        files = {
                            "file": (file_path.name, f, "application/octet-stream")
                        }
                        response = api.reports.import_ptrac_report(
                            auth.base_url, auth.get_auth_headers(), existing_client_id, files
                        )
                        log.success(f"Imported report '{report_name}' for existing client '{client_name}'")
                    except Exception as e:
                        log.exception(f"Failed to import report '{report_name}' for existing client {client_name}: {e}")
                        continue

        except Exception as exc:
            log.exception(f"Failed to import report from {file_path}:\n{exc}")


def create_custom_rbac_role(auth: Auth) -> None:
    """Create a custom RBAC role on the instance using a JSON payload file."""

    log.info("Creating custom RBAC role")

    payload_path = Path("custom_rbac_payload.json")
    if not payload_path.is_file():
        log.exception(f"Payload file {payload_path} not found")
        return

    try:
        with open(payload_path, "r") as f:
            payload = json.load(f)
    except Exception as e:
        log.exception(f"Failed to load payload file: {e}")
        return

    try:
        response = api._admin._security.rbac.create_security_role(
            auth.base_url, auth.get_auth_headers(), 0, payload
        )
        log.success(f"Created RBAC role '{payload.get('title', '')}'")
    except Exception as e:
        log.exception(f"Failed to create RBAC role: {e}")
        return


def main() -> None:
    for line in settings.script_info:
        print(line)

    with open("config.yaml", "r") as f:
        args = yaml.safe_load(f)

    log.info(f'Running on {args.get("instance_url", "")}')

    auth = Auth(args)
    if not auth.check_instance_health():
        log.error("Instance health check failed")
        return
    auth.handle_authentication()

    ptrac_folder = args.get("ptrac_folder")
    if ptrac_folder:
        import_reports(auth, ptrac_folder)
    else:
        log.warning("No ptrac_folder specified in config.yaml. Skipping importing .ptrac reports...")

    create_custom_rbac_role(auth)


if __name__ == "__main__":
    main()

