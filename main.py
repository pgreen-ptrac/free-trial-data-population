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

scorecard = {
    "instance_health": None,
    "authentication": None,
    "reports": [],
    "rbac_role": None,
}


def print_scorecard() -> None:
    """Print a summary of successes and failures."""
    print("\n---------- Scorecard ----------")
    if scorecard["instance_health"] is not None:
        print(
            f"Instance Health Check: {'Success' if scorecard['instance_health'] else 'Failed'}"
        )
    if scorecard["authentication"] is not None:
        print(
            f"Authentication: {'Success' if scorecard['authentication'] else 'Failed'}"
        )

    if scorecard["reports"]:
        print("\nReport Imports:")
        for entry in scorecard["reports"]:
            status = "Success" if entry.get("status") else "Failed"
            msg = f" - {entry.get('message')}" if entry.get("message") else ""
            print(f"  {entry.get('file')}: {status}{msg}")
    else:
        print("\nReport Imports: None")

    if scorecard["rbac_role"] is not None:
        status = "Success" if scorecard["rbac_role"].get("status") else "Failed"
        role = scorecard["rbac_role"].get("role", "")
        msg = scorecard["rbac_role"].get("message", "")
        details = f" ({role})" if role else ""
        message = f" - {msg}" if msg and not scorecard["rbac_role"].get("status") else ""
        print(f"RBAC Role Creation{details}: {status}{message}")

    print("--------------------------------\n")


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
        scorecard["reports"].append({"file": folder, "status": False, "message": "invalid directory"})
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
                        scorecard["reports"].append({"file": file_path.name, "status": True})
                    except Exception as e:
                        log.exception(f"Failed to import report '{report_name}' for new client {client_name}: {e}")
                        scorecard["reports"].append({"file": file_path.name, "status": False, "message": str(e)})
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
                        scorecard["reports"].append({"file": file_path.name, "status": True})
                    except Exception as e:
                        log.exception(f"Failed to import report '{report_name}' for existing client {client_name}: {e}")
                        scorecard["reports"].append({"file": file_path.name, "status": False, "message": str(e)})
                        continue

        except Exception as exc:
            log.exception(f"Failed to import report from {file_path}:\n{exc}")
            scorecard["reports"].append({"file": file_path.name, "status": False, "message": str(exc)})


def create_custom_rbac_role(auth: Auth) -> None:
    """Create a custom RBAC role on the instance using a JSON payload file."""

    log.info("Creating custom RBAC role")

    payload_path = Path("custom_rbac_payload.json")
    if not payload_path.is_file():
        log.exception(f"Payload file {payload_path} not found")
        scorecard["rbac_role"] = {"status": False, "message": "payload file not found"}
        return

    try:
        with open(payload_path, "r") as f:
            payload = json.load(f)
    except Exception as e:
        log.exception(f"Failed to load payload file: {e}")
        scorecard["rbac_role"] = {"status": False, "message": str(e)}
        return

    try:
        response = api._admin._security.rbac.create_security_role(
            auth.base_url, auth.get_auth_headers(), 0, payload
        )
        log.success(f"Created RBAC role '{payload.get('title', '')}'")
        scorecard["rbac_role"] = {"status": True, "role": payload.get('title', '')}
    except Exception as e:
        log.exception(f"Failed to create RBAC role: {e}")
        scorecard["rbac_role"] = {"status": False, "message": str(e)}
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
        scorecard["instance_health"] = False
        print_scorecard()
        return
    scorecard["instance_health"] = True

    try:
        auth.handle_authentication()
        scorecard["authentication"] = bool(auth.auth_headers.get("Authorization"))
    except Exception as e:
        log.exception(e)
        scorecard["authentication"] = False
        print_scorecard()
        return

    ptrac_folder = args.get("ptrac_folder")
    if ptrac_folder:
        import_reports(auth, ptrac_folder)
    else:
        log.warning("No ptrac_folder specified in config.yaml. Skipping importing .ptrac reports...")

    create_custom_rbac_role(auth)

    print_scorecard()


if __name__ == "__main__":
    main()

