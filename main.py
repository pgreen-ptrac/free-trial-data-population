"""Utility script for post-provisioning automation."""

import yaml

import settings
import utils.log_handler as logger
from utils.auth_handler import Auth
from pathlib import Path

log = logger.log

import api


def check_instance_health(auth: Auth) -> bool:
    """Verify the newly created instance is up and responding."""
    log.info("Verifying instance health")
    try:
        response = api.tenant.root_request(auth.base_url, {})
        if response.json.get("text") == "Authenticate at /authenticate":
            log.success("Instance is online")
            return True
        log.error("Unexpected response when checking instance health")
    except Exception as exc:
        log.exception(exc)
    return False


def import_reports(auth: Auth, client_id: int, folder: str) -> None:
    """Import all ``.ptrac`` files in ``folder`` for the provided ``client_id``."""
    path = Path(folder)
    if not path.is_dir():
        log.error(f"{folder} is not a valid directory")
        return

    ptrac_files = sorted(path.glob("*.ptrac"))
    if not ptrac_files:
        log.warning(f"No .ptrac files found in {folder}")
        return

    for file_path in ptrac_files:
        try:
            with open(file_path, "rb") as f:
                payload = {"file": f}
                api.reports.import_ptrac_report(
                    auth.base_url, auth.get_auth_headers(), client_id, payload
                )
            log.success(f"Imported report from {file_path}")
        except Exception as exc:
            log.exception(exc)
            log.error(f"Failed to import report from {file_path}")


def create_custom_rbac_role(auth: Auth, role_payload: dict) -> None:
    """Create a custom RBAC role on the instance."""
    # TODO: call the API that creates the RBAC role using ``role_payload``
    # response = api._admin._security.rbac.create_security_role(
    #     auth.base_url, auth.get_auth_headers(), auth.tenant_id
    # )
    # api._admin._security.rbac.update_security_role_info(
    #     auth.base_url, auth.get_auth_headers(), auth.tenant_id,
    #     response.json.get("id"), role_payload
    # )
    log.info("Would create a custom RBAC role with provided payload")


def main() -> None:
    for line in settings.script_info:
        print(line)

    with open("config.yaml", "r") as f:
        args = yaml.safe_load(f)

    log.info(args.get("instance_url"))

    auth = Auth(args)
    auth.handle_authentication()

    if not check_instance_health(auth):
        log.error("Instance health check failed")
        return

    client_id = args.get("client_id")
    ptrac_folder = args.get("ptrac_folder")
    if client_id and ptrac_folder:
        import_reports(auth, client_id, ptrac_folder)

    role_payload = args.get("rbac_role_payload")
    if role_payload:
        create_custom_rbac_role(auth, role_payload)


if __name__ == "__main__":
    main()

