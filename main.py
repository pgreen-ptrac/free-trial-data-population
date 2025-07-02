"""Utility script for post-provisioning automation."""

import yaml

import settings
import utils.log_handler as logger
from utils.auth_handler import Auth

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


def import_client_data(auth: Auth, ptrac_file: str) -> None:
    """Import client information from a ptrac file."""
    # TODO: call the API that imports client data using the ptrac file
    # with open(ptrac_file, "rb") as f:
    #     payload = {"file": f}
    #     api.clients.import_client_ptrac(auth.base_url,
    #                                    auth.get_auth_headers(), payload)
    log.info(f"Would import client data from {ptrac_file}")


def import_report_data(auth: Auth, client_id: int, ptrac_file: str) -> None:
    """Import a report for a client from a ptrac file."""
    # TODO: call the API that imports report data using the ptrac file
    # with open(ptrac_file, "rb") as f:
    #     payload = {"file": f}
    #     api.reports.import_ptrac_report(
    #         auth.base_url, auth.get_auth_headers(), client_id, payload
    #     )
    log.info(
        f"Would import report data for client {client_id} from {ptrac_file}"
    )


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

    client_ptrac_file = args.get("client_ptrac_file")
    if client_ptrac_file:
        import_client_data(auth, client_ptrac_file)

    report_ptrac_file = args.get("report_ptrac_file")
    client_id = args.get("client_id")
    if report_ptrac_file and client_id:
        import_report_data(auth, client_id, report_ptrac_file)

    role_payload = args.get("rbac_role_payload")
    if role_payload:
        create_custom_rbac_role(auth, role_payload)


if __name__ == "__main__":
    main()

