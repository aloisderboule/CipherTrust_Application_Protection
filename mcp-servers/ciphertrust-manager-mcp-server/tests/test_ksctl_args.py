"""Unit tests: the ksctl command lines the tools build.

No CipherTrust Manager needed: ksctl execution is replaced by a recorder.
Needs CIPHERTRUST_URL set (any value) and KSCTL_PATH pointing to an existing
file, so that importing the server's settings doesn't try to download ksctl.
"""

import asyncio
import json
from pathlib import Path

import pytest

from ciphertrust_mcp_server.tools.connections_ldap import ConnectionLDAPManagementTool
from ciphertrust_mcp_server.tools.connections_oidc import ConnectionOIDCManagementTool
from ciphertrust_mcp_server.tools.connections_users import ConnectionUsersManagementTool
from ciphertrust_mcp_server.tools.cte_management.base import bool_flag
from ciphertrust_mcp_server.tools.cte_management.client_group_operations import ClientGroupOperations
from ciphertrust_mcp_server.tools.cte_management.client_operations import ClientOperations
from ciphertrust_mcp_server.tools.cte_management.ldt_comm_group_operations import LDTCommGroupOperations
from ciphertrust_mcp_server.tools.cte_management.main import CTEManagementTool
from ciphertrust_mcp_server.tools.cte_management.policy_operations import PolicyOperations
from ciphertrust_mcp_server.tools.cte_management.profile_operations import ProfileOperations
from ciphertrust_mcp_server.tools.keys import KeyManagementTool
from ciphertrust_mcp_server.utils.helpers import sanitize_command_args


class Recorder:
    """Stands in for execute_with_domain; keeps the last ksctl args."""

    def __init__(self, inspect=None):
        self.args = None
        self.inspect = inspect

    def __call__(self, args, domain=None, auth_domain=None):
        self.args = list(args)
        if self.inspect:
            self.inspect(self.args)
        return {"data": {}}


def run(coro):
    return asyncio.run(coro)


# --- boolean flags: ksctl has no --no-<flag> ------------------------------

def test_bool_flag():
    assert bool_flag("--mfa-enabled", True) == "--mfa-enabled=true"
    assert bool_flag("--mfa-enabled", False) == "--mfa-enabled=false"


def test_modify_guardpoint_mfa_off():
    rec = Recorder()
    run(ClientOperations(rec).execute_operation(
        "client_modify_guardpoint", cte_client_identifier="10.0.4.12",
        guard_point_identifier="gp1", mfa_enabled=False, guard_enabled=True))
    assert "--mfa-enabled=false" in rec.args
    assert "--guard-enabled=true" in rec.args
    assert not any(a.startswith("--no-") for a in rec.args)


def test_create_guardpoint_preserve_sparse_off():
    rec = Recorder()
    run(ClientOperations(rec).execute_operation(
        "client_create_guardpoint", cte_client_identifier="c", guard_path_list="/data",
        guard_point_type="directory_auto", preserve_sparse_regions=False))
    assert "--preserve-sparse-regions=false" in rec.args


def test_create_guardpoint_disabled_is_refused():
    # create-guardpoints has no --guard-enabled flag at all
    with pytest.raises(ValueError, match="client_modify_guardpoint"):
        run(ClientOperations(Recorder()).execute_operation(
            "client_create_guardpoint", cte_client_identifier="c", guard_path_list="/data",
            guard_point_type="directory_auto", guard_enabled=False))


def test_client_group_modify_comm_off():
    rec = Recorder()
    run(ClientGroupOperations(rec).execute_operation(
        "client_group_modify", client_group_identifier="g", comm_enabled=False))
    assert "--comm-enabled=false" in rec.args


def test_no_negated_flags_left_in_cte_sources():
    root = Path(__file__).resolve().parents[1] / "src" / "ciphertrust_mcp_server" / "tools" / "cte_management"
    for f in root.glob("*.py"):
        assert '"--no-' not in f.read_text(encoding="utf-8"), f"{f.name} still builds a --no-<flag>"


# --- grouped connection tools publish their parameters ----------------------

@pytest.mark.parametrize("tool, expected", [
    (ConnectionLDAPManagementTool, {"name", "server_url", "test_username", "test_password_file"}),
    (ConnectionOIDCManagementTool, {"name"}),
    (ConnectionUsersManagementTool, set()),
])
def test_connection_tools_schema_has_parameters(tool, expected):
    props = tool().get_schema()["properties"]
    assert "action" in props
    assert len(props) > 1, "only 'action' in the schema: clients never send the other parameters"
    assert expected <= set(props)


# --- LDAP test: connection name, password from a file -----------------------

def test_ldap_test_passes_name_and_password_file(tmp_path):
    secret = tmp_path / "pw.txt"
    secret.write_text("s3cret\n", encoding="utf-8")
    tool = ConnectionLDAPManagementTool()
    rec = Recorder()
    tool.execute_with_domain = rec
    run(tool.execute(action="test", name="cte-lab-ad", test_username="abelard",
                     test_password_file=str(secret)))
    assert rec.args[rec.args.index("--name") + 1] == "cte-lab-ad"
    assert rec.args[rec.args.index("--test-password") + 1] == "s3cret"


def test_ldap_test_requires_a_password():
    tool = ConnectionLDAPManagementTool()
    tool.execute_with_domain = Recorder()
    with pytest.raises(ValueError, match="test_password"):
        run(tool.execute(action="test", name="cte-lab-ad", test_username="abelard"))


def test_secret_flags_masked_in_logs():
    out = sanitize_command_args(["--test-password", "a", "--bind-password", "b", "--client-secret", "c"])
    assert out == ["--test-password", "***", "--bind-password", "***", "--client-secret", "***"]


# --- CTE key JSON ------------------------------------------------------------

def test_cte_key_json_uses_rest_field_names():
    seen = {}

    def inspect(args):
        seen.update(json.loads(Path(args[args.index("--jsonfile") + 1]).read_text()))

    tool = KeyManagementTool()
    tool.execute_with_domain = Recorder(inspect)
    run(tool.execute(action="create", name="uc-smb-key", cte_key_type="ldt", cte_encryption_mode="CBC_CS1",
                     xts=True, cte_persistent_on_client=True, usage_mask=76))
    assert seen["usageMask"] == 76 and "usage_mask" not in seen
    assert seen["xts"] is True
    assert seen["meta"]["cte"] == {"cte_versioned": True, "encryption_mode": "CBC_CS1", "persistent_on_client": True}


# --- CTE tool schema: every action parameter is declared ---------------------
# The tool sets additionalProperties: false, so an undeclared parameter can't
# be sent at all.

def test_cte_schema_declares_every_action_parameter():
    schema = CTEManagementTool().get_schema()
    props = set(schema["properties"])
    missing = {(action, p) for action, req in schema["action_requirements"].items()
               for p in req.get("required", []) + req.get("optional", []) if p not in props}
    assert not missing
    assert {"client_group_create_guardpoint", "ldt_comm_group_create"} <= set(schema["properties"]["action"]["enum"])


# --- client group members and GuardPoints ------------------------------------

def test_client_group_add_clients():
    rec = Recorder()
    run(ClientGroupOperations(rec).execute_operation(
        "client_group_add_clients", client_group_identifier="uc-smb-hosts",
        cte_client_list="10.0.4.12,10.0.4.15", inherit_attributes=True))
    assert rec.args == ["cte", "client-groups", "add-clients", "--client-group-identifier", "uc-smb-hosts",
                        "--cte-client-list", "10.0.4.12,10.0.4.15", "--inherit-attributes=true"]


def test_client_group_create_cifs_guardpoint():
    # what cte_demo.py cm-client-group sends through REST today
    rec = Recorder()
    run(ClientGroupOperations(rec).execute_operation(
        "client_group_create_guardpoint", client_group_identifier="uc-smb-hosts",
        guard_path_list=r"\\fs\share\letters", guard_point_type="directory_auto",
        cte_policy_identifier="uc-smb-policy", cifs_enabled=True, preserve_sparse_regions=True,
        network_share_credentials_identifier="uc-cifs-share"))
    a = rec.args
    assert a[:3] == ["cte", "client-groups", "create-guardpoints"]
    assert a[a.index("--guard-path-list") + 1] == r"\\fs\share\letters"
    assert a[a.index("--network-share-credentials-identifier") + 1] == "uc-cifs-share"
    assert {"--cifs-enabled=true", "--preserve-sparse-regions=true"} <= set(a)
    assert "--mfa-enabled=false" not in a  # unset booleans are left to CM's defaults


def test_client_group_guardpoint_mfa_off():
    rec = Recorder()
    run(ClientGroupOperations(rec).execute_operation(
        "client_group_modify_guardpoint", client_group_identifier="uc-smb-hosts",
        guard_point_identifier="gp1", mfa_enabled=False))
    assert rec.args == ["cte", "client-groups", "modify-guardpoints", "--client-group-identifier", "uc-smb-hosts",
                        "--guard-point-identifier", "gp1", "--mfa-enabled=false"]


@pytest.mark.parametrize("action, command", [
    ("client_group_list_clients", "list-clients"),
    ("client_group_list_guardpoints", "list-guardpoints"),
])
def test_client_group_lists(action, command):
    rec = Recorder()
    run(ClientGroupOperations(rec).execute_operation(action, client_group_identifier="g"))
    assert rec.args[:3] == ["cte", "client-groups", command]
    assert "--limit" in rec.args


# --- LDT Communication Groups -------------------------------------------------

def test_ldt_comm_group_create_and_add_clients():
    rec = Recorder()
    ops = LDTCommGroupOperations(rec)
    run(ops.execute_operation("ldt_comm_group_create", ldt_comm_group_name="uc-smb-ldt",
                              ldt_comm_group_description="SMB share"))
    assert rec.args == ["cte", "ldt-group-comm-services", "create", "--cte-ldt-group-comm-service-name",
                        "uc-smb-ldt", "--cte-ldt-group-comm-service-description", "SMB share"]
    run(ops.execute_operation("ldt_comm_group_add_clients", ldt_comm_group_identifier="uc-smb-ldt",
                              cte_client_list="10.0.4.12,10.0.4.15"))
    assert rec.args == ["cte", "ldt-group-comm-services", "add-clients", "--cte-ldt-group-comm-service-identifier",
                        "uc-smb-ldt", "--cte-client-list", "10.0.4.12,10.0.4.15"]


def test_ldt_comm_group_status():
    rec = Recorder()
    run(LDTCommGroupOperations(rec).execute_operation("ldt_comm_group_status", ldt_comm_group_identifier="g"))
    assert rec.args[:3] == ["cte", "ldt-group-comm-services", "get-status-details"]


# --- profile: logging, syslog, MFA ---------------------------------------------

def test_profile_modify_logging_and_mfa():
    rec = Recorder()
    syslog = {"local": False, "syslog_threshold": "INFO",
              "servers": [{"name": "10.0.4.20", "port": 5514, "protocol": "UDP", "message_format": "RFC5424"}]}
    run(ProfileOperations(rec).execute_operation(
        "profile_modify", cte_profile_identifier="DefaultClientProfile",
        policy_evaluation_logger={"threshold": "INFO", "syslog_enabled": True}, syslog_settings=syslog,
        oidc_connection_id="uc-keycloak-cte", concise_logging=False))
    a = rec.args
    assert json.loads(a[a.index("--policy-evaluation-logger-json") + 1]) == {"threshold": "INFO", "syslog_enabled": True}
    assert json.loads(a[a.index("--syslog-settings-json") + 1]) == syslog
    assert a[a.index("--oidc-connection-id") + 1] == "uc-keycloak-cte"
    assert "--concise-logging=false" in a
