"""LDT Communication Group operations for CTE management.

An LDT Communication Group (ksctl: ldt-group-comm-services) is the set of CTE
clients that share the same CIFS/NFS GuardPoints under Live Data
Transformation: its members coordinate the transformation, one of them acting
as the primary.
"""

from typing import Any
from .base import CTESubTool


class LDTCommGroupOperations(CTESubTool):
    """Handles LDT Communication Group operations for CTE management."""

    def get_operations(self) -> list[str]:
        """Return list of all LDT Communication Group operations."""
        return [
            "ldt_comm_group_create", "ldt_comm_group_list", "ldt_comm_group_get",
            "ldt_comm_group_modify", "ldt_comm_group_delete",
            "ldt_comm_group_add_clients", "ldt_comm_group_list_clients",
            "ldt_comm_group_remove_client", "ldt_comm_group_status"
        ]

    def get_schema_properties(self) -> dict[str, Any]:
        """Return schema properties specific to LDT Communication Group operations."""
        return {
            "ldt_comm_group_name": {
                "type": "string",
                "description": "Name of the LDT Communication Group"
            },
            "ldt_comm_group_identifier": {
                "type": "string",
                "description": "LDT Communication Group identifier (name, ID or URI)"
            },
            "ldt_comm_group_description": {
                "type": "string",
                "description": "Description of the LDT Communication Group"
            },
            "client_os_type": {
                "type": "string",
                "description": "Filter: operating system of the clients (Windows, Linux, FreeBSD)"
            }
        }

    def get_action_requirements(self) -> dict[str, Any]:
        """Return action requirements for LDT Communication Group operations."""
        return {
            "ldt_comm_group_create": {
                "required": ["ldt_comm_group_name"],
                "optional": ["ldt_comm_group_description", "domain", "auth_domain"],
                "example": {
                    "action": "ldt_comm_group_create",
                    "ldt_comm_group_name": "uc-smb-ldt",
                    "ldt_comm_group_description": "Clients sharing the SMB GuardPoint"
                }
            },
            "ldt_comm_group_list": {
                "required": [],
                "optional": ["ldt_comm_group_name", "limit", "skip", "sort", "domain", "auth_domain"],
                "example": {"action": "ldt_comm_group_list"}
            },
            "ldt_comm_group_get": {
                "required": ["ldt_comm_group_identifier"],
                "optional": ["domain", "auth_domain"],
                "example": {"action": "ldt_comm_group_get", "ldt_comm_group_identifier": "uc-smb-ldt"}
            },
            "ldt_comm_group_modify": {
                "required": ["ldt_comm_group_identifier", "ldt_comm_group_description"],
                "optional": ["domain", "auth_domain"],
                "example": {
                    "action": "ldt_comm_group_modify",
                    "ldt_comm_group_identifier": "uc-smb-ldt",
                    "ldt_comm_group_description": "Updated description"
                }
            },
            "ldt_comm_group_delete": {
                "required": ["ldt_comm_group_identifier"],
                "optional": ["domain", "auth_domain"],
                "example": {"action": "ldt_comm_group_delete", "ldt_comm_group_identifier": "uc-smb-ldt"}
            },
            "ldt_comm_group_add_clients": {
                "required": ["ldt_comm_group_identifier", "cte_client_list"],
                "optional": ["domain", "auth_domain"],
                "example": {
                    "action": "ldt_comm_group_add_clients",
                    "ldt_comm_group_identifier": "uc-smb-ldt",
                    "cte_client_list": "10.0.4.12,10.0.4.15"
                }
            },
            "ldt_comm_group_list_clients": {
                "required": ["ldt_comm_group_identifier"],
                "optional": ["cte_client_name", "client_os_type", "cte_profile_name", "limit", "skip", "sort",
                             "domain", "auth_domain"],
                "example": {"action": "ldt_comm_group_list_clients", "ldt_comm_group_identifier": "uc-smb-ldt"}
            },
            "ldt_comm_group_remove_client": {
                "required": ["ldt_comm_group_identifier", "cte_client_identifier"],
                "optional": ["domain", "auth_domain"],
                "example": {
                    "action": "ldt_comm_group_remove_client",
                    "ldt_comm_group_identifier": "uc-smb-ldt",
                    "cte_client_identifier": "10.0.4.15"
                }
            },
            "ldt_comm_group_status": {
                "required": ["ldt_comm_group_identifier"],
                "optional": ["domain", "auth_domain"],
                "example": {"action": "ldt_comm_group_status", "ldt_comm_group_identifier": "uc-smb-ldt"}
            }
        }

    async def execute_operation(self, action: str, **kwargs: Any) -> Any:
        """Execute the specified LDT Communication Group operation."""
        method_name = f"_{action}"
        if hasattr(self, method_name):
            return getattr(self, method_name)(**kwargs)
        return {"error": f"Unknown LDT Communication Group action: {action}"}

    def _run(self, args, kwargs):
        result = self.execute_with_domain(args, kwargs.get("domain"), kwargs.get("auth_domain"))
        return result.get("data", result.get("stdout", ""))

    @staticmethod
    def _base(command: str, kwargs) -> list[str]:
        return ["cte", "ldt-group-comm-services", command,
                "--cte-ldt-group-comm-service-identifier", kwargs["ldt_comm_group_identifier"]]

    @staticmethod
    def _paging(args: list[str], kwargs) -> None:
        args.extend(["--limit", str(kwargs.get("limit", 100)), "--skip", str(kwargs.get("skip", 0))])
        if kwargs.get("sort"):
            args.extend(["--sort", kwargs["sort"]])

    def _ldt_comm_group_create(self, **kwargs):
        """Create an LDT Communication Group."""
        args = ["cte", "ldt-group-comm-services", "create",
                "--cte-ldt-group-comm-service-name", kwargs["ldt_comm_group_name"]]
        if kwargs.get("ldt_comm_group_description"):
            args.extend(["--cte-ldt-group-comm-service-description", kwargs["ldt_comm_group_description"]])
        return self._run(args, kwargs)

    def _ldt_comm_group_list(self, **kwargs):
        """List LDT Communication Groups."""
        args = ["cte", "ldt-group-comm-services", "list"]
        self._paging(args, kwargs)
        if kwargs.get("ldt_comm_group_name"):
            args.extend(["--cte-ldt-group-comm-service-name", kwargs["ldt_comm_group_name"]])
        return self._run(args, kwargs)

    def _ldt_comm_group_get(self, **kwargs):
        """Get an LDT Communication Group."""
        return self._run(self._base("get", kwargs), kwargs)

    def _ldt_comm_group_modify(self, **kwargs):
        """Modify an LDT Communication Group (its description is the only settable field)."""
        args = self._base("modify", kwargs)
        args.extend(["--cte-ldt-group-comm-service-description", kwargs["ldt_comm_group_description"]])
        return self._run(args, kwargs)

    def _ldt_comm_group_delete(self, **kwargs):
        """Delete an LDT Communication Group."""
        return self._run(self._base("delete", kwargs), kwargs)

    def _ldt_comm_group_add_clients(self, **kwargs):
        """Add CTE clients to an LDT Communication Group."""
        args = self._base("add-clients", kwargs)
        args.extend(["--cte-client-list", kwargs["cte_client_list"]])
        return self._run(args, kwargs)

    def _ldt_comm_group_list_clients(self, **kwargs):
        """List the CTE clients in an LDT Communication Group."""
        args = self._base("list-clients", kwargs)
        self._paging(args, kwargs)
        for key, flag in (("cte_client_name", "--cte-client-name"), ("client_os_type", "--client-os-type"),
                          ("cte_profile_name", "--cte-profile-name")):
            if kwargs.get(key):
                args.extend([flag, kwargs[key]])
        return self._run(args, kwargs)

    def _ldt_comm_group_remove_client(self, **kwargs):
        """Remove a CTE client from an LDT Communication Group."""
        args = self._base("remove-client", kwargs)
        args.extend(["--cte-client-identifier", kwargs["cte_client_identifier"]])
        return self._run(args, kwargs)

    def _ldt_comm_group_status(self, **kwargs):
        """Status details of an LDT Communication Group (members, primary, transformation)."""
        return self._run(self._base("get-status-details", kwargs), kwargs)
