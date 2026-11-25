"""Client group operations for CTE management."""

from typing import Any
from .base import CTESubTool, bool_flag

class ClientGroupOperations(CTESubTool):
    """Handles all client group operations for CTE management."""
    
    def get_operations(self) -> list[str]:
        """Return list of all client group operations."""
        return [
            "client_group_create", "client_group_list", "client_group_get", 
            "client_group_delete", "client_group_modify",
            "client_group_add_clients", "client_group_list_clients", "client_group_remove_client",
            "client_group_create_guardpoint", "client_group_list_guardpoints", "client_group_get_guardpoint",
            "client_group_modify_guardpoint", "client_group_unguard_guardpoint"
        ]
    
    def get_schema_properties(self) -> dict[str, Any]:
        """Return schema properties specific to client group operations."""
        return {
            "client_group_name": {
                "type": "string",
                "description": "Name of CTE client group"
            },
            "client_group_identifier": {
                "type": "string",
                "description": "Client group identifier"
            },
            "client_group_description": {
                "type": "string",
                "description": "Description for CTE client group"
            },
            "client_group_password": {
                "type": "string",
                "description": "Password for CTE client group"
            },
            "cluster_type": {
                "type": "string",
                "enum": ["NON-CLUSTER", "HDFS"],
                "default": "NON-CLUSTER",
                "description": "Cluster type"
            },
            "cte_client_list": {
                "type": "string",
                "description": "Comma-separated CTE client identifiers (names, IDs or URIs), e.g. '10.0.4.12,10.0.4.15'"
            },
            "inherit_attributes": {
                "type": "boolean",
                "description": "Clients added to the group take the group's attributes (profile, settings)"
            },
            "network_share_credentials_identifier": {
                "type": "string",
                "description": "SMB connection (Connection Manager) whose credentials CTE uses for a CIFS GuardPoint"
            },
            "dps_id": {
                "type": "string",
                "description": "ID of the Designated Primary Set (DPS) for a CIFS GuardPoint"
            },
            "guard_path": {
                "type": "string",
                "description": "Filter: guarded path"
            }
        }
    
    def get_action_requirements(self) -> dict[str, Any]:
        """Return action requirements for client group operations."""
        return {
            "client_group_create": {
                "required": ["client_group_name"],
                "optional": ["cluster_type", "client_group_description", "client_group_password", 
                            "password_creation_method", "comm_enabled", "cte_profile_identifier", 
                            "domain", "auth_domain"],
                "example": {
                    "action": "client_group_create",
                    "client_group_name": "WebServerGroup",
                    "cluster_type": "NON-CLUSTER",
                    "client_group_description": "Web server client group"
                }
            },
            "client_group_list": {
                "required": [],
                "optional": ["limit", "skip", "client_group_name", "cluster_type", "domain", "auth_domain"],
                "example": {
                    "action": "client_group_list",
                    "limit": 20
                }
            },
            "client_group_get": {
                "required": ["client_group_identifier"],
                "optional": ["domain", "auth_domain"],
                "example": {
                    "action": "client_group_get",
                    "client_group_identifier": "WebServerGroup"
                }
            },
            "client_group_delete": {
                "required": ["client_group_identifier"],
                "optional": ["domain", "auth_domain"],
                "example": {
                    "action": "client_group_delete",
                    "client_group_identifier": "WebServerGroup"
                }
            },
            "client_group_modify": {
                "required": ["client_group_identifier"],
                "optional": ["client_group_description", "client_group_password", "password_creation_method", 
                            "comm_enabled", "cte_client_locked", "system_locked", "cte_profile_identifier", 
                            "domain", "auth_domain"],
                "example": {
                    "action": "client_group_modify",
                    "client_group_identifier": "WebServerGroup",
                    "client_group_description": "Updated description"
                }
            },
            "client_group_add_clients": {
                "required": ["client_group_identifier", "cte_client_list"],
                "optional": ["inherit_attributes", "domain", "auth_domain"],
                "example": {
                    "action": "client_group_add_clients",
                    "client_group_identifier": "uc-smb-hosts",
                    "cte_client_list": "10.0.4.12,10.0.4.15",
                    "inherit_attributes": True
                }
            },
            "client_group_list_clients": {
                "required": ["client_group_identifier"],
                "optional": ["cte_client_name", "limit", "domain", "auth_domain"],
                "example": {
                    "action": "client_group_list_clients",
                    "client_group_identifier": "uc-smb-hosts"
                }
            },
            "client_group_remove_client": {
                "required": ["client_group_identifier", "cte_client_identifier"],
                "optional": ["domain", "auth_domain"],
                "example": {
                    "action": "client_group_remove_client",
                    "client_group_identifier": "uc-smb-hosts",
                    "cte_client_identifier": "10.0.4.15"
                }
            },
            "client_group_create_guardpoint": {
                "required": ["client_group_identifier", "guard_path_list", "guard_point_type"],
                "optional": ["cte_policy_identifier", "auto_mount_enabled", "cifs_enabled", "early_access",
                             "preserve_sparse_regions", "mfa_enabled", "is_idt_capable_device",
                             "network_share_credentials_identifier", "dps_id", "domain", "auth_domain"],
                "example": {
                    "action": "client_group_create_guardpoint",
                    "client_group_identifier": "uc-smb-hosts",
                    "guard_path_list": "\\\\fileserver\\share\\letters",
                    "guard_point_type": "directory_auto",
                    "cte_policy_identifier": "uc-smb-policy",
                    "cifs_enabled": True,
                    "network_share_credentials_identifier": "uc-cifs-share"
                }
            },
            "client_group_list_guardpoints": {
                "required": ["client_group_identifier"],
                "optional": ["guard_path", "cte_policy_identifier", "limit", "skip", "domain", "auth_domain"],
                "example": {
                    "action": "client_group_list_guardpoints",
                    "client_group_identifier": "uc-smb-hosts"
                }
            },
            "client_group_get_guardpoint": {
                "required": ["client_group_identifier", "guard_point_identifier"],
                "optional": ["domain", "auth_domain"],
                "example": {
                    "action": "client_group_get_guardpoint",
                    "client_group_identifier": "uc-smb-hosts",
                    "guard_point_identifier": "<id from client_group_list_guardpoints>"
                }
            },
            "client_group_modify_guardpoint": {
                "required": ["client_group_identifier", "guard_point_identifier"],
                "optional": ["guard_enabled", "mfa_enabled", "network_share_credentials_identifier", "dps_id",
                             "domain", "auth_domain"],
                "example": {
                    "action": "client_group_modify_guardpoint",
                    "client_group_identifier": "uc-smb-hosts",
                    "guard_point_identifier": "<id from client_group_list_guardpoints>",
                    "mfa_enabled": False
                }
            },
            "client_group_unguard_guardpoint": {
                "required": ["client_group_identifier", "guard_point_identifier"],
                "optional": ["domain", "auth_domain"],
                "example": {
                    "action": "client_group_unguard_guardpoint",
                    "client_group_identifier": "uc-smb-hosts",
                    "guard_point_identifier": "<id from client_group_list_guardpoints>"
                }
            }
        }
    
    async def execute_operation(self, action: str, **kwargs: Any) -> Any:
        """Execute the specified client group operation."""
        method_name = f"_{action}"
        if hasattr(self, method_name):
            return getattr(self, method_name)(**kwargs)
        else:
            return {"error": f"Unknown client group action: {action}"}
    
    def _client_group_create(self, **kwargs):
        """Create a CTE client group."""
        args = ["cte", "client-groups", "create"]
        args.extend(["--client-group-name", kwargs["client_group_name"]])
        args.extend(["--cluster-type", kwargs.get("cluster_type", "NON-CLUSTER")])

        if kwargs.get("client_group_description"):
            args.extend(["--client-group-description", kwargs["client_group_description"]])
        if kwargs.get("client_group_password"):
            args.extend(["--client-group-password", kwargs["client_group_password"]])
        if kwargs.get("password_creation_method", "GENERATE") != "GENERATE":
            args.extend(["--password-creation-method", kwargs["password_creation_method"]])
        if kwargs.get("comm_enabled"):
            args.append("--comm-enabled")
        if kwargs.get("cte_profile_identifier"):
            args.extend(["--cte-profile-identifier", kwargs["cte_profile_identifier"]])
        
        result = self.execute_with_domain(args, kwargs.get("domain"), kwargs.get("auth_domain"))
        return result.get("data", result.get("stdout", ""))
    
    def _client_group_list(self, **kwargs):
        """List CTE client groups."""
        args = ["cte", "client-groups", "list"]
        args.extend(["--limit", str(kwargs.get("limit", 10))])
        args.extend(["--skip", str(kwargs.get("skip", 0))])
        
        if kwargs.get("client_group_name"):
            args.extend(["--client-group-name", kwargs["client_group_name"]])
        if kwargs.get("cluster_type"):
            args.extend(["--cluster-type", kwargs["cluster_type"]])
        
        result = self.execute_with_domain(args, kwargs.get("domain"), kwargs.get("auth_domain"))
        return result.get("data", result.get("stdout", ""))
    
    def _client_group_get(self, **kwargs):
        """Get a CTE client group."""
        args = ["cte", "client-groups", "get"]
        args.extend(["--client-group-identifier", kwargs["client_group_identifier"]])
        
        result = self.execute_with_domain(args, kwargs.get("domain"), kwargs.get("auth_domain"))
        return result.get("data", result.get("stdout", ""))
    
    def _client_group_delete(self, **kwargs):
        """Delete a CTE client group."""
        args = ["cte", "client-groups", "delete"]
        args.extend(["--client-group-identifier", kwargs["client_group_identifier"]])
        
        result = self.execute_with_domain(args, kwargs.get("domain"), kwargs.get("auth_domain"))
        return result.get("data", result.get("stdout", ""))
    
    def _client_group_modify(self, **kwargs):
        """Modify a CTE client group."""
        args = ["cte", "client-groups", "modify"]
        args.extend(["--client-group-identifier", kwargs["client_group_identifier"]])
        
        if kwargs.get("client_group_description") is not None:
            args.extend(["--client-group-description", kwargs["client_group_description"]])
        if kwargs.get("client_group_password"):
            args.extend(["--client-group-password", kwargs["client_group_password"]])
        if kwargs.get("password_creation_method"):
            args.extend(["--password-creation-method", kwargs["password_creation_method"]])
        if kwargs.get("comm_enabled") is not None:
            args.append(bool_flag("--comm-enabled", kwargs["comm_enabled"]))
        if kwargs.get("cte_client_locked") is not None:
            args.append(bool_flag("--cte-client-locked", kwargs["cte_client_locked"]))
        if kwargs.get("system_locked") is not None:
            args.append(bool_flag("--system-locked", kwargs["system_locked"]))
        if kwargs.get("cte_profile_identifier"):
            args.extend(["--cte-profile-identifier", kwargs["cte_profile_identifier"]])
        
        result = self.execute_with_domain(args, kwargs.get("domain"), kwargs.get("auth_domain"))
        return result.get("data", result.get("stdout", ""))

    # Members

    def _run(self, args, kwargs):
        result = self.execute_with_domain(args, kwargs.get("domain"), kwargs.get("auth_domain"))
        return result.get("data", result.get("stdout", ""))

    def _client_group_add_clients(self, **kwargs):
        """Add CTE clients to a client group (they get the group's GuardPoints)."""
        args = ["cte", "client-groups", "add-clients",
                "--client-group-identifier", kwargs["client_group_identifier"],
                "--cte-client-list", kwargs["cte_client_list"]]
        if kwargs.get("inherit_attributes") is not None:
            args.append(bool_flag("--inherit-attributes", kwargs["inherit_attributes"]))
        return self._run(args, kwargs)

    def _client_group_list_clients(self, **kwargs):
        """List the CTE clients in a client group."""
        args = ["cte", "client-groups", "list-clients",
                "--client-group-identifier", kwargs["client_group_identifier"],
                "--limit", str(kwargs.get("limit", 100))]
        if kwargs.get("cte_client_name"):
            args.extend(["--cte-client-name", kwargs["cte_client_name"]])
        return self._run(args, kwargs)

    def _client_group_remove_client(self, **kwargs):
        """Remove a CTE client from a client group (the group's GuardPoints leave it)."""
        args = ["cte", "client-groups", "remove-client",
                "--client-group-identifier", kwargs["client_group_identifier"],
                "--cte-client-identifier", kwargs["cte_client_identifier"]]
        return self._run(args, kwargs)

    # GuardPoints on the group (each member gets a copy)

    def _client_group_create_guardpoint(self, **kwargs):
        """Create a GuardPoint on a client group."""
        args = ["cte", "client-groups", "create-guardpoints",
                "--client-group-identifier", kwargs["client_group_identifier"],
                "--guard-path-list", kwargs["guard_path_list"],
                "--guard-point-type", kwargs["guard_point_type"]]
        if kwargs.get("cte_policy_identifier"):
            args.extend(["--cte-policy-identifier", kwargs["cte_policy_identifier"]])
        for key in ("auto_mount_enabled", "cifs_enabled", "early_access", "preserve_sparse_regions",
                    "mfa_enabled", "is_idt_capable_device"):
            if kwargs.get(key) is not None:
                args.append(bool_flag("--" + key.replace("_", "-"), kwargs[key]))
        if kwargs.get("network_share_credentials_identifier"):
            args.extend(["--network-share-credentials-identifier", kwargs["network_share_credentials_identifier"]])
        if kwargs.get("dps_id"):
            args.extend(["--dps-id", kwargs["dps_id"]])
        return self._run(args, kwargs)

    def _client_group_list_guardpoints(self, **kwargs):
        """List the GuardPoints of a client group."""
        args = ["cte", "client-groups", "list-guardpoints",
                "--client-group-identifier", kwargs["client_group_identifier"],
                "--limit", str(kwargs.get("limit", 100)),
                "--skip", str(kwargs.get("skip", 0))]
        if kwargs.get("guard_path"):
            args.extend(["--guard-path", kwargs["guard_path"]])
        if kwargs.get("cte_policy_identifier"):
            args.extend(["--cte-policy-identifier", kwargs["cte_policy_identifier"]])
        return self._run(args, kwargs)

    def _client_group_get_guardpoint(self, **kwargs):
        """Get one GuardPoint of a client group."""
        args = ["cte", "client-groups", "get-guardpoints",
                "--client-group-identifier", kwargs["client_group_identifier"],
                "--guard-point-identifier", kwargs["guard_point_identifier"]]
        return self._run(args, kwargs)

    def _client_group_modify_guardpoint(self, **kwargs):
        """Modify a client group GuardPoint (propagated to every member)."""
        args = ["cte", "client-groups", "modify-guardpoints",
                "--client-group-identifier", kwargs["client_group_identifier"],
                "--guard-point-identifier", kwargs["guard_point_identifier"]]
        for key in ("guard_enabled", "mfa_enabled"):
            if kwargs.get(key) is not None:
                args.append(bool_flag("--" + key.replace("_", "-"), kwargs[key]))
        if kwargs.get("network_share_credentials_identifier"):
            args.extend(["--network-share-credentials-identifier", kwargs["network_share_credentials_identifier"]])
        if kwargs.get("dps_id"):
            args.extend(["--dps-id", kwargs["dps_id"]])
        return self._run(args, kwargs)

    def _client_group_unguard_guardpoint(self, **kwargs):
        """Unguard a client group GuardPoint (removed from the group and every member)."""
        args = ["cte", "client-groups", "unguard-guardpoints",
                "--client-group-identifier", kwargs["client_group_identifier"],
                "--guard-point-identifier", kwargs["guard_point_identifier"]]
        return self._run(args, kwargs)
