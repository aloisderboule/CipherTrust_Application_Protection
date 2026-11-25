"""Profile operations for CTE management."""

import json
from typing import Any
from .base import CTESubTool, bool_flag

# Logger / syslog objects passed to `ksctl cte profiles modify --<name>-json`.
# Each one replaces that whole setting: read it with profile_get first and
# send it back with the changes.
JSON_SETTINGS = {
    "policy_evaluation_logger": "--policy-evaluation-logger-json",
    "management_service_logger": "--management-service-logger-json",
    "security_admin_logger": "--security-admin-logger-json",
    "system_admin_logger": "--system-admin-logger-json",
    "syslog_settings": "--syslog-settings-json",
}

class ProfileOperations(CTESubTool):
    """Handles all profile operations for CTE management."""
    
    def get_operations(self) -> list[str]:
        """Return list of all profile operations."""
        return [
            "profile_create", "profile_list", "profile_get", 
            "profile_delete", "profile_modify"
        ]
    
    def get_schema_properties(self) -> dict[str, Any]:
        """Return schema properties specific to profile operations."""
        return {
            "cte_profile_name": {
                "type": "string",
                "description": "Name of the CTE profile"
            },
            "cte_profile_identifier": {
                "type": "string",
                "description": "CTE profile identifier"
            },
            "cte_profile_description": {
                "type": "string",
                "description": "Description of the CTE profile"
            },
            "concise_logging": {
                "type": "boolean",
                "description": "Whether to allow concise logging"
            },
            "connect_timeout": {
                "type": "integer",
                "description": "Connect timeout in seconds (5-150)"
            },
            "metadata_scan_interval": {
                "type": "integer",
                "description": "Time interval in seconds to scan files under guard point"
            },
            "partial_config_enable": {
                "type": "boolean",
                "description": "Enable CM to send partial config to agents"
            },
            "server_response_rate": {
                "type": "integer",
                "description": "Percentage value of successful API calls (0-100)"
            },
            "policy_evaluation_logger": {
                "type": "object",
                "description": "Policy evaluation logger (who accessed what: permit/deny), e.g. "
                               "{\"threshold\": \"INFO\", \"syslog_enabled\": true, \"file_enabled\": true}. "
                               "Replaces the whole setting: start from profile_get's value"
            },
            "management_service_logger": {
                "type": "object",
                "description": "Management service logger (agent life, keys, LDT, MFA); same shape as policy_evaluation_logger"
            },
            "security_admin_logger": {
                "type": "object",
                "description": "Security admin logger; same shape as policy_evaluation_logger"
            },
            "system_admin_logger": {
                "type": "object",
                "description": "System admin logger; same shape as policy_evaluation_logger"
            },
            "syslog_settings": {
                "type": "object",
                "description": "Agents' syslog forwarding, e.g. {\"local\": false, \"syslog_threshold\": \"INFO\", "
                               "\"servers\": [{\"name\": \"10.0.4.20\", \"port\": 5514, \"protocol\": \"UDP\", "
                               "\"message_format\": \"RFC5424\"}]}. Replaces the whole setting"
            },
            "oidc_connection_id": {
                "type": "string",
                "description": "OIDC connection (name or ID) the agents use for MFA on GuardPoints with mfa_enabled"
            },
            "mfa_exempt_user_set_id": {
                "type": "string",
                "description": "User set exempted from MFA"
            }
        }
    
    def get_action_requirements(self) -> dict[str, Any]:
        """Return action requirements for profile operations."""
        return {
            "profile_create": {
                "required": ["cte_profile_name"],
                "optional": ["cte_profile_description", "concise_logging", "connect_timeout", 
                            "metadata_scan_interval", "partial_config_enable", "server_response_rate", 
                            "domain", "auth_domain"],
                "example": {
                    "action": "profile_create",
                    "cte_profile_name": "StandardProfile",
                    "cte_profile_description": "Standard CTE profile",
                    "connect_timeout": 30
                }
            },
            "profile_list": {
                "required": [],
                "optional": ["limit", "skip", "cte_profile_name", "domain", "auth_domain"],
                "example": {
                    "action": "profile_list",
                    "limit": 20
                }
            },
            "profile_get": {
                "required": ["cte_profile_identifier"],
                "optional": ["cte_profile_name", "domain", "auth_domain"],
                "example": {
                    "action": "profile_get",
                    "cte_profile_identifier": "StandardProfile"
                }
            },
            "profile_delete": {
                "required": ["cte_profile_identifier"],
                "optional": ["cte_profile_name", "domain", "auth_domain"],
                "example": {
                    "action": "profile_delete",
                    "cte_profile_identifier": "StandardProfile"
                }
            },
            "profile_modify": {
                "required": ["cte_profile_identifier"],
                "optional": ["cte_profile_description", "concise_logging", "connect_timeout",
                            "metadata_scan_interval", "partial_config_enable", "server_response_rate",
                            "policy_evaluation_logger", "management_service_logger", "security_admin_logger",
                            "system_admin_logger", "syslog_settings", "oidc_connection_id",
                            "mfa_exempt_user_set_id", "domain", "auth_domain"],
                "example": {
                    "action": "profile_modify",
                    "cte_profile_identifier": "DefaultClientProfile",
                    "policy_evaluation_logger": {"threshold": "INFO", "syslog_enabled": True, "file_enabled": True},
                    "oidc_connection_id": "uc-keycloak-cte"
                }
            }
        }
    
    async def execute_operation(self, action: str, **kwargs: Any) -> Any:
        """Execute the specified profile operation."""
        method_name = f"_{action}"
        if hasattr(self, method_name):
            return getattr(self, method_name)(**kwargs)
        else:
            return {"error": f"Unknown profile action: {action}"}
    
    def _profile_create(self, **kwargs):
        """Create a CTE profile."""
        args = ["cte", "profiles", "create"]
        args.extend(["--cte-profile-name", kwargs["cte_profile_name"]])
        
        if kwargs.get("cte_profile_description"):
            args.extend(["--cte-profile-description", kwargs["cte_profile_description"]])
        if kwargs.get("concise_logging") is not None:
            if kwargs["concise_logging"]:
                args.append("--concise-logging")
        if kwargs.get("connect_timeout") is not None:
            args.extend(["--connect-timeout", str(kwargs["connect_timeout"])])
        if kwargs.get("metadata_scan_interval") is not None:
            args.extend(["--metadata-scan-interval", str(kwargs["metadata_scan_interval"])])
        if kwargs.get("partial_config_enable") is not None:
            if kwargs["partial_config_enable"]:
                args.append("--partial-config-enable")
        if kwargs.get("server_response_rate") is not None:
            args.extend(["--server-response-rate", str(kwargs["server_response_rate"])])
        
        result = self.execute_with_domain(args, kwargs.get("domain"), kwargs.get("auth_domain"))
        return result.get("data", result.get("stdout", ""))
    
    def _profile_list(self, **kwargs):
        """List CTE profiles."""
        args = ["cte", "profiles", "list"]
        args.extend(["--limit", str(kwargs.get("limit", 10))])
        args.extend(["--skip", str(kwargs.get("skip", 0))])
        
        if kwargs.get("cte_profile_name"):
            args.extend(["--cte-profile-name", kwargs["cte_profile_name"]])
        
        result = self.execute_with_domain(args, kwargs.get("domain"), kwargs.get("auth_domain"))
        return result.get("data", result.get("stdout", ""))
    
    def _profile_get(self, **kwargs):
        """Get a CTE profile."""
        args = ["cte", "profiles", "get"]
        args.extend(["--cte-profile-identifier", kwargs["cte_profile_identifier"]])
        
        if kwargs.get("cte_profile_name"):
            args.extend(["--cte-profile-name", kwargs["cte_profile_name"]])
        
        result = self.execute_with_domain(args, kwargs.get("domain"), kwargs.get("auth_domain"))
        return result.get("data", result.get("stdout", ""))
    
    def _profile_delete(self, **kwargs):
        """Delete a CTE profile."""
        args = ["cte", "profiles", "delete"]
        args.extend(["--cte-profile-identifier", kwargs["cte_profile_identifier"]])
        
        if kwargs.get("cte_profile_name"):
            args.extend(["--cte-profile-name", kwargs["cte_profile_name"]])
        
        result = self.execute_with_domain(args, kwargs.get("domain"), kwargs.get("auth_domain"))
        return result.get("data", result.get("stdout", ""))
    
    def _profile_modify(self, **kwargs):
        """Modify a CTE profile."""
        args = ["cte", "profiles", "modify"]
        args.extend(["--cte-profile-identifier", kwargs["cte_profile_identifier"]])

        if kwargs.get("cte_profile_description"):
            args.extend(["--cte-profile-description", kwargs["cte_profile_description"]])
        if kwargs.get("concise_logging") is not None:
            args.append(bool_flag("--concise-logging", kwargs["concise_logging"]))
        if kwargs.get("connect_timeout") is not None:
            args.extend(["--connect-timeout", str(kwargs["connect_timeout"])])
        if kwargs.get("metadata_scan_interval") is not None:
            args.extend(["--metadata-scan-interval", str(kwargs["metadata_scan_interval"])])
        if kwargs.get("partial_config_enable") is not None:
            args.append(bool_flag("--partial-config-enable", kwargs["partial_config_enable"]))
        if kwargs.get("server_response_rate") is not None:
            args.extend(["--server-response-rate", str(kwargs["server_response_rate"])])
        for key, flag in JSON_SETTINGS.items():
            if kwargs.get(key) is not None:
                value = kwargs[key]
                args.extend([flag, value if isinstance(value, str) else json.dumps(value)])
        if kwargs.get("oidc_connection_id"):
            args.extend(["--oidc-connection-id", kwargs["oidc_connection_id"]])
        if kwargs.get("mfa_exempt_user_set_id"):
            args.extend(["--mfa-exempt-user-set-id", kwargs["mfa_exempt_user_set_id"]])
                
        result = self.execute_with_domain(args, kwargs.get("domain"), kwargs.get("auth_domain"))
        return result.get("data", result.get("stdout", ""))