"""NetSapiens server type detection via systemd services and packages."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from nssec.core.checklist import run_command


class ServerType(Enum):
    """NetSapiens server types."""

    CORE = "core"  # NMS - Main SIP/PBX
    NDP = "ndp"  # Device provisioning
    RECORDING = "recording"  # LiCf - Call recording
    CONFERENCING = "conferencing"  # NCS - Conferencing
    QOS = "qos"  # Quality monitoring
    COMBO = "combo"  # Multiple roles
    UNKNOWN = "unknown"


class Runtime(Enum):
    """How a component runs."""

    SYSTEMD = "systemd"
    TOMCAT = "tomcat"
    PACKAGE_ONLY = "package_only"  # No daemon (cron jobs, CLI tools, etc.)


@dataclass
class ServiceInfo:
    """Information about a NetSapiens service."""

    name: str
    service_name: str
    package_name: str
    server_type: ServerType
    description: str
    runtime: Runtime = Runtime.SYSTEMD
    tomcat_webapp: str = ""  # Webapp name or war file for Tomcat components


# NetSapiens services and their mappings
NS_SERVICES = [
    ServiceInfo(
        name="NMS",
        service_name="netsapiens_nms.service",
        package_name="netsapiens-nms",
        server_type=ServerType.CORE,
        description="Core SIP/PBX server",
    ),
    ServiceInfo(
        name="NDP",
        service_name="",  # Runs on Tomcat, not as a systemd service
        package_name="netsapiens-ndp",
        server_type=ServerType.NDP,
        description="Device provisioning",
        runtime=Runtime.TOMCAT,
        tomcat_webapp="cfg",
    ),
    ServiceInfo(
        name="LiCf",
        service_name="netsapiens_licf.service",
        package_name="netsapiens-licf",
        server_type=ServerType.RECORDING,
        description="Call recording (Legal Intercept)",
    ),
    ServiceInfo(
        name="NCS",
        service_name="netsapiens_ncs.service",
        package_name="netsapiens-ncs",
        server_type=ServerType.CONFERENCING,
        description="Conferencing server",
    ),
    ServiceInfo(
        name="SBUS",
        service_name="netsapiens_sbus.service",
        package_name="netsapiens-sbus",
        server_type=ServerType.CORE,  # Usually with Core
        description="Service Bus",
    ),
    ServiceInfo(
        name="NFR",
        service_name="netsapiens_nfr.service",
        package_name="netsapiens-nfr",
        server_type=ServerType.CORE,  # File replicator, usually with Core
        description="File Replicator",
    ),
    ServiceInfo(
        name="NMC",
        service_name="netsapiens_nmc.service",
        package_name="netsapiens-nmc",
        server_type=ServerType.RECORDING,  # Media converter, usually with Recording
        description="Media Converter",
    ),
    ServiceInfo(
        name="Node",
        service_name="nsnode.service",
        package_name="netsapiens-node",
        server_type=ServerType.CORE,
        description="NetSapiens Node",
    ),
    ServiceInfo(
        name="Insight Agent",
        service_name="netsapiens-insight-agent.service",
        package_name="netsapiens-insight-agent",
        server_type=ServerType.CORE,  # Can be on any server
        description="Monitoring agent",
    ),
    ServiceInfo(
        name="APIBAN",
        service_name="",  # Runs via cron, no service
        package_name="netsapiens-apiban",
        server_type=ServerType.CORE,  # Should be on all SIP servers
        description="SIP scanner blocking via UFW",
        runtime=Runtime.PACKAGE_ONLY,
    ),
    ServiceInfo(
        name="Certmanager",
        service_name="",
        package_name="netsapiens-certmanager",
        server_type=ServerType.CORE,
        description="SSL certificate management",
        runtime=Runtime.PACKAGE_ONLY,
    ),
    ServiceInfo(
        name="API",
        service_name="",
        package_name="netsapiens-api",
        server_type=ServerType.CORE,
        description="REST API",
        runtime=Runtime.PACKAGE_ONLY,
    ),
    ServiceInfo(
        name="Portals",
        service_name="",
        package_name="netsapiens-portals",
        server_type=ServerType.CORE,
        description="Web portals",
        runtime=Runtime.PACKAGE_ONLY,
    ),
]


def _run_command(cmd: list[str], timeout: int = 10) -> str | None:
    """Run a command and return stdout, or None on error.

    This is a convenience wrapper around run_command from checklist.py
    that returns only stdout for simpler use cases.
    """
    stdout, _, returncode = run_command(cmd, timeout=timeout)
    return stdout if returncode == 0 else None


def get_installed_packages() -> set[str]:
    """Get set of installed netsapiens packages via dpkg."""
    output = _run_command(["dpkg", "-l"])
    if not output:
        return set()

    packages = set()
    for line in output.splitlines():
        if line.startswith("ii") and "netsapiens" in line:
            parts = line.split()
            if len(parts) >= 2:
                packages.add(parts[1])
    return packages


def get_active_services() -> dict[str, bool]:
    """Get dict of netsapiens service names and their active status."""
    # Get all netsapiens-related services
    output = _run_command(
        ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend"]
    )
    if not output:
        return {}

    services = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            service_name = parts[0]
            if "netsapiens" in service_name or "nsnode" in service_name or "voip" in service_name:
                # Check if active (3rd column is "active")
                is_active = parts[2] == "active" if len(parts) > 2 else False
                services[service_name] = is_active

    return services


def get_enabled_services() -> set[str]:
    """Get set of enabled netsapiens services."""
    output = _run_command(
        [
            "systemctl",
            "list-unit-files",
            "--type=service",
            "--state=enabled",
            "--no-pager",
            "--no-legend",
        ]
    )
    if not output:
        return set()

    enabled = set()
    for line in output.splitlines():
        parts = line.split()
        if parts:
            service_name = parts[0]
            if "netsapiens" in service_name or "nsnode" in service_name:
                enabled.add(service_name)
    return enabled


def is_tomcat_webapp_deployed(webapp_name: str) -> bool:
    """Check if a Tomcat webapp is deployed and Tomcat is running.

    Checks for the webapp .war file or extracted directory across
    common Tomcat installation paths (tomcat6 through tomcat10).
    """
    import os

    # Check if tomcat service is active
    output = _run_command(["systemctl", "is-active", "tomcat9"])
    tomcat_active = output and output.strip() == "active"
    if not tomcat_active:
        # Try generic tomcat service name
        output = _run_command(["systemctl", "is-active", "tomcat"])
        tomcat_active = output and output.strip() == "active"

    if not tomcat_active:
        return False

    # Check for webapp in common Tomcat webapps directories
    for version in ["9", "10", "8", "7", "6", ""]:
        base = f"/var/lib/tomcat{version}/webapps"
        war_path = os.path.join(base, f"{webapp_name}.war")
        dir_path = os.path.join(base, webapp_name)
        if os.path.exists(war_path) or os.path.isdir(dir_path):
            return True

    return False


def detect_installed_components() -> dict[str, dict]:
    """Detect which NetSapiens components are installed and running.

    Returns:
        Dict mapping component names to their status info.
    """
    packages = get_installed_packages()
    active_services = get_active_services()
    enabled_services = get_enabled_services()

    components = {}

    for svc in NS_SERVICES:
        pkg_installed = svc.package_name in packages
        svc_enabled = svc.service_name in enabled_services

        # Determine active status based on runtime type
        if svc.runtime == Runtime.TOMCAT:
            svc_active = (
                is_tomcat_webapp_deployed(svc.tomcat_webapp) if svc.tomcat_webapp else False
            )
        elif svc.runtime == Runtime.PACKAGE_ONLY:
            svc_active = False
        else:
            svc_active = active_services.get(svc.service_name, False)

        if pkg_installed or svc_active:
            components[svc.name] = {
                "service_info": svc,
                "package_installed": pkg_installed,
                "service_active": svc_active,
                "service_enabled": svc_enabled,
                "server_type": svc.server_type,
            }

    return components


def detect_server_type() -> ServerType:
    """Detect the primary server type based on installed/running services.

    Returns:
        ServerType enum value indicating the server role.
    """
    components = detect_installed_components()

    if not components:
        return ServerType.UNKNOWN

    # Collect unique server types from active components
    server_types: set[ServerType] = set()
    for name, info in components.items():
        # Prioritize components that are actually running
        if info["service_active"] or info["package_installed"]:
            server_types.add(info["server_type"])

    # Remove CORE if it's just supporting services (SBUS, NFR, Node, Insight)
    primary_types: set[ServerType] = {
        ServerType.CORE,
        ServerType.NDP,
        ServerType.RECORDING,
        ServerType.CONFERENCING,
    }
    detected_primary: set[ServerType] = server_types & primary_types

    if len(detected_primary) > 1:
        return ServerType.COMBO
    elif len(detected_primary) == 1:
        return detected_primary.pop()
    elif ServerType.CORE in server_types:
        return ServerType.CORE

    return ServerType.UNKNOWN


def get_server_info() -> dict:
    """Get detailed information about the server configuration.

    Returns:
        Dictionary with server type, installed components, and service status.
    """
    components = detect_installed_components()
    server_type = detect_server_type()
    packages = get_installed_packages()
    active_services = get_active_services()

    return {
        "server_type": server_type.value,
        "components": {
            name: {
                "description": info["service_info"].description,
                "package": info["service_info"].package_name,
                "service": info["service_info"].service_name,
                "runtime": info["service_info"].runtime,
                "installed": info["package_installed"],
                "active": info["service_active"],
                "enabled": info["service_enabled"],
            }
            for name, info in components.items()
        },
        "is_combo": server_type == ServerType.COMBO,
        "all_packages": sorted(packages),
        "active_services": sorted([s for s, active in active_services.items() if active]),
    }


def get_applicable_security_modules(server_type: ServerType | None = None) -> list[str]:
    """Get security modules applicable to this server type.

    Args:
        server_type: Server type to check. If None, auto-detect.

    Returns:
        List of applicable security module names.
    """
    if server_type is None:
        server_type = detect_server_type()

    # Base modules apply to all servers
    modules = ["ssh", "firewall"]

    if server_type == ServerType.CORE:
        modules.extend(["waf_admin_ui", "mysql", "checkip", "api_rate_limiting", "sbus"])
    elif server_type == ServerType.NDP:
        modules.extend(["waf_endpoints", "mtls"])
    elif server_type == ServerType.RECORDING:
        modules.extend(["waf_recording", "upload_limits", "nmc"])
    elif server_type == ServerType.CONFERENCING:
        modules.extend(["waf_ncs", "media_ports"])
    elif server_type == ServerType.COMBO:
        # All modules for combo servers
        modules.extend(
            [
                "waf_admin_ui",
                "waf_endpoints",
                "waf_recording",
                "waf_ncs",
                "mysql",
                "checkip",
                "api_rate_limiting",
                "mtls",
                "upload_limits",
                "sbus",
                "nmc",
                "media_ports",
            ]
        )

    return modules
