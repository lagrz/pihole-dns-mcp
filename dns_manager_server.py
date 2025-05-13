#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "mcp[cli]",
#     "pydantic",
#     "python-dotenv",
#     "httpx",
# ]
# ///
"""
DNS Host Manager MCP Server

This server provides tools to manage DNS hosts through the API.
It handles authentication and caching of session IDs.
"""

import os
import time
import json
import httpx
import os.path
import stat
import pathlib
import logging
from enum import Enum
from pydantic import BaseModel, AnyHttpUrl, Field, IPvAnyAddress
from typing import Dict, List, Optional
from urllib.parse import quote
from mcp.server.fastmcp import FastMCP, Context
from dotenv import load_dotenv

load_dotenv()

HOME_DIR = pathlib.Path.home()

# Get log level from environment or default to INFO
log_level_str = os.getenv("DNS_API_LOG_LEVEL", "INFO").upper()
log_level = getattr(logging, log_level_str, logging.INFO)

# Determine if logging to file or stdout
log_to_file = os.getenv("DNS_API_LOG_TO_FILE", "false").lower() == "true"

# Configure logging
if log_to_file:
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        filename=os.path.join(HOME_DIR, ".mcp-pihole-api.log"),
        filemode="a",
    )
else:
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

# Initialize FastMCP server
mcp = FastMCP("dns-manager")


class Config(BaseModel):
    """
    Configuration model for the DNS API connection.

    Attributes:
        dns_api_base_url (AnyHttpUrl): The base URL for the DNS API.
        dns_api_password (str): The password for authentication with the DNS API.
    """

    dns_api_base_url: AnyHttpUrl = Field(description="DNS API base URL")
    dns_api_password: str = Field(description="DNS API password")


class DnsHostRequest(BaseModel):
    """
    Model for DNS host entry requests.

    Attributes:
        ip_address (IPvAnyAddress): The IP address (IPv4 or IPv6) for the DNS host entry.
        hostname (str): The hostname to associate with the IP address.
    """

    ip_address: IPvAnyAddress = Field(
        description="The IP address (IPv4 or IPv6) for the DNS host entry"
    )
    hostname: str = Field(description="The hostname to associate with the IP address")


class BlockingStatus(str, Enum):
    """
    Enum for the DNS blocking status values.
    """

    ENABLED = "enabled"
    DISABLED = "disabled"
    FAILED = "failed"
    UNKNOWN = "unknown"


class BlockingStatusResponse(BaseModel):
    """
    Response model for blocking status API.

    Attributes:
        blocking (BlockingStatus): Current blocking status.
        timer (Optional[float]): Remaining seconds until blocking mode is automatically changed, or None if no timer.
        took (float): Time in seconds it took to process the request.
    """

    blocking: BlockingStatus = Field(description="Current blocking status")
    timer: Optional[float] = Field(
        None,
        description="Remaining seconds until blocking mode is automatically changed",
    )
    took: float = Field(description="Time in seconds it took to process the request")


class BlockingStatusRequest(BaseModel):
    """
    Request model for changing blocking status.

    Attributes:
        blocking (bool): Whether blocking should be enabled (True) or disabled (False).
        timer (Optional[float]): Optional timer in seconds. Once elapsed, the opposite blocking mode is set.
    """

    blocking: bool = Field(
        description="Whether blocking should be enabled (True) or disabled (False)"
    )
    timer: Optional[float] = Field(
        None,
        description="Optional timer in seconds after which the opposite blocking mode is set",
    )


config = Config.model_validate(
    {
        "dns_api_base_url": os.getenv("DNS_API_BASE_URL"),
        "dns_api_password": os.getenv("DNS_API_PASSWORD"),
    }
)


# Session management
class SessionManager:
    """
    Manages API sessions including authentication, caching, and renewal.

    This class handles authentication with the DNS API, maintains session IDs,
    and manages the session cache to avoid unnecessary re-authentication.

    Attributes:
        sid (str): The current session ID.
        expiry (float): The expiration timestamp for the current session.
        validity_seconds (int): The validity duration of the session in seconds.
        cache_file (pathlib.Path): Path to the file storing cached session data.
        session_cache (Dict): Dictionary containing cached session information.
    """

    def __init__(self):
        """
        Initialize the SessionManager with default values and load any existing cache.
        """
        self.sid = None
        self.expiry = 0
        self.validity_seconds = 0
        self.cache_file = pathlib.Path(pathlib.Path.home(), ".mcp-pihole-api.json")
        self.session_cache = self._load_cache()

    def _load_cache(self) -> Dict[str, List]:
        """
        Load session cache from file.

        Returns:
            Dict[str, List]: Dictionary containing cached session data, or empty dict if no cache exists.

        Raises:
            Exception: Logs but doesn't propagate exceptions during cache loading.
        """
        try:
            if self.cache_file.exists():
                with open(self.cache_file, "r") as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logging.error(f"Error loading cache: {str(e)}")
            return {}

    def _save_cache(self) -> None:
        """
        Save session cache to file with secure permissions.

        This method saves the current session_cache to the cache file and
        sets the file permissions to 0600 (read/write for owner only).

        Raises:
            Exception: Logs but doesn't propagate exceptions during cache saving.
        """
        try:
            # Create the file with secure permissions (0600)
            with open(self.cache_file, "w") as f:
                json.dump(self.session_cache, f)

            # Set file permissions to 0600 (read/write for owner only)
            os.chmod(self.cache_file, stat.S_IRUSR | stat.S_IWUSR)
            logging.debug(f"Cache saved to {self.cache_file} with secure permissions")
        except Exception as e:
            logging.error(f"Error saving cache: {str(e)}")

    async def get_valid_sid(self) -> str:
        """
        Get a valid session ID, refreshing if necessary.

        This method returns a valid session ID, either from cache or by
        authenticating with the API if the cached session has expired.

        Returns:
            str: A valid session ID.

        Raises:
            Exception: If authentication fails or API communication fails.
        """
        current_time = time.time()
        host_key: str = str(config.dns_api_base_url)
        logging.info(f"Checking session for host: {host_key}")
        # Check if we have a cached session for this host
        if host_key in self.session_cache:
            cached_sid, cached_expiry = self.session_cache[host_key]
            logging.info(f"Cached session found: {cached_sid}")
            if current_time < cached_expiry:
                self.sid = cached_sid
                self.expiry = cached_expiry
                return self.sid
        logging.info("No cached session found")

        # If session is still valid, return existing sid
        if self.sid and current_time < self.expiry:
            return self.sid

        # Otherwise, login and get a new sid
        url = f"{config.dns_api_base_url}api/auth"
        payload = {"password": config.dns_api_password}
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "user-agent": "MCP-DNS-Manager-Server/0.1.0",
        }

        try:
            logging.info(f"Logging in to API: {url}")
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.post(url, headers=headers, json=payload)
                response.raise_for_status()
                data = response.json()

                self.sid = data["session"]["sid"]
                self.validity_seconds = data["session"]["validity"]
                self.expiry = (
                    current_time + self.validity_seconds - 60
                )  # Refresh 1 minute before expiry

                logging.info(f"Successfully logged in: {self.sid}")
                # Update cache
                self.session_cache[host_key] = [self.sid, self.expiry]
                self._save_cache()

                return self.sid
        except httpx.HTTPStatusError as e:
            logging.error(
                f"Authentication failed with status code {e.response.status_code}: {str(e)}"
            )
            raise Exception(f"Authentication failed: {str(e)}")
        except Exception as e:
            logging.error(f"Authentication failed: {str(e)}")
            raise Exception(f"Authentication failed: {str(e)}")


# Create a session manager instance
session_manager = SessionManager()


# Helper functions
async def make_api_request(
    method: str, endpoint: str, data: Optional[Dict] = None, use_json: bool = True
) -> Dict:
    """
    Make an authenticated request to the API.

    Args:
        method (str): HTTP method to use (GET, PUT, DELETE).
        endpoint (str): API endpoint to call (without base URL).
        data (Optional[Dict], optional): Request data for PUT requests. Defaults to None.

    Returns:
        Dict: The JSON response from the API as a dictionary.

    Raises:
        ValueError: If an unsupported HTTP method is provided.
        Exception: If the API request fails or returns an error status.
    """
    sid = await session_manager.get_valid_sid()
    url = f"{config.dns_api_base_url}{endpoint}"

    headers = {
        "accept": "application/json",
        "sid": sid,
        "user-agent": "MCP-DNS-Manager-Server/0.1.0",
    }

    try:
        async with httpx.AsyncClient(verify=False) as client:
            if method.upper() == "GET":
                response = await client.get(url, headers=headers)
            elif method.upper() == "PUT":
                response = await client.put(
                    url,
                    headers=headers,
                    json=data if use_json else None,
                    data=data if not use_json else None,
                )
            elif method.upper() == "POST":
                content_type = (
                    "application/json"
                    if use_json
                    else "application/x-www-form-urlencoded"
                )
                headers["content-type"] = content_type
                response = await client.post(
                    url,
                    headers=headers,
                    json=data if use_json else None,
                    data=data if not use_json else None,
                )
            elif method.upper() == "DELETE":
                response = await client.delete(url, headers=headers)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            logging.debug(f"API response status: {response.status_code}")
            response.raise_for_status()
            if method.upper() == "DELETE":
                return {}
            return response.json()
    except httpx.HTTPStatusError as e:
        logging.error(
            f"API request failed with status code {e.response.status_code}: {str(e)}"
        )
        raise Exception(f"API request failed: {str(e)}")
    except Exception as e:
        logging.error(f"API request failed: {str(e)}")
        raise Exception(f"API request failed: {str(e)}")


# Tool implementations
@mcp.tool()
async def get_dns_hosts(ctx: Context) -> str:
    """
    Get all DNS host entries.

    Retrieves all DNS host entries from the API and formats them as a list.

    Args:
        ctx (Context): The MCP context.

    Returns:
        str: A list of DNS host entries in the format 'IP_ADDRESS HOSTNAME'.

    Raises:
        Exception: If there is an error retrieving DNS hosts from the API.
    """
    try:
        response = await make_api_request("GET", "api/config/dns/hosts")
        hosts = response.get("config", {}).get("dns", {}).get("hosts", [])

        if not hosts:
            return "No DNS hosts found."

        return "DNS Hosts:\n" + "\n".join(hosts)
    except Exception as e:
        return f"Error retrieving DNS hosts: {str(e)}"


@mcp.tool()
async def add_dns_host(ip_address: str, hostname: str) -> str:
    """
    Add a new DNS host entry.

    Validates the IP address and hostname, then adds a new DNS host entry
    to the DNS configuration.

    Args:
        ip_address (str): The IP address for the host entry.
        hostname (str): The hostname to associate with the IP address.

    Returns:
        str: Confirmation message of the addition.

    Raises:
        Exception: If validation fails or there is an error adding the DNS host.
    """
    try:
        dns_host_request = DnsHostRequest.model_validate(
            {"ip_address": ip_address, "hostname": hostname}
        )

        host_entry = f"{dns_host_request.ip_address} {dns_host_request.hostname}"
        encoded_entry = quote(host_entry)
        endpoint = f"api/config/dns/hosts/{encoded_entry}"

        await make_api_request("PUT", endpoint)

        return f"Successfully added DNS host: {host_entry}"
    except Exception as e:
        return f"Error adding DNS host: {str(e)}"


@mcp.tool()
async def delete_dns_host(ip_address: str, hostname: str) -> str:
    """
    Delete a DNS host entry.

    Validates the IP address and hostname, then deletes the corresponding
    DNS host entry from the DNS configuration.

    Args:
        ip_address (str): The IP address of the host entry to delete.
        hostname (str): The hostname of the entry to delete.

    Returns:
        str: Confirmation message of the deletion.

    Raises:
        Exception: If validation fails or there is an error deleting the DNS host.
    """
    try:
        dns_host_request = DnsHostRequest.model_validate(
            {"ip_address": ip_address, "hostname": hostname}
        )

        host_entry = f"{dns_host_request.ip_address} {dns_host_request.hostname}"
        encoded_entry = quote(host_entry)
        endpoint = f"api/config/dns/hosts/{encoded_entry}"

        await make_api_request("DELETE", endpoint)

        return f"Successfully deleted DNS host: {host_entry}"
    except Exception as e:
        return f"Error deleting DNS host: {str(e)}"


@mcp.tool()
async def get_blocking_status() -> str:
    """
    Get the current DNS blocking status.

    Retrieves the current Pi-hole blocking status and any active timers.

    Returns:
        str: A formatted string with the current blocking status and timer information.

    Raises:
        Exception: If there is an error retrieving the blocking status from the API.
    """
    try:
        response = await make_api_request("GET", "api/dns/blocking")
        status_response = BlockingStatusResponse.model_validate(response)

        status_str = f"DNS Blocking Status: {status_response.blocking.value}"

        if status_response.timer is not None:
            minutes, seconds = divmod(status_response.timer, 60)
            if minutes > 0:
                timer_str = f"{int(minutes)} minute{'s' if minutes != 1 else ''} and {int(seconds)} second{'s' if seconds != 1 else ''}"
            else:
                timer_str = f"{int(seconds)} second{'s' if seconds != 1 else ''}"

            status_str += f"\nA timer is active and will change the blocking status in {timer_str}."
        else:
            status_str += (
                "\nNo timer is active. This status is permanent until changed."
            )

        return status_str
    except Exception as e:
        return f"Error retrieving blocking status: {str(e)}"


@mcp.tool()
async def set_blocking_status(blocking: bool, timer: Optional[float] = None) -> str:
    """
    Change the current DNS blocking status.

    Sets the Pi-hole blocking status to enabled or disabled, with an optional timer.
    To disable DNS blocking set blocking to False and a timer in seconds to disable blocking.
    To enable DNS blocking set blocking to True and None for timer

    Args:
        blocking (bool): True to enable blocking, False to disable it.
        timer (Optional[float], optional): Timer in seconds after which the blocking status will automatically reverse.
                                          Defaults to None (permanent change).

    Returns:
        str: A confirmation message with the new status and timer information.

    Raises:
        Exception: If there is an error setting the blocking status.
    """
    try:
        request = BlockingStatusRequest(blocking=blocking, timer=timer)

        response = await make_api_request(
            "POST",
            "api/dns/blocking",
            data={"blocking": request.blocking, "timer": request.timer},
        )

        status_response = BlockingStatusResponse.model_validate(response)
        status_str = f"DNS Blocking has been set to: {status_response.blocking.value}"

        if status_response.timer is not None:
            minutes, seconds = divmod(status_response.timer, 60)
            if minutes > 0:
                timer_str = f"{int(minutes)} minute{'s' if minutes != 1 else ''} and {int(seconds)} second{'s' if seconds != 1 else ''}"
            else:
                timer_str = f"{int(seconds)} second{'s' if seconds != 1 else ''}"

            status_str += f"\nA timer has been set and will change the blocking status in {timer_str}."
        else:
            status_str += (
                "\nNo timer is active. This status is permanent until changed."
            )

        return status_str
    except Exception as e:
        return f"Error setting blocking status: {str(e)}"


@mcp.prompt()
def dns_host_add_prompt(ip_address: str, hostname: str) -> str:
    """
    Create a prompt for adding a DNS host entry.

    Args:
        ip_address (str): The IP address for the new DNS host entry.
        hostname (str): The hostname for the new DNS host entry.

    Returns:
        str: A formatted prompt string for adding a DNS host entry.
    """
    return f"""
Add a new DNS host entry with
IP address: {ip_address}
Hostname: {hostname}
"""


@mcp.prompt()
def dns_host_delete_prompt(hostname: str) -> str:
    """
    Create a prompt for deleting a DNS host entry.

    Args:
        hostname (str): The hostname of the DNS entry to be deleted.

    Returns:
        str: A formatted prompt string for deleting a DNS host entry.
    """
    return f"""
Delete the DNS host entry for hostname: {hostname}

Please find and remove this entry.
"""


@mcp.prompt()
def enable_blocking_prompt(duration_minutes: Optional[int] = None) -> str:
    """
    Create a prompt for enabling DNS blocking.

    Args:
        duration_minutes (Optional[int], optional): Duration in minutes for temporary blocking.
                                                    Defaults to None (permanent).

    Returns:
        str: A formatted prompt for enabling DNS blocking.
    """
    if duration_minutes is not None:
        return f"Please enable DNS blocking for {duration_minutes} minutes."
    else:
        return "Please enable DNS blocking permanently."


@mcp.prompt()
def disable_blocking_prompt(duration_minutes: Optional[int] = None) -> str:
    """
    Create a prompt for disabling DNS blocking.

    Args:
        duration_minutes (Optional[int], optional): Duration in minutes for temporary disabling.
                                                     Defaults to None (permanent).

    Returns:
        str: A formatted prompt for disabling DNS blocking.
    """
    if duration_minutes is not None:
        return f"Please disable DNS blocking for {duration_minutes} minutes."
    else:
        return "Please disable DNS blocking permanently."


if __name__ == "__main__":
    mcp.run()
