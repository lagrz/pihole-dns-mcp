# DNS Manager MCP Server

This Model Context Protocol (MCP) server provides tools to manage DNS host entries and blocking status through the Pi-hole API.

## Features

- Retrieve a list of current DNS host entries
- Add new DNS host entries
- Delete existing DNS host entries
- Get DNS blocking status
- Enable/disable DNS blocking with optional timers
- Session management with automatic renewal
- Secure password handling through environment variables

## Requirements

- Python 3.13 or higher
- A Pi-hole instance with API access

## Installation

Clone this repository or download the source code:

```bash
git clone https://github.com/lagrz/pihole-dns-mcp.git
cd pihole-dns-mcp
```

## Configuration

The server requires two environment variables to connect to your Pi-hole instance:

```bash
DNS_API_BASE_URL="http://10.0.11.41"
DNS_API_PASSWORD="your_api_password"
```

### Additional Configuration Options

You can configure logging behavior with these optional environment variables:

- `DNS_API_LOG_LEVEL`: Set log level (DEBUG, INFO, WARNING, ERROR) - default is INFO
- `DNS_API_LOG_TO_FILE`: Set to "true" to log to `~/.mcp-pihole-api.log` instead of stdout

Example:

```env
DNS_API_LOG_LEVEL=DEBUG
DNS_API_LOG_TO_FILE=true
```

## Using with Claude for Desktop

To integrate with Claude for Desktop:

1. Find your Claude for Desktop configuration:

   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
   - Linux: `~/.config/Claude/claude_desktop_config.json`

2. Add the MCP server configuration:

```json
{
  "mcpServers": {
    "dns-manager": {
      "command": "uv",
      "args": ["run", "/absolute/path/to/dns_manager_server.py"],
      "env": {
        "DNS_API_BASE_URL": "http://10.0.11.41",
        "DNS_API_PASSWORD": "your_api_password"
      }
    }
  }
}
```

3. Restart Claude for Desktop

## Available Tools

The server provides the following tools:

### DNS Host Management

- `get_dns_hosts`: Retrieve all DNS host entries from Pi-hole
- `add_dns_host`: Add a new DNS host entry (IP address and hostname)
- `delete_dns_host`: Delete an existing DNS host entry

### DNS Blocking Management

- `get_blocking_status`: Get current DNS blocking status and any active timers
- `set_blocking_status`: Enable or disable DNS blocking with optional timer

### DNS Host Backup and Restore

- `backup_dns_hosts`: Creates a backup of all current DNS host entries to a timestamped JSON file in the `~/.mcp-pihole-backups/` directory.
- `list_dns_backups`: Lists all available DNS host backup files found in `~/.mcp-pihole-backups/`.
- `restore_dns_hosts (filename: str)`: Restores DNS host entries from the specified backup file. The filename should be one of those listed by `list_dns_backups`. Backups are stored in JSON format.

## Example Usage in Claude

Once connected to Claude, you can use the following prompts:

### DNS Host Management

- "Show me all DNS host entries"
- "Add a DNS host entry for IP 192.168.1.100 with hostname server.local"
- "Remove the DNS host entry for 192.168.1.100 server.local"

### DNS Blocking

- "What's the current DNS blocking status?"
- "Enable DNS blocking"
- "Disable DNS blocking for 30 minutes"
- "Enable DNS blocking for 1 hour"

### DNS Host Backup and Restore

- "Create a backup of my DNS hosts."
- "Show me all DNS backups."
- "Restore DNS hosts from backup 'backup-YYYYMMDD-HHMMSS.json'."

## Testing

You can test the server using the MCP inspector:

```bash
npx @modelcontextprotocol/inspector uv run dns_manager_server.py
```

## Troubleshooting

### Configuration Issues

1. Verify your environment variables are set correctly
2. Check that your Pi-hole is accessible at the configured URL
3. Ensure your Pi-hole password is correct

### Connection Issues

1. Check if Pi-hole is running and accessible
2. Verify the API base URL is correct (include http:// and port if needed)
3. Check Claude for Desktop logs for detailed error messages

### Authentication Issues

1. Verify the Pi-hole password is correct
2. Check that API access is enabled in Pi-hole settings
3. Review the log file (`~/.mcp-pihole-api.log`) for authentication errors

## Security Notes

- The API password is stored in environment variables to avoid hardcoding credentials
- Session IDs are cached but automatically renewed when expired
- No sensitive information is logged to standard output
- Session cache file (`~/.mcp-pihole-api.json`) is created with secure permissions (0600)

## File Locations

The server creates the following files in your home directory:

- `~/.mcp-pihole-api.json`: Session cache (secure permissions)
- `~/.mcp-pihole-api.log`: Log file (when `DNS_API_LOG_TO_FILE=true`)
- `~/.mcp-pihole-backups/`: Directory for DNS host backup files (JSON format).

## Development

The project uses:

- [uv](https://github.com/astral-sh/uv) for dependency management
- [FastMCP](https://github.com/jlowin/fastmcp) for MCP server implementation
- [httpx](https://github.com/encode/httpx) for HTTP requests
- [pydantic](https://pydantic.dev/) for data validation
