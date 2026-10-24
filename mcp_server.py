#!/usr/bin/env python3
"""Launch the String Decryptor MCP server over stdio.

Print a ready-to-paste client configuration (absolute paths included):

    python mcp_server.py --print-config
    python mcp_server.py --print-config --config-style opencode
    python mcp_server.py --print-config --config-style vscode

Generic MCP client configuration:

    {
      "mcpServers": {
        "stringdecrypt": {
          "command": "C:/Python314/python.exe",
          "args": ["C:/path/to/ida_stringdecrypt/mcp_server.py"]
        }
      }
    }
"""

from stringdecrypt.mcp_server import main

if __name__ == "__main__":
    raise SystemExit(main())
