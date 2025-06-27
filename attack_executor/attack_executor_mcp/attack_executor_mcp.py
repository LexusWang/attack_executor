#!/usr/bin/env python3

# This script connects the MCP AI agent to the Attack Executor API Server

import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional, List
import requests

from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_ATTACK_EXECUTOR_SERVER = "http://192.168.50.80:5001"
DEFAULT_REQUEST_TIMEOUT = 600  # 10 minutes default timeout for API requests

class AttackExecutorClient:
    """Client for communicating with the Attack Executor API Server"""
    
    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        """
        Initialize the Attack Executor Client
        
        Args:
            server_url: URL of the Attack Executor API Server
            timeout: Request timeout in seconds
        """
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        logger.info(f"Initialized Attack Executor Client connecting to {server_url}")
        
    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform a GET request with optional query parameters.
        
        Args:
            endpoint: API endpoint path (without leading slash)
            params: Optional query parameters
            
        Returns:
            Response data as dictionary
        """
        if params is None:
            params = {}

        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"GET {url} with params: {params}")
            response = requests.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform a POST request with JSON data.
        
        Args:
            endpoint: API endpoint path (without leading slash)
            json_data: JSON data to send
            
        Returns:
            Response data as dictionary
        """
        url = f"{self.server_url}/{endpoint}"
        
        try:
            logger.debug(f"POST {url} with data: {json_data}")
            response = requests.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def check_health(self) -> Dict[str, Any]:
        """
        Check the health of the Attack Executor API Server
        
        Returns:
            Health status information
        """
        return self.safe_get("health")

def setup_mcp_server(attack_executor_client: AttackExecutorClient) -> FastMCP:
    """
    Set up the MCP server with all Attack Executor tool functions
    
    Args:
        attack_executor_client: Initialized AttackExecutorClient
        
    Returns:
        Configured FastMCP instance
    """
    mcp = FastMCP("attack-executor-mcp")
    
    @mcp.tool()
    def nmap_scan(target: str, options: str = "-sS -sV -O -A") -> Dict[str, Any]:
        """
        Execute an Nmap scan using the Attack Executor NmapExecutor.
        
        Args:
            target: The IP address or hostname to scan
            options: Nmap scan options (e.g., "-sS -sV -O -A") or "xml" for XML parsing
            
        Returns:
            Scan results from NmapExecutor
        """
        data = {
            "target": target,
            "options": options
        }
        return attack_executor_client.safe_post("api/scan/nmap", data)

    @mcp.tool()
    def gobuster_scan(
        target: str, 
        mode: str = "dir", 
        wordlist: str = "/usr/share/wordlists/dirb/common.txt", 
        extensions: Optional[List[str]] = None, 
        threads: int = 10,
        endchar: str = "/"
    ) -> Dict[str, Any]:
        """
        Execute Gobuster scan using the Attack Executor GobusterExecutor.
        
        Args:
            target: The target URL or domain
            mode: Scan mode (dir, subdomain, fuzz)
            wordlist: Path to wordlist file
            extensions: List of file extensions for dir mode
            threads: Number of threads to use
            endchar: End character for fuzz mode
            
        Returns:
            Scan results from GobusterExecutor
        """
        data = {
            "target": target,
            "mode": mode,
            "wordlist": wordlist,
            "extensions": extensions,
            "threads": threads,
            "endchar": endchar
        }
        return attack_executor_client.safe_post("api/scan/gobuster", data)

    @mcp.tool()
    def shell_execute(command: str) -> Dict[str, Any]:
        """
        Execute shell commands using the Attack Executor ShellExecutor.
        
        Args:
            command: Shell command to execute
            
        Returns:
            Command execution results with stdout, stderr, and return code
        """
        data = {
            "command": command
        }
        return attack_executor_client.safe_post("api/shell/execute", data)

    return mcp

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Attack Executor MCP Client")
    parser.add_argument("--server", type=str, default=DEFAULT_ATTACK_EXECUTOR_SERVER, 
                      help=f"Attack Executor API server URL (default: {DEFAULT_ATTACK_EXECUTOR_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()

def main():
    """Main entry point for the MCP server."""
    args = parse_args()
    
    # Configure logging based on debug flag
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Initialize the Attack Executor client
    attack_executor_client = AttackExecutorClient(args.server, args.timeout)
    
    # Check server health and log the result
    health = attack_executor_client.check_health()
    if "error" in health:
        logger.warning(f"Unable to connect to Attack Executor API server at {args.server}: {health['error']}")
        logger.warning("MCP server will start, but tool execution may fail")
    else:
        logger.info(f"Successfully connected to Attack Executor API server at {args.server}")
        logger.info(f"Server health status: {health['status']}")
        if health.get("tools_available"):
            available_tools = [tool for tool, available in health["tools_available"].items() if available]
            logger.info(f"Available tools: {', '.join(available_tools)}")
    
    # Set up and run the MCP server
    mcp = setup_mcp_server(attack_executor_client)
    logger.info("Starting Attack Executor MCP server")
    mcp.run()

if __name__ == "__main__":
    main() 