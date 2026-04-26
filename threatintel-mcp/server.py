from mcp.server.fastmcp import FastMCP
import random
import hashlib

mcp = FastMCP("ThreatIntelMCP")

@mcp.tool()
def check_ip_reputation(ip_address: str) -> str:
    """Check the reputation of an IP address."""
    # Mock implementation: 
    # If the IP starts with 185, we return suspicious. Otherwise benign.
    if ip_address.startswith("185."):
        return f"IP {ip_address} has 15/80 detections on VT. Known for Cobalt Strike C2."
    elif ip_address.startswith("10.") or ip_address.startswith("192.168."):
        return f"IP {ip_address} is private. No external reputation data."
    else:
        return f"IP {ip_address} has 0/80 detections. Clean."

@mcp.tool()
def check_domain_reputation(domain: str) -> str:
    """Check the reputation of a domain."""
    # Mock implementation
    if "evil" in domain or "dga" in domain or len(domain) > 20:
        return f"Domain {domain} is flagged as malicious (phishing/C2). Registered 2 days ago."
    else:
        return f"Domain {domain} is benign."

@mcp.tool()
def check_hash(file_hash: str) -> str:
    """Check the reputation of a file hash (MD5, SHA1, or SHA256)."""
    # Mock implementation:
    if "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" == file_hash.lower():
        return "Clean. Empty file."
    
    # Randomly assign a malicious tag based on the first hex character
    try:
        first_char = file_hash[0].lower()
        if first_char in "0123":
            return f"Hash {file_hash} identified as Ransomware (LockBit) with 55/70 detections."
        elif first_char in "4567":
            return f"Hash {file_hash} identified as Trojan/Dropper with 40/70 detections."
        else:
            return f"Hash {file_hash} not found in VirusTotal database."
    except Exception:
        return "Invalid hash."

if __name__ == "__main__":
    mcp.run(transport='stdio')
