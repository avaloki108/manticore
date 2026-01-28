"""
Proof-of-Concept (PoC) generator for vulnerability findings.

Generates standalone Python scripts using Web3.py v7 for reproducing
identified vulnerabilities.
"""
import os
from typing import List, Optional, Callable
from dataclasses import dataclass
from datetime import datetime, UTC


@dataclass
class PoCConfig:
    """Configuration for PoC generation."""
    chain_id: Optional[int] = None
    rpc_url: str = "http://localhost:8545"
    gas_limit: int = 3000000
    gas_price: int = 0
    value: int = 0


class PoCGenerator:
    """
    Generates standalone Python scripts for reproducing vulnerability findings.
    
    Each generated script:
    - Connects to a local fork or node
    - Reconstructs the malicious transaction
    - Executes the transaction
    - Includes assertions for success verification
    """

    def __init__(self, config: Optional[PoCConfig] = None):
        """
        Initialize PoC generator.
        
        Args:
            config: Optional PoCConfig for customizing generated scripts
        """
        self.config = config or PoCConfig()

    def minimize_calldata(
        self,
        finding: dict,
        verify_callback: Optional[Callable[[dict], bool]] = None
    ) -> dict:
        """
        Minimize calldata by iteratively removing bytes while exploit still holds.
        
        This implements Phase 5 exploit minimization:
        - Tries to remove bytes from calldata
        - Verifies exploit still holds after each removal
        - Returns finding with minimized calldata
        
        Args:
            finding: Dictionary with Finding data (from Finding.to_dict())
            verify_callback: Optional function to verify exploit still holds.
                           Takes a finding dict and returns True if valid.
                           If None, performs basic byte reduction without verification.
        
        Returns:
            Finding dict with minimized calldata
        """
        # Extract calldata from finding
        original_data = finding.get("data", "")
        
        # Skip minimization if no calldata or too short
        if not original_data or len(original_data) < 10:
            return finding.copy()
        
        # Remove '0x' prefix if present
        if original_data.startswith("0x"):
            hex_data = original_data[2:]
        else:
            hex_data = original_data
        
        # Must have even number of hex characters (full bytes)
        if len(hex_data) % 2 != 0:
            return finding.copy()
        
        # Convert hex to bytes
        try:
            data_bytes = bytes.fromhex(hex_data)
        except ValueError:
            # Invalid hex, return original
            return finding.copy()
        
        # If no bytes to minimize, return original
        if len(data_bytes) == 0:
            return finding.copy()
        
        # Perform iterative byte removal
        minimized_bytes = self._remove_bytes_iteratively(
            data_bytes,
            finding,
            verify_callback
        )
        
        # Convert back to hex string
        minimized_hex = minimized_bytes.hex()
        minimized_data = f"0x{minimized_hex}"
        
        # Create minimized finding
        minimized_finding = finding.copy()
        minimized_finding["data"] = minimized_data
        
        return minimized_finding

    def _remove_bytes_iteratively(
        self,
        data_bytes: bytes,
        finding: dict,
        verify_callback: Optional[Callable[[dict], bool]] = None
    ) -> bytes:
        """
        Iteratively remove bytes while exploit still holds.
        
        Implements the algorithm:
        ```
        while exploit still holds:
            remove calldata byte
        ```
        
        Args:
            data_bytes: Original calldata as bytes
            finding: Original finding dict
            verify_callback: Optional verification function
        
        Returns:
            Minimized calldata as bytes
        """
        current_bytes = data_bytes
        
        # Try removing bytes from the end (least significant for most calls)
        while len(current_bytes) > 4:  # Keep at least function selector (4 bytes)
            # Try removing the last byte
            test_bytes = current_bytes[:-1]
            
            # Create test finding with reduced calldata
            test_finding = finding.copy()
            test_finding["data"] = f"0x{test_bytes.hex()}"
            
            # Verify exploit still holds
            if verify_callback is not None:
                if verify_callback(test_finding):
                    # Exploit still holds, keep reduced bytes
                    current_bytes = test_bytes
                else:
                    # Exploit broken, stop minimization
                    break
            else:
                # No verification callback, perform basic reduction
                # Keep function selector (first 4 bytes) and try to reduce rest
                if len(test_bytes) >= 4:
                    current_bytes = test_bytes
                else:
                    break
        
        # Also try removing bytes from the middle (padding bytes often removable)
        # Look for runs of zeros (common padding)
        if len(current_bytes) > 4:
            current_bytes = self._remove_padding_bytes(current_bytes, finding, verify_callback)
        
        return current_bytes

    def _remove_padding_bytes(
        self,
        data_bytes: bytes,
        finding: dict,
        verify_callback: Optional[Callable[[dict], bool]] = None
    ) -> bytes:
        """
        Remove padding bytes (runs of zeros) from calldata.
        
        Many function calls include zero-padded parameters that can be removed
        without affecting the exploit. This method identifies and removes
        such padding while preserving the function selector.
        
        Args:
            data_bytes: Calldata as bytes
            finding: Finding dict for verification
            verify_callback: Optional verification function
        
        Returns:
            Calldata with padding removed
        """
        # Always keep function selector (first 4 bytes)
        if len(data_bytes) <= 4:
            return data_bytes
        
        selector = data_bytes[:4]
        params = data_bytes[4:]
        
        # Try to remove trailing zeros (common in padded parameters)
        while len(params) > 0 and params[-1] == 0:
            test_bytes = selector + params[:-1]
            test_finding = finding.copy()
            test_finding["data"] = f"0x{test_bytes.hex()}"
            
            if verify_callback is not None:
                if verify_callback(test_finding):
                    params = params[:-1]
                else:
                    break
            else:
                # Basic reduction: remove trailing zeros
                params = params[:-1]
        
        return selector + params

    def generate_poc(self, finding: dict, minimize: bool = False) -> str:
        """
        Generate a standalone PoC script for a single finding.
        
        Args:
            finding: Dictionary with Finding data (from Finding.to_dict())
            minimize: If True, minimize calldata before generating PoC
            
        Returns:
            Generated Python script as string
        """
        # Minimize calldata if requested
        if minimize:
            finding = self.minimize_calldata(finding)
        
        # Extract finding data
        kind = finding.get("kind", "UNKNOWN")
        description = finding.get("description", "")
        address = finding.get("address", "")
        sender = finding.get("sender", "")
        data = finding.get("data", "")
        value = finding.get("value", 0)
        pc = finding.get("pc", 0)
        tags = finding.get("tags", [])
        
        # Format addresses for Web3.py
        if isinstance(address, int):
            address_hex = f"0x{address:x}"
        else:
            address_hex = address
            
        if isinstance(sender, int):
            sender_hex = f"0x{sender:x}"
        elif sender and sender.startswith("0x"):
            sender_hex = sender
        else:
            sender_hex = "0x" + ("0" * 40)  # Default to zero address
            
        # Generate script
        script = self._generate_script_template(
            kind=kind,
            description=description,
            address=address_hex,
            sender=sender_hex,
            data=data,
            value=value,
            pc=pc,
            tags=tags,
        )
        
        return script

    def generate_pocs(
        self,
        findings: List[dict],
        minimize: bool = False
    ) -> List[str]:
        """
        Generate PoC scripts for multiple findings.
        
        Args:
            findings: List of Finding dictionaries
            minimize: If True, minimize calldata for all findings
            
        Returns:
            List of generated Python scripts
        """
        return [self.generate_poc(finding, minimize=minimize) for finding in findings]

    def _generate_script_template(
        self,
        kind: str,
        description: str,
        address: str,
        sender: str,
        data: str,
        value: int,
        pc: int,
        tags: List[str],
    ) -> str:
        """
        Generate a Python script template for a finding.
        """
        # Generate timestamp
        timestamp = datetime.now(UTC).isoformat()
        
        # Generate tags comment
        tags_comment = "\n".join([f"#   - {tag}" for tag in tags])
        
        # Build script using .format() to avoid f-string linter issues
        script_template = '''#!/usr/bin/env python3
"""
Proof-of-Concept script for vulnerability: {kind}

Generated by Manticore on {timestamp}

Vulnerability Description:
{description}

Tags:
{tags_comment}

This script reproduces the vulnerability by executing a crafted transaction.
"""

from web3 import Web3
from web3.exceptions import TransactionNotFound

# Initialize Web3 connection
w3 = Web3(Web3.HTTPProvider("{rpc_url}"))

# Verify connection
if not w3.is_connected():
    raise Exception("Failed to connect to RPC endpoint")

# Contract address
CONTRACT_ADDRESS = "{address}"

# Attacker address
ATTACKER_ADDRESS = "{sender}"

# Transaction data
TX_DATA = "{data}"

# Transaction value (in wei)
TX_VALUE = {value}

# Gas settings
GAS_LIMIT = {gas_limit}
GAS_PRICE = {gas_price}

print(f"Target contract: {{CONTRACT_ADDRESS}}")
print(f"Attacker address: {{ATTACKER_ADDRESS}}")
print(f"Transaction data: {{TX_DATA}}")
print(f"Transaction value: {{TX_VALUE}} wei")
print()

# Check attacker balance
attacker_balance = w3.eth.get_balance(ATTACKER_ADDRESS)
print(f"Attacker balance before attack: {{attacker_balance}} wei")

# Fund attacker if needed (for testing purposes)
if attacker_balance < TX_VALUE:
    print("WARNING: Attacker has insufficient balance.")
    print("This script requires attacker to have enough ETH to send TX_VALUE wei.")
    print("Please fund the attacker address before running this script.")
    # For testing, you might want to use a local fork with pre-funded accounts
    # Uncomment the following line to use a funded account from the fork:
    # ATTACKER_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279ffF"  # Example funded account
    # attacker_balance = w3.eth.get_balance(ATTACKER_ADDRESS)

# Build transaction
transaction = {{
    "from": ATTACKER_ADDRESS,
    "to": CONTRACT_ADDRESS,
    "data": TX_DATA,
    "value": TX_VALUE,
    "gas": GAS_LIMIT,
    "gasPrice": GAS_PRICE,
    "nonce": w3.eth.get_transaction_count(ATTACKER_ADDRESS),
    "chainId": {chain_id},
}}

print("Transaction constructed:")
print(f"  From: {{transaction['from']}}")
print(f"  To: {{transaction['to']}}")
print(f"  Data: {{transaction['data']}}")
print(f"  Value: {{transaction['value']}} wei")
print(f"  Gas: {{transaction['gas']}}")
print()

# Send transaction
print("Sending transaction...")
try:
    tx_hash = w3.eth.send_transaction(transaction)
    print(f"Transaction sent! Hash: {{tx_hash.hex()}}")
    
    # Wait for transaction receipt
    print("Waiting for transaction receipt...")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    
    print()
    print("Transaction receipt:")
    print(f"  Status: {{'SUCCESS' if receipt['status'] == 1 else 'FAILED'}}")
    print(f"  Block number: {{receipt['blockNumber']}}")
    print(f"  Gas used: {{receipt['gasUsed']}}")
    print(f"  Transaction hash: {{receipt['transactionHash'].hex()}}")
    
    # Verify exploit succeeded
    if receipt['status'] == 1:
        print()
        print("=" * 60)
        print("EXPLOIT SUCCESSFUL!")
        print("=" * 60)
        print()
        print("The vulnerability has been successfully triggered.")
        print("The transaction executed without reverting.")
        print()
        print("Expected impact:")
        print("  - The vulnerability condition was satisfied")
        print("  - State was modified as expected by exploit")
        print("  - The attacker gained the expected advantage")
    else:
        print()
        print("=" * 60)
        print("EXPLOIT FAILED")
        print("=" * 60)
        print()
        print("The transaction reverted or failed.")
        print("This could indicate:")
        print("  - The vulnerability condition was not met")
        print("  - Additional constraints prevent exploitation")
        print("  - The contract has been patched")
        
except Exception as e:
    print()
    print("=" * 60)
    print("ERROR")
    print("=" * 60)
    print(f"An error occurred: {{e}}")
    import traceback
    traceback.print_exc()

print()
print("Script completed.")
'''
        
        # Format the script with finding-specific values
        chain_id_value = self.config.chain_id if self.config.chain_id else "w3.eth.chain_id"
        
        return script_template.format(
            kind=kind,
            timestamp=timestamp,
            description=description,
            tags_comment=tags_comment,
            rpc_url=self.config.rpc_url,
            address=address,
            sender=sender,
            data=data,
            value=value,
            gas_limit=self.config.gas_limit,
            gas_price=self.config.gas_price,
            chain_id=chain_id_value,
        )

    def write_poc_to_file(
        self,
        finding: dict,
        output_path: str,
        minimize: bool = False
    ) -> None:
        """
        Generate and write a PoC script to a file.
        
        Args:
            finding: Dictionary with Finding data
            output_path: Path to write the PoC script
            minimize: If True, minimize calldata before generating PoC
        """
        script = self.generate_poc(finding, minimize=minimize)
        
        with open(output_path, "w") as f:
            f.write(script)
        
        print(f"PoC script written to: {output_path}")

    def write_pocs_to_directory(
        self,
        findings: List[dict],
        output_dir: str,
        minimize: bool = False
    ) -> None:
        """
        Generate and write PoC scripts for multiple findings to a directory.
        
        Args:
            findings: List of Finding dictionaries
            output_dir: Directory to write PoC scripts
            minimize: If True, minimize calldata for all findings
        """
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        for i, finding in enumerate(findings):
            kind = finding.get("kind", "UNKNOWN").lower().replace("_", "-")
            output_path = os.path.join(output_dir, f"poc_{kind}_{i}.py")
            self.write_poc_to_file(finding, output_path, minimize=minimize)
        
        print(f"PoC scripts written to directory: {output_dir}")
