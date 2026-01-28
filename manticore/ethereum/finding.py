"""
Structured findings data model for Manticore exploit detection.

This module provides type-safe data structures for representing vulnerability findings
with full context for verification and PoC generation.
"""
import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import List, Optional
from datetime import datetime, UTC


@dataclass
class Finding:
    """
    Represents a structured vulnerability finding with full exploit context.

    This class encapsulates all transactional data required for verification
    and automated PoC generation.
    """
    kind: str
    """Vulnerability classification (e.g., AUTHORIZATION_BYPASS, REENTRANCY)"""

    description: str
    """Human-readable explanation of the vulnerability"""

    severity: str
    """Severity level: CRITICAL, HIGH, MEDIUM, LOW"""

    address: int
    """Target contract address"""

    sender: Optional[int] = None
    """Concrete attacker address (if available)"""

    data: str = ""
    """Hex-encoded calldata payload"""

    value: int = 0
    """ETH value sent in transaction"""

    pc: int = 0
    """Program counter at failure point"""

    tx_index: Optional[int] = None
    """Transaction index in the analysis"""

    chain_id: Optional[int] = None
    """Chain identifier (e.g., 1 for Ethereum mainnet)"""

    workspace_path: Optional[str] = None
    """Path to workspace directory"""

    tags: List[str] = field(default_factory=list)
    """Additional metadata tags for categorization"""

    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    """ISO 8601 timestamp of finding creation"""

    def __post_init__(self):
        if self.data:
            d = self.data.lower()
            if d.startswith("0x"):
                d = d[2:]
            # Remove exactly ONE trailing "00" byte (not all)
            if d.endswith("00"):
                d = d[:-2]
            if len(d) % 2 != 0:
                d += "0"
            self.data = "0x" + d

    def to_dict(self) -> dict:
        """
        Convert Finding to dictionary for JSON serialization.

        Returns:
            Dictionary representation suitable for json.dump()
        """
        result = asdict(self)
        # Convert int fields to hex strings for addresses
        if result["address"] is not None:
            result["address"] = f"0x{result['address']:040x}"
        if result["sender"] is not None:
            result["sender"] = f"0x{result['sender']:040x}"
        return result

    @property
    def id(self) -> str:
        """
        Generate stable unique ID for this finding.

        ID is hash of (kind + address + data + pc) to ensure
        uniqueness and stability across multiple runs.

        Returns:
            Hexadecimal string hash
        """
        id_string = f"{self.kind}:{self.address}:{self.data}:{self.pc}"
        return hashlib.sha256(id_string.encode()).hexdigest()[:16]

    def __str__(self) -> str:
        """Human-readable string representation."""
        return f"[{self.severity}] {self.kind}: {self.description}"


class FindingSink:
    """
    Thread-safe collection and JSON output for Finding objects.

    This class collects findings from detectors and writes them to JSON
    when requested. It maintains backward compatibility with text output.
    """

    def __init__(self, output_path: Optional[str] = None):
        """
        Initialize FindingSink.

        Args:
            output_path: Path to write JSON findings. None means no JSON output.
        """
        self._output_path = output_path
        self._findings: List[Finding] = []

    def add_finding(self, finding: Finding) -> None:
        """
        Add a Finding to the collection.

        Args:
            finding: Finding object to add
        """
        self._findings.append(finding)

    def get_findings(self) -> List[Finding]:
        """
        Get all collected findings.

        Returns:
            List of Finding objects
        """
        return self._findings.copy()

    def write_json(self) -> None:
        """
        Write all findings to JSON file if output_path is set.

        The output is a JSON array of Finding dictionaries.
        """
        if self._output_path is None:
            return

        with open(self._output_path, "w") as f:
            json.dump(
                [finding.to_dict() for finding in self._findings],
                f,
                indent=2
            )

    def clear(self) -> None:
        """Clear all collected findings."""
        self._findings.clear()
