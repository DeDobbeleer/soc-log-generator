#!/usr/bin/env python3
"""
AWS VPC Flow Logs Generator

Generates realistic AWS VPC Flow Logs in multiple formats:
- Default format (v2)
- Custom format with all fields
- Parquet format metadata

Simulates network traffic between EC2 instances, load balancers,
NAT gateways, and external endpoints with realistic patterns.
"""

import json
import random
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

# Handle imports for both module and script execution
try:
    from ...core import LogEvent, EventSeverity, AssetInventory
    from ...generators.base import BaseGenerator
except ImportError:
    from core import LogEvent, EventSeverity, AssetInventory
    from generators.base import BaseGenerator


class AWSVPCFlowGenerator(BaseGenerator):
    """
    Generator for AWS VPC Flow Logs.
    
    Simulates network traffic flows with realistic patterns including
    internal traffic, external connections, and potential anomalies.
    """
    
    # AWS Regions
    REGIONS = [
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "eu-west-1", "eu-west-2", "eu-central-1",
        "ap-southeast-1", "ap-northeast-1", "ap-south-1"
    ]
    
    # Account IDs
    ACCOUNT_IDS = ["123456789012", "234567901234", "345690123456"]
    
    # VPC and subnet CIDRs
    VPC_CIDRS = [
        "10.0.0.0/16", "10.1.0.0/16", "172.16.0.0/16",
        "192.168.0.0/16", "10.100.0.0/16"
    ]
    
    # Common ports
    PORTS = {
        "ssh": (22, 0.15),
        "http": (80, 0.10),
        "https": (443, 0.35),
        "dns": (53, 0.08),
        "smtp": (25, 0.03),
        "rdp": (3389, 0.05),
        "postgresql": (5432, 0.08),
        "mysql": (3306, 0.06),
        "redis": (6379, 0.03),
        "elasticsearch": (9200, 0.02),
        "kibana": (5601, 0.02),
        "grafana": (3000, 0.02),
        "jenkins": (8080, 0.01),
    }
    
    # Protocol numbers
    PROTOCOLS = {
        6: ("TCP", 0.85),
        17: ("UDP", 0.14),
        1: ("ICMP", 0.01),
    }
    
    # Traffic types
    TRAFFIC_TYPES = [
        ("internal", 0.6),      # Internal VPC traffic
        ("egress", 0.25),       # Outbound to internet
        ("ingress", 0.10),      # Inbound from internet
        ("nat", 0.03),          # Through NAT gateway
        ("lb", 0.02),           # Through load balancer
    ]
    
    # Actions
    ACTIONS = [
        ("ACCEPT", 0.95),
        ("REJECT", 0.05),
    ]
    
    # Log statuses
    LOG_STATUS = [
        ("OK", 0.97),
        ("NODATA", 0.02),
        ("SKIPDATA", 0.01),
    ]
    
    # Instance IDs
    INSTANCE_PREFIXES = ["i-", "eni-", "sg-"]
    
    # Known external IPs (simulated)
    EXTERNAL_IPS = [
        "8.8.8.8",      # Google DNS
        "1.1.1.1",      # Cloudflare
        "13.107.42.14", # Microsoft
        "142.250.185.78", # Google
        "104.16.249.249", # Cloudflare
        "151.101.1.140",  # Reddit
        "140.82.121.4",   # GitHub
        "52.94.236.248",  # AWS
    ]
    
    def __init__(self, config: Dict[str, Any], inventory: Optional[AssetInventory] = None):
        """Initialize VPC Flow generator."""
        super().__init__(config)
        self.eps = config.get('eps', 100)
        self.inventory = inventory
        self.vpc_id = f"vpc-{uuid.uuid4().hex[:8]}"
        self.subnet_id = f"subnet-{uuid.uuid4().hex[:8]}"
        
    def _generate_eni(self) -> str:
        """Generate Elastic Network Interface ID."""
        return f"eni-{uuid.uuid4().hex[:8]}"
    
    def _generate_instance_id(self) -> str:
        """Generate EC2 instance ID."""
        return f"i-{uuid.uuid4().hex[:16]}"
    
    def _generate_internal_ip(self) -> str:
        """Generate internal VPC IP."""
        cidr = random.choice(self.VPC_CIDRS)
        base = cidr.split("/")[0]
        octets = base.split(".")
        # Generate IP in subnet
        return f"{octets[0]}.{octets[1]}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    def _generate_external_ip(self) -> str:
        """Generate external/public IP."""
        if random.random() < 0.3:
            return random.choice(self.EXTERNAL_IPS)
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    def _get_port(self) -> Tuple[int, str]:
        """Get a random port and service name."""
        services = list(self.PORTS.keys())
        ports, weights = zip(*[(p, w) for p, (p_num, w) in zip([self.PORTS[s][0] for s in services], [self.PORTS[s][1] for s in services])])
        # Fix: properly extract ports and weights
        port_list = [self.PORTS[s][0] for s in services]
        weight_list = [self.PORTS[s][1] for s in services]
        port = random.choices(port_list, weights=weight_list)[0]
        service = [s for s, (p, _) in self.PORTS.items() if p == port][0]
        return port, service
    
    def _get_protocol(self) -> Tuple[int, str]:
        """Get random protocol."""
        protos = list(self.PROTOCOLS.keys())
        names, weights = zip(*[self.PROTOCOLS[p] for p in protos])
        proto = random.choices(protos, weights=weights)[0]
        return proto, self.PROTOCOLS[proto][0]
    
    def _generate_flow_record(self) -> Dict[str, Any]:
        """Generate a VPC flow log record."""
        traffic_type = random.choices(
            [t for t, _ in self.TRAFFIC_TYPES],
            [w for _, w in self.TRAFFIC_TYPES]
        )[0]
        
        # Determine source and destination based on traffic type
        if traffic_type == "internal":
            src_ip = self._generate_internal_ip()
            dst_ip = self._generate_internal_ip()
        elif traffic_type == "egress":
            src_ip = self._generate_internal_ip()
            dst_ip = self._generate_external_ip()
        elif traffic_type == "ingress":
            src_ip = self._generate_external_ip()
            dst_ip = self._generate_internal_ip()
        else:  # nat or lb
            src_ip = self._generate_internal_ip()
            dst_ip = self._generate_external_ip()
        
        # Get ports and protocol
        dst_port, service = self._get_port()
        src_port = random.randint(1024, 65535)
        protocol_num, protocol_name = self._get_protocol()
        
        # For UDP DNS, use port 53
        if protocol_num == 17 and random.random() < 0.5:
            dst_port = 53
            service = "dns"
        
        # Determine action
        action = random.choices(
            [a for a, _ in self.ACTIONS],
            [w for _, w in self.ACTIONS]
        )[0]
        
        # Reject suspicious ports more often
        if dst_port in [22, 3389] and random.random() < 0.3:
            action = "REJECT"
        
        # Generate packet and byte counts
        if action == "REJECT":
            packets = random.randint(1, 10)
            bytes_count = packets * random.randint(40, 1500)
        else:
            packets = random.randint(10, 10000)
            bytes_count = packets * random.randint(100, 1500)
        
        # Timestamps
        now = datetime.now(timezone.utc)
        start_time = int(now.timestamp())
        duration = random.randint(1, 300)
        end_time = start_time + duration
        
        # ENI
        eni = self._generate_eni()
        
        # Account ID
        account_id = random.choice(self.ACCOUNT_IDS)
        
        # Build flow record (v2 format)
        record = {
            "version": "2",
            "account_id": account_id,
            "interface_id": eni,
            "srcaddr": src_ip,
            "dstaddr": dst_ip,
            "srcport": src_port,
            "dstport": dst_port,
            "protocol": protocol_num,
            "packets": packets,
            "bytes": bytes_count,
            "start": start_time,
            "end": end_time,
            "action": action,
            "log_status": random.choices(
                [s for s, _ in self.LOG_STATUS],
                [w for _, w in self.LOG_STATUS]
            )[0],
            "vpc_id": self.vpc_id,
            "subnet_id": self.subnet_id,
            "instance_id": self._generate_instance_id(),
            "tcp_flags": self._generate_tcp_flags(protocol_num, action),
            "type": "IPv4",
            "pkt_srcaddr": src_ip,
            "pkt_dstaddr": dst_ip,
            "region": random.choice(self.REGIONS),
            "az_id": f"{random.choice(self.REGIONS)}-{random.choice(['1a', '1b', '1c'])}",
            "sublocation_type": "-",
            "sublocation_id": "-",
            "pkt_src_aws_service": "-",
            "pkt_dst_aws_service": "-",
            "flow_direction": "ingress" if traffic_type == "ingress" else "egress",
            "traffic_path": self._get_traffic_path(traffic_type),
        }
        
        return record, service, action
    
    def _generate_tcp_flags(self, protocol: int, action: str) -> str:
        """Generate TCP flags."""
        if protocol != 6:  # Not TCP
            return "0"
        
        if action == "REJECT":
            return random.choice(["2", "4", "8"])  # SYN, RST, PSH
        
        # Established connection
        flags = ["16", "17", "18", "24", "25"]  # ACK, ACK+FIN, SYN+ACK, ACK+PSH, ACK+PSH+FIN
        return random.choice(flags)
    
    def _get_traffic_path(self, traffic_type: str) -> int:
        """Get traffic path identifier."""
        paths = {
            "internal": 1,      # Through VPC
            "egress": random.choice([2, 3, 4]),  # Through internet gateway, virtual private gateway, etc.
            "ingress": 5,       # From internet
            "nat": 6,           # Through NAT gateway
            "lb": 7,            # Through load balancer
        }
        return paths.get(traffic_type, 1)
    
    def _format_default(self, record: Dict[str, Any]) -> str:
        """Format as default VPC Flow Log (v2)."""
        return " ".join([
            record["version"],
            record["account_id"],
            record["interface_id"],
            record["srcaddr"],
            record["dstaddr"],
            str(record["srcport"]),
            str(record["dstport"]),
            str(record["protocol"]),
            str(record["packets"]),
            str(record["bytes"]),
            str(record["start"]),
            str(record["end"]),
            record["action"],
            record["log_status"],
        ])
    
    def _format_custom(self, record: Dict[str, Any]) -> str:
        """Format with all available fields."""
        fields = [
            record["version"],
            record["vpc_id"],
            record["subnet_id"],
            record["instance_id"],
            record["interface_id"],
            record["account_id"],
            record["type"],
            record["srcaddr"],
            record["dstaddr"],
            record["pkt_srcaddr"],
            record["pkt_dstaddr"],
            str(record["srcport"]),
            str(record["dstport"]),
            str(record["protocol"]),
            str(record["packets"]),
            str(record["bytes"]),
            str(record["start"]),
            str(record["end"]),
            record["action"],
            record["log_status"],
            record["tcp_flags"],
            record["az_id"],
            record["sublocation_type"],
            record["sublocation_id"],
            record["pkt_src_aws_service"],
            record["pkt_dst_aws_service"],
            record["flow_direction"],
            str(record["traffic_path"]),
        ]
        return " ".join(fields)
    
    def generate_event(self) -> LogEvent:
        """Generate a VPC Flow Log event."""
        record, service, action = self._generate_flow_record()
        
        # Choose format
        format_type = random.choice(["default", "custom"])
        if format_type == "default":
            raw_log = self._format_default(record)
        else:
            raw_log = self._format_custom(record)
        
        # Create message
        direction = "inbound" if record["flow_direction"] == "ingress" else "outbound"
        message = f"VPC Flow: {direction} {record['protocol']} traffic {record['srcaddr']}:{record['srcport']} -> {record['dstaddr']}:{record['dstport']} ({service}) - {action}"
        
        # Determine severity
        if action == "REJECT":
            severity = EventSeverity.MEDIUM
        elif record["dstport"] in [22, 3389]:
            severity = EventSeverity.LOW  # Administrative ports
        else:
            severity = EventSeverity.LOW
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="aws_vpcflow",
            source_ip=record["srcaddr"],
            source_host=f"vpc-{record['region']}.amazonaws.com",
            message=message,
            raw_log=raw_log,
            fields={
                "version": record["version"],
                "account_id": record["account_id"],
                "vpc_id": record["vpc_id"],
                "subnet_id": record["subnet_id"],
                "instance_id": record["instance_id"],
                "interface_id": record["interface_id"],
                "srcaddr": record["srcaddr"],
                "dstaddr": record["dstaddr"],
                "srcport": record["srcport"],
                "dstport": record["dstport"],
                "protocol": record["protocol"],
                "protocol_name": self.PROTOCOLS.get(record["protocol"], ("UNKNOWN", 0))[0],
                "packets": record["packets"],
                "bytes": record["bytes"],
                "start": record["start"],
                "end": record["end"],
                "action": record["action"],
                "log_status": record["log_status"],
                "tcp_flags": record["tcp_flags"],
                "flow_direction": record["flow_direction"],
                "traffic_path": record["traffic_path"],
                "region": record["region"],
                "az_id": record["az_id"],
                "service": service,
            },
            tags=["aws", "vpcflow", service, record["action"].lower(), record["flow_direction"]],
            severity=severity
        )


# Example usage
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    print("AWS VPC Flow Generator Demo")
    print("=" * 60)
    
    inventory = AssetInventory()
    config = {"eps": 10}
    
    generator = AWSVPCFlowGenerator(config, inventory)
    
    for i in range(5):
        event = generator.generate_event()
        print(f"\nFlow {i+1}:")
        print(f"  {event.message}")
        print(f"  Raw: {event.raw_log[:100]}...")
        print(f"  Severity: {event.severity.name}")
