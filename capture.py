#!/usr/bin/env python3
"""
PCAP Capture Module for DNSSEC Benchmarking
Handles packet capture and DNS query/response pair matching.
"""

import asyncio
import os
import time
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict

import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP


@dataclass
class DNSPacket:
    """Represents a captured DNS packet with metadata."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    dns_id: int
    query_name: str
    query_type: str
    response_code: int
    flags: int
    ttl: Optional[int] = None
    has_rrsig: bool = False
    packet_type: str = "unknown"  # "query" or "response"


class PCAPCapture:
    """Handles PCAP packet capture and DNS packet analysis."""
    
    def __init__(self, interface: str = "any", target_ip: str = None, target_port: int = 53):
        self.interface = interface
        self.target_ip = target_ip
        self.target_port = target_port
        self.captured_packets = []
        self.capture_task = None
        self.stop_capture = asyncio.Event()
        
        # Setup logging
        handlers = [logging.StreamHandler()]
        try:
            handlers.append(logging.FileHandler('logs/benchmark.log'))
        except (PermissionError, FileNotFoundError):
            pass  # Skip file logging if we can't write to it
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=handlers
        )
        self.logger = logging.getLogger(__name__)
        
        # Ensure logs directory exists
        os.makedirs('logs', exist_ok=True)
    
    async def start_capture(self):
        """Start asynchronous packet capture."""
        try:
            self.logger.info(f"Starting PCAP capture on interface: {self.interface}")
            
            # Start capture in a separate thread
            loop = asyncio.get_event_loop()
            self.capture_task = loop.run_in_executor(
                None, self._capture_packets_sync
            )
            
            # Return the task instead of waiting
            return self.capture_task
            
        except Exception as e:
            self.logger.error(f"PCAP capture error: {e}")
            raise
    
    def _capture_packets_sync(self):
        """Synchronous packet capture using scapy."""
        try:
            def packet_handler(packet):
                """Handle each captured packet."""
                try:
                    dns_packet = self._parse_dns_packet(packet)
                    if dns_packet:
                        self.captured_packets.append(dns_packet)
                        self.logger.debug(f"Captured DNS packet: {dns_packet.query_name}")
                except Exception as e:
                    self.logger.warning(f"Error parsing packet: {e}")
            
            # Start sniffing with better interface handling
            try:
                scapy.sniff(
                    iface=self.interface,
                    filter=f"udp port {self.target_port}",
                    prn=packet_handler,
                    stop_filter=lambda x: self.stop_capture.is_set(),
                    timeout=1
                )
            except Exception as e:
                self.logger.warning(f"Failed to capture on {self.interface}: {e}")
                # Try without specifying interface
                try:
                    scapy.sniff(
                        filter=f"udp port {self.target_port}",
                        prn=packet_handler,
                        stop_filter=lambda x: self.stop_capture.is_set(),
                        timeout=1
                    )
                except Exception as e2:
                    self.logger.error(f"Failed to capture on any interface: {e2}")
            
        except Exception as e:
            self.logger.error(f"Scapy capture error: {e}")
    
    def _parse_dns_packet(self, packet) -> Optional[DNSPacket]:
        """Parse a captured packet and extract DNS information."""
        try:
            # Check if packet has DNS layer
            if not packet.haslayer(DNS):
                return None
            
            # Extract IP and UDP information
            ip_layer = packet[IP]
            udp_layer = packet[UDP]
            dns_layer = packet[DNS]
            
            # Determine packet type and extract information
            is_query = dns_layer.qr == 0
            is_response = dns_layer.qr == 1
            
            if not (is_query or is_response):
                return None
            
            # Extract query information
            query_name = ""
            query_type = ""
            if dns_layer.qd:  # Question section
                query_name = dns_layer.qd.qname.decode('utf-8').rstrip('.')
                query_type = dns_layer.qd.qtype
            
            # Extract response information
            response_code = dns_layer.rcode
            ttl = None
            has_rrsig = False
            
            if is_response and dns_layer.an:  # Answer section
                for rr in dns_layer.an:
                    if rr.type == 46:  # RRSIG
                        has_rrsig = True
                    if ttl is None:
                        ttl = rr.ttl
            
            # Determine if this is a query or response based on direction
            packet_type = "query" if is_query else "response"
            
            return DNSPacket(
                timestamp=time.time(),
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                src_port=udp_layer.sport,
                dst_port=udp_layer.dport,
                dns_id=dns_layer.id,
                query_name=query_name,
                query_type=query_type,
                response_code=response_code,
                flags=dns_layer.flags,
                ttl=ttl,
                has_rrsig=has_rrsig,
                packet_type=packet_type
            )
            
        except Exception as e:
            self.logger.warning(f"Error parsing DNS packet: {e}")
            return None
    
    def get_packets(self) -> List[DNSPacket]:
        """Get all captured packets."""
        return self.captured_packets.copy()
    
    def match_query_response_pairs(self) -> List[Tuple[DNSPacket, DNSPacket]]:
        """Match DNS queries with their corresponding responses."""
        queries = {}
        pairs = []
        
        # Group packets by DNS ID and port tuple
        for packet in self.captured_packets:
            key = (packet.dns_id, packet.src_port, packet.dst_port)
            
            if packet.packet_type == "query":
                queries[key] = packet
            elif packet.packet_type == "response":
                # Look for matching query
                query_key = (packet.dns_id, packet.dst_port, packet.src_port)
                if query_key in queries:
                    pairs.append((queries[query_key], packet))
                    del queries[query_key]
        
        self.logger.info(f"Matched {len(pairs)} query-response pairs")
        return pairs
    
    def stop(self):
        """Stop packet capture."""
        self.stop_capture.set()
        if self.capture_task and not self.capture_task.done():
            self.capture_task.cancel()
    
    def get_statistics(self) -> Dict:
        """Get capture statistics."""
        total_packets = len(self.captured_packets)
        queries = [p for p in self.captured_packets if p.packet_type == "query"]
        responses = [p for p in self.captured_packets if p.packet_type == "response"]
        pairs = self.match_query_response_pairs()
        
        return {
            'total_packets': total_packets,
            'queries': len(queries),
            'responses': len(responses),
            'matched_pairs': len(pairs),
            'unmatched_queries': len(queries) - len(pairs),
            'unmatched_responses': len(responses) - len(pairs)
        }
    
    def filter_packets_by_domain(self, domain_list: List[str]) -> List[DNSPacket]:
        """Filter captured packets to only include specified domains."""
        filtered = []
        for packet in self.captured_packets:
            if any(domain.lower() in packet.query_name.lower() for domain in domain_list):
                filtered.append(packet)
        return filtered
    
    def export_pcap(self, filename: str):
        """Export captured packets to PCAP file."""
        try:
            # Convert DNSPacket objects back to scapy packets for export
            scapy_packets = []
            for dns_packet in self.captured_packets:
                # This is a simplified reconstruction
                # In practice, you might want to store the original packet objects
                pass
            
            # For now, just log the export request
            self.logger.info(f"Export to {filename} requested (not implemented)")
            
        except Exception as e:
            self.logger.error(f"Error exporting PCAP: {e}")


class PacketAnalyzer:
    """Analyzes captured packets for performance metrics."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def calculate_latency(self, query: DNSPacket, response: DNSPacket) -> float:
        """Calculate latency between query and response."""
        return (response.timestamp - query.timestamp) * 1000  # Convert to milliseconds
    
    def detect_cache_hit(self, packets: List[DNSPacket]) -> Dict[str, bool]:
        """Detect cache hits based on TTL values and response times."""
        cache_status = {}
        domain_first_query = {}
        
        for packet in packets:
            if packet.packet_type == "response":
                domain = packet.query_name
                
                if domain not in domain_first_query:
                    domain_first_query[domain] = packet
                    cache_status[domain] = False  # Cache miss
                else:
                    # Compare TTL with first query
                    first_ttl = domain_first_query[domain].ttl
                    current_ttl = packet.ttl
                    
                    if first_ttl and current_ttl and current_ttl < first_ttl:
                        cache_status[domain] = True  # Cache hit
                    else:
                        cache_status[domain] = False  # Cache miss
        
        return cache_status
    
    def analyze_dnssec_signatures(self, packets: List[DNSPacket]) -> Dict:
        """Analyze DNSSEC signature presence in responses."""
        dnssec_stats = {
            'total_responses': 0,
            'signed_responses': 0,
            'unsigned_responses': 0,
            'validation_failures': 0
        }
        
        for packet in packets:
            if packet.packet_type == "response":
                dnssec_stats['total_responses'] += 1
                
                if packet.has_rrsig:
                    dnssec_stats['signed_responses'] += 1
                else:
                    dnssec_stats['unsigned_responses'] += 1
                
                # Check for DNSSEC validation failures (AD flag not set)
                if not (packet.flags & 0x20):  # AD flag not set
                    dnssec_stats['validation_failures'] += 1
        
        return dnssec_stats


# Example usage and testing
if __name__ == "__main__":
    async def test_capture():
        """Test the PCAP capture functionality."""
        capture = PCAPCapture(interface="lo", target_ip="127.0.0.1")
        
        print("Starting test capture...")
        await capture.start_capture()
        
        # Let it capture for a few seconds
        await asyncio.sleep(5)
        capture.stop()
        
        packets = capture.get_packets()
        print(f"Captured {len(packets)} packets")
        
        stats = capture.get_statistics()
        print(f"Statistics: {stats}")
    
    # Run test if executed directly
    asyncio.run(test_capture())
