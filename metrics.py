#!/usr/bin/env python3
"""
Metrics Calculation Module for DNSSEC Benchmarking
Handles latency calculation, cache efficiency analysis, and DNSSEC overhead measurement.
"""

import logging
import statistics
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict

from capture import DNSPacket


@dataclass
class BenchmarkMetrics:
    """Container for benchmark metrics and statistics."""
    total_queries: int
    successful_responses: int
    failed_queries: int
    average_latency: float
    median_latency: float
    p95_latency: float
    p99_latency: float
    min_latency: float
    max_latency: float
    cache_hit_ratio: float
    cache_hits: int
    cache_misses: int
    dnssec_overhead: float
    dnssec_enabled_queries: int
    dnssec_disabled_queries: int
    validation_failures: int
    error_rate: float


@dataclass
class QueryResult:
    """Individual query result with timing and metadata."""
    timestamp: float
    domain: str
    query_id: int
    latency_ms: float
    cache_status: str  # "HIT" or "MISS"
    dnssec_enabled: bool
    dnssec_overhead_ms: float
    response_code: int
    flags: int
    ttl: Optional[int]
    has_rrsig: bool


class MetricsCalculator:
    """Calculates and analyzes benchmark metrics from captured packets."""
    
    def __init__(self):
        self.results: List[QueryResult] = []
        self.query_response_pairs: List[Tuple[DNSPacket, DNSPacket]] = []
        self.logger = logging.getLogger(__name__)
    
    def process_packets(self, packets: List[DNSPacket]):
        """Process captured packets and calculate metrics."""
        self.logger.info(f"Processing {len(packets)} captured packets")
        
        # Match query-response pairs
        self.query_response_pairs = self._match_pairs(packets)
        
        # Calculate individual query results
        self.results = self._calculate_query_results(self.query_response_pairs)
        
        self.logger.info(f"Processed {len(self.results)} query results")
    
    def _match_pairs(self, packets: List[DNSPacket]) -> List[Tuple[DNSPacket, DNSPacket]]:
        """Match DNS queries with their corresponding responses."""
        queries = {}
        pairs = []
        
        # Sort packets by timestamp to process in order
        sorted_packets = sorted(packets, key=lambda p: p.timestamp)
        
        for packet in sorted_packets:
            if packet.packet_type == "query":
                # Store query with key based on DNS ID and port combination
                key = (packet.dns_id, packet.src_port, packet.dst_port)
                queries[key] = packet
                
            elif packet.packet_type == "response":
                # Look for matching query (reverse port combination)
                query_key = (packet.dns_id, packet.dst_port, packet.src_port)
                
                if query_key in queries:
                    query = queries[query_key]
                    pairs.append((query, packet))
                    del queries[query_key]
        
        self.logger.info(f"Matched {len(pairs)} query-response pairs")
        return pairs
    
    def _calculate_query_results(self, pairs: List[Tuple[DNSPacket, DNSPacket]]) -> List[QueryResult]:
        """Calculate individual query results from matched pairs."""
        results = []
        domain_first_query = {}  # Track first query per domain for cache analysis
        
        for query, response in pairs:
            # Calculate latency
            latency = (response.timestamp - query.timestamp) * 1000  # Convert to ms
            
            # Determine cache status
            domain = query.query_name
            cache_status = "MISS"
            
            if domain in domain_first_query:
                # Check if this is a repeated query (potential cache hit)
                first_query_time = domain_first_query[domain]
                time_diff = query.timestamp - first_query_time
                
                # If query is within TTL window, consider it a cache hit
                if response.ttl and time_diff < response.ttl:
                    cache_status = "HIT"
            else:
                domain_first_query[domain] = query.timestamp
            
            # Determine DNSSEC status
            dnssec_enabled = bool(query.flags & 0x20)  # AD flag
            dnssec_overhead = 0.0  # Will be calculated separately
            
            result = QueryResult(
                timestamp=query.timestamp,
                domain=domain,
                query_id=query.dns_id,
                latency_ms=latency,
                cache_status=cache_status,
                dnssec_enabled=dnssec_enabled,
                dnssec_overhead_ms=dnssec_overhead,
                response_code=response.response_code,
                flags=response.flags,
                ttl=response.ttl,
                has_rrsig=response.has_rrsig
            )
            
            results.append(result)
        
        # Calculate DNSSEC overhead
        self._calculate_dnssec_overhead(results)
        
        return results
    
    def _calculate_dnssec_overhead(self, results: List[QueryResult]):
        """Calculate DNSSEC validation overhead by comparing latencies."""
        dnssec_latencies = []
        no_dnssec_latencies = []
        
        for result in results:
            if result.dnssec_enabled:
                dnssec_latencies.append(result.latency_ms)
            else:
                no_dnssec_latencies.append(result.latency_ms)
        
        if dnssec_latencies and no_dnssec_latencies:
            avg_dnssec = statistics.mean(dnssec_latencies)
            avg_no_dnssec = statistics.mean(no_dnssec_latencies)
            overhead = avg_dnssec - avg_no_dnssec
            
            # Update overhead for all results
            for result in results:
                if result.dnssec_enabled:
                    result.dnssec_overhead_ms = overhead
                else:
                    result.dnssec_overhead_ms = 0.0
        else:
            # If no comparison possible, set overhead to 0
            for result in results:
                result.dnssec_overhead_ms = 0.0
    
    def get_results(self) -> List[Dict]:
        """Get all query results as dictionaries."""
        return [asdict(result) for result in self.results]
    
    def get_summary(self) -> Dict:
        """Get benchmark summary statistics."""
        if not self.results:
            return {
                'total_queries': 0,
                'successful_responses': 0,
                'failed_queries': 0,
                'average_latency': 0.0,
                'median_latency': 0.0,
                'p95_latency': 0.0,
                'p99_latency': 0.0,
                'min_latency': 0.0,
                'max_latency': 0.0,
                'cache_hit_ratio': 0.0,
                'cache_hits': 0,
                'cache_misses': 0,
                'dnssec_overhead': 0.0,
                'dnssec_enabled_queries': 0,
                'dnssec_disabled_queries': 0,
                'error_rate': 100.0
            }
        
        latencies = [r.latency_ms for r in self.results]
        successful = [r for r in self.results if r.response_code == 0]
        failed = [r for r in self.results if r.response_code != 0]
        cache_hits = [r for r in self.results if r.cache_status == "HIT"]
        cache_misses = [r for r in self.results if r.cache_status == "MISS"]
        dnssec_enabled = [r for r in self.results if r.dnssec_enabled]
        dnssec_disabled = [r for r in self.results if not r.dnssec_enabled]
        
        summary = {
            'total_queries': len(self.results),
            'successful_responses': len(successful),
            'failed_queries': len(failed),
            'average_latency': statistics.mean(latencies) if latencies else 0.0,
            'median_latency': statistics.median(latencies) if latencies else 0.0,
            'p95_latency': self._percentile(latencies, 95) if latencies else 0.0,
            'p99_latency': self._percentile(latencies, 99) if latencies else 0.0,
            'min_latency': min(latencies) if latencies else 0.0,
            'max_latency': max(latencies) if latencies else 0.0,
            'cache_hit_ratio': len(cache_hits) / len(self.results) * 100 if self.results else 0.0,
            'cache_hits': len(cache_hits),
            'cache_misses': len(cache_misses),
            'dnssec_overhead': self._calculate_dnssec_overhead_value(),
            'dnssec_enabled_queries': len(dnssec_enabled),
            'dnssec_disabled_queries': len(dnssec_disabled),
            'error_rate': len(failed) / len(self.results) * 100 if self.results else 0.0
        }
        
        return summary
    
    def _calculate_dnssec_overhead_value(self) -> float:
        """Calculate the actual DNSSEC overhead value."""
        dnssec_latencies = [r.latency_ms for r in self.results if r.dnssec_enabled]
        no_dnssec_latencies = [r.latency_ms for r in self.results if not r.dnssec_enabled]
        
        if dnssec_latencies and no_dnssec_latencies:
            return statistics.mean(dnssec_latencies) - statistics.mean(no_dnssec_latencies)
        
        return 0.0
    
    def _percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile of a dataset."""
        if not data:
            return 0.0
        
        sorted_data = sorted(data)
        index = int((percentile / 100) * len(sorted_data))
        if index >= len(sorted_data):
            index = len(sorted_data) - 1
        
        return sorted_data[index]
    
    def calculate_cache_efficiency(self) -> Dict:
        """Calculate detailed cache efficiency metrics."""
        if not self.results:
            return {'hits': 0, 'misses': 0, 'efficiency': 0.0}
        
        hits = sum(1 for r in self.results if r.cache_status == "HIT")
        misses = sum(1 for r in self.results if r.cache_status == "MISS")
        total = hits + misses
        
        return {
            'hits': hits,
            'misses': misses,
            'efficiency': (hits / total * 100) if total > 0 else 0.0
        }
    
    def get_latency_distribution(self) -> Dict:
        """Get latency distribution statistics."""
        if not self.results:
            return {}
        
        latencies = [r.latency_ms for r in self.results]
        
        return {
            'mean': statistics.mean(latencies),
            'median': statistics.median(latencies),
            'std_dev': statistics.stdev(latencies) if len(latencies) > 1 else 0.0,
            'variance': statistics.variance(latencies) if len(latencies) > 1 else 0.0,
            'range': max(latencies) - min(latencies),
            'q1': self._percentile(latencies, 25),
            'q3': self._percentile(latencies, 75),
            'iqr': self._percentile(latencies, 75) - self._percentile(latencies, 25)
        }
    
    def get_dnssec_analysis(self) -> Dict:
        """Get detailed DNSSEC analysis."""
        if not self.results:
            return {}
        
        dnssec_enabled = [r for r in self.results if r.dnssec_enabled]
        dnssec_disabled = [r for r in self.results if not r.dnssec_enabled]
        
        analysis = {
            'dnssec_enabled_count': len(dnssec_enabled),
            'dnssec_disabled_count': len(dnssec_disabled),
            'signed_responses': sum(1 for r in self.results if r.has_rrsig),
            'validation_failures': sum(1 for r in dnssec_enabled if not (r.flags & 0x20))
        }
        
        if dnssec_enabled and dnssec_disabled:
            dnssec_latencies = [r.latency_ms for r in dnssec_enabled]
            no_dnssec_latencies = [r.latency_ms for r in dnssec_disabled]
            
            analysis.update({
                'dnssec_avg_latency': statistics.mean(dnssec_latencies),
                'no_dnssec_avg_latency': statistics.mean(no_dnssec_latencies),
                'overhead_ms': statistics.mean(dnssec_latencies) - statistics.mean(no_dnssec_latencies),
                'overhead_percentage': ((statistics.mean(dnssec_latencies) - statistics.mean(no_dnssec_latencies)) / 
                                      statistics.mean(no_dnssec_latencies) * 100) if no_dnssec_latencies else 0.0
            })
        
        return analysis
    
    def export_detailed_metrics(self, filename: str):
        """Export detailed metrics to a file."""
        import json
        
        detailed_metrics = {
            'summary': self.get_summary(),
            'cache_efficiency': self.calculate_cache_efficiency(),
            'latency_distribution': self.get_latency_distribution(),
            'dnssec_analysis': self.get_dnssec_analysis(),
            'individual_results': self.get_results()
        }
        
        with open(filename, 'w') as f:
            json.dump(detailed_metrics, f, indent=2, default=str)
        
        self.logger.info(f"Detailed metrics exported to {filename}")


# Example usage and testing
if __name__ == "__main__":
    # Test the metrics calculator
    calculator = MetricsCalculator()
    
    # Create some dummy data for testing
    from capture import DNSPacket
    
    test_packets = [
        DNSPacket(
            timestamp=1000.0,
            src_ip="127.0.0.1",
            dst_ip="8.8.8.8",
            src_port=12345,
            dst_port=53,
            dns_id=1,
            query_name="example.com",
            query_type="A",
            response_code=0,
            flags=0x0100,  # Query
            packet_type="query"
        ),
        DNSPacket(
            timestamp=1000.05,
            src_ip="8.8.8.8",
            dst_ip="127.0.0.1",
            src_port=53,
            dst_port=12345,
            dns_id=1,
            query_name="example.com",
            query_type="A",
            response_code=0,
            flags=0x8180,  # Response
            ttl=300,
            has_rrsig=False,
            packet_type="response"
        )
    ]
    
    calculator.process_packets(test_packets)
    summary = calculator.get_summary()
    print("Test Summary:", summary)
