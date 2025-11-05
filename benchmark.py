#!/usr/bin/env python3
"""
DNSSEC Resolver Performance Benchmarking Tool
Main entry point with CLI interface and YANG configuration management.
"""

import argparse
import asyncio
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional

import dns.resolver
import dns.query
import dns.message
import dns.flags
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.style as style

from capture import PCAPCapture
from metrics import MetricsCalculator
from yang_config import YANGConfigManager


class DNSSECBenchmark:
    """Main benchmarking class that orchestrates the entire process."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.capture = PCAPCapture(
            interface=config.get('capture_interface', 'wlan1'),
            target_ip=config['target_ip'],
            target_port=config['port']
        )
        self.metrics = MetricsCalculator()
        self.results = []
        self.domain_first_query = {}  # Track first query time per domain
        self.domain_ttl = {}  # Track TTL per domain
        
    async def run_benchmark(self):
        """Execute the complete benchmarking process."""
        print(f"🚀 Starting DNSSEC benchmark against {self.config['target_ip']}:{self.config['port']}")
        
        # Start PCAP capture
        capture_task = await self.capture.start_capture()
        await asyncio.sleep(1)  # Let capture initialize
        
        try:
            # Execute DNS queries
            await self._execute_queries()
            
            # Stop capture and process results
            self.capture.stop()
            captured_packets = self.capture.get_packets()
            
            # Calculate metrics from captured packets if available
            if captured_packets:
                self.metrics.process_packets(captured_packets)
                # Combine with direct query results
                self.results.extend(self.metrics.get_results())
            else:
                # Use direct query results if no PCAP capture
                print("📊 Using direct query results (no PCAP capture)")
                # Calculate metrics from direct results
                if self.results:
                    self.metrics.results = []
                    for result in self.results:
                        from metrics import QueryResult
                        query_result = QueryResult(
                            timestamp=result['timestamp'],
                            domain=result['domain'],
                            query_id=result['query_id'],
                            latency_ms=result['latency_ms'],
                            cache_status=result['cache_status'],
                            dnssec_enabled=result['dnssec_enabled'],
                            dnssec_overhead_ms=result['dnssec_overhead_ms'],
                            response_code=result['response_code'],
                            flags=result['flags'],
                            ttl=result['ttl'],
                            has_rrsig=result['has_rrsig']
                        )
                        self.metrics.results.append(query_result)
            
            # Generate outputs
            self._generate_outputs()
            self._generate_plots()
            
            print("✅ Benchmark completed successfully!")
            self._print_summary()
            
        except Exception as e:
            print(f"❌ Benchmark failed: {e}")
            raise
        finally:
            self.capture.stop()
    
    async def _execute_queries(self):
        """Send DNS queries according to configuration."""
        domains = self.config['domains']
        query_count = self.config['query_count']
        rate_limit = self.config['rate_limit']
        
        # Split queries for DNSSEC overhead comparison
        half_queries = query_count // 2
        queries_sent = 0
        delay = 1.0 / rate_limit if rate_limit > 0 else 0
        
        print(f"📡 Sending {query_count} queries to {len(domains)} domains...")
        print(f"🔍 DNSSEC Overhead Analysis: First {half_queries} queries (DNSSEC OFF), Next {half_queries} queries (DNSSEC ON)")
        
        for i in range(query_count):
            domain = domains[i % len(domains)]
            
            # Determine DNSSEC setting based on query position
            dnssec_enabled = i >= half_queries  # First half: OFF, Second half: ON
            
            try:
                # Create DNS query
                query = dns.message.make_query(domain, 'A')
                if dnssec_enabled:
                    query.flags |= dns.flags.CD  # Checking Disabled for testing
                    query.flags |= dns.flags.AD  # Authenticated Data
                
                # Send query using asyncio with dnspython
                start_time = time.time()
                
                # Use asyncio to run the synchronous DNS query
                loop = asyncio.get_event_loop()
                response = await loop.run_in_executor(
                    None,
                    lambda: dns.query.udp(
                        query, 
                        self.config['target_ip'], 
                        port=self.config['port'],
                        timeout=self.config.get('timeout', 5)
                    )
                )
                end_time = time.time()
                
                # Store result
                latency = (end_time - start_time) * 1000
                
                # Determine cache status based on domain query history
                cache_status = self._determine_cache_status(domain, start_time)
                
                # Check for DNSSEC signatures in response
                has_rrsig = self._check_dnssec_signatures(response)
                
                # Get TTL from response
                ttl = self._extract_ttl(response)
                
                # Store TTL for cache hit detection
                self.domain_ttl[domain] = ttl
                
                self.results.append({
                    'timestamp': start_time,
                    'domain': domain,
                    'query_id': query.id,
                    'latency_ms': latency,
                    'cache_status': cache_status,
                    'dnssec_enabled': dnssec_enabled,
                    'dnssec_overhead_ms': 0.0,  # Will be calculated later
                    'response_code': response.rcode(),
                    'flags': response.flags,
                    'ttl': ttl,
                    'has_rrsig': has_rrsig
                })
                
                queries_sent += 1
                dnssec_status = "ON" if dnssec_enabled else "OFF"
                print(f"✅ Query {queries_sent}: {domain} - {latency:.2f}ms (DNSSEC {dnssec_status})")
                
                # Rate limiting
                if delay > 0:
                    await asyncio.sleep(delay)
                    
            except Exception as e:
                print(f"⚠️  Query failed for {domain}: {e}")
                continue
    
    def _generate_outputs(self):
        """Generate CSV and JSON output files."""
        try:
            os.makedirs('results', exist_ok=True)
            
            # Generate CSV
            df = pd.DataFrame(self.results)
            csv_path = 'results/results.csv'
            df.to_csv(csv_path, index=False)
            print(f"📄 Results saved to {csv_path}")
            
            # Generate JSON
            json_path = 'results/results.json'
            with open(json_path, 'w') as f:
                json.dump({
                    'config': self.config,
                    'summary': self.metrics.get_summary(),
                    'results': self.results
                }, f, indent=2, default=str)
            print(f"📄 Results saved to {json_path}")
            
        except PermissionError:
            print("⚠️  Permission denied - cannot save results files")
            print("📊 Results summary:")
            summary = self.metrics.get_summary()
            print(f"   Total queries: {summary['total_queries']}")
            print(f"   Average latency: {summary['average_latency']:.2f} ms")
            print(f"   Cache hit ratio: {summary['cache_hit_ratio']:.1f}%")
    
    def _generate_plots(self):
        """Generate visualization plots."""
        os.makedirs('results/plots', exist_ok=True)
        
        if not self.results:
            print("⚠️  No results to plot - skipping visualization")
            return
            
        df = pd.DataFrame(self.results)
        try:
            style.use('seaborn-v0_8')
        except:
            style.use('default')
        
        # Latency distribution histogram
        plt.figure(figsize=(10, 6))
        plt.hist(df['latency_ms'], bins=30, alpha=0.7, color='skyblue', edgecolor='black')
        plt.xlabel('Latency (ms)')
        plt.ylabel('Frequency')
        plt.title('DNS Query Latency Distribution')
        plt.grid(True, alpha=0.3)
        plt.savefig('results/plots/latency_distribution.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # Cache hit ratio (simulated based on repeated queries)
        cache_stats = self.metrics.calculate_cache_efficiency()
        plt.figure(figsize=(8, 6))
        labels = ['Cache Hit', 'Cache Miss']
        sizes = [cache_stats['hits'], cache_stats['misses']]
        colors = ['lightgreen', 'lightcoral']
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        plt.title('Cache Hit Ratio')
        plt.savefig('results/plots/cache_ratio.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # DNSSEC overhead comparison
        dnssec_data = df.groupby('dnssec_enabled')['latency_ms'].mean()
        plt.figure(figsize=(8, 6))
        bars = plt.bar(['DNSSEC Disabled', 'DNSSEC Enabled'], dnssec_data.values, 
                      color=['lightblue', 'orange'])
        plt.ylabel('Average Latency (ms)')
        plt.title('DNSSEC Validation Overhead')
        plt.grid(True, alpha=0.3)
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.2f}ms', ha='center', va='bottom')
        
        plt.savefig('results/plots/dnssec_overhead.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        print("📊 Plots generated in results/plots/")
    
    def _print_summary(self):
        """Print benchmark summary to console."""
        summary = self.metrics.get_summary()
        print("\n" + "="*50)
        print("📈 BENCHMARK SUMMARY")
        print("="*50)
        print(f"Total Queries: {summary['total_queries']}")
        print(f"Successful Responses: {summary['successful_responses']}")
        print(f"Average Latency: {summary['average_latency']:.2f} ms")
        print(f"Cache Hit Ratio: {summary['cache_hit_ratio']:.1f}%")
        print(f"DNSSEC Overhead: {summary['dnssec_overhead']:.2f} ms")
        print("="*50)
    
    def _determine_cache_status(self, domain: str, timestamp: float) -> str:
        """Determine if this query is a cache hit or miss."""
        if domain not in self.domain_first_query:
            # First query for this domain - cache miss
            self.domain_first_query[domain] = timestamp
            return "MISS"
        else:
            # Check if query is within TTL window
            first_query_time = self.domain_first_query[domain]
            time_diff = timestamp - first_query_time
            
            # If we have TTL info for this domain and within TTL window, it's a cache hit
            if domain in self.domain_ttl and time_diff < self.domain_ttl[domain]:
                return "HIT"
            else:
                # Update first query time for this new query
                self.domain_first_query[domain] = timestamp
                return "MISS"
    
    def _check_dnssec_signatures(self, response) -> bool:
        """Check if response contains DNSSEC signatures (RRSIG records)."""
        try:
            # Check if response has answer section with RRSIG records
            if hasattr(response, 'answer') and response.answer:
                for rrset in response.answer:
                    if hasattr(rrset, 'rdtype') and rrset.rdtype == 46:  # RRSIG type
                        return True
            return False
        except Exception:
            return False
    
    def _extract_ttl(self, response) -> int:
        """Extract TTL from DNS response."""
        try:
            if hasattr(response, 'answer') and response.answer:
                for rrset in response.answer:
                    if hasattr(rrset, 'ttl'):
                        return rrset.ttl
            return 300  # Default TTL
        except Exception:
            return 300


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='DNSSEC Resolver Performance Benchmarking Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--ip',
                       help='Target DNS resolver IP address')
    parser.add_argument('--port', type=int, default=53,
                       help='Target DNS resolver port (default: 53)')
    parser.add_argument('--queries', type=int,
                       help='Number of queries to send')
    parser.add_argument('--rate', type=float, default=100.0,
                       help='Query rate limit per second (default: 100)')
    parser.add_argument('--dnssec', action='store_true',
                       help='[DEPRECATED] DNSSEC overhead analysis is now automatic (first half OFF, second half ON)')
    parser.add_argument('--domains', type=str,
                       help='Path to file containing domain names (one per line)')
    parser.add_argument('--interface', type=str, default='wlan1',
                       help='Network interface for PCAP capture (default: wlan1)')
    parser.add_argument('--timeout', type=int, default=5000,
                       help='Query timeout in milliseconds (default: 5000)')
    parser.add_argument('--config', type=str,
                       help='Path to YANG JSON configuration file')
    
    return parser.parse_args()


def load_domains_from_file(filepath: str) -> List[str]:
    """Load domain names from a text file."""
    try:
        with open(filepath, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
        return domains
    except FileNotFoundError:
        print(f"❌ Domain file not found: {filepath}")
        sys.exit(1)


def interactive_config():
    """Interactive configuration mode."""
    print("🔧 DNSSEC Benchmark Configuration")
    print("="*40)
    
    config = {}
    
    # Get resolver details
    config['target_ip'] = input("Enter DNS resolver IP: ").strip()
    config['port'] = int(input("Enter DNS resolver port (default 53): ") or "53")
    
    # Get domain list
    domain_file = input("Enter path to domain list file: ").strip()
    config['domains'] = load_domains_from_file(domain_file)
    
    # Get benchmark parameters with validation
    min_queries = len(config['domains']) * 2
    print(f"📊 Minimum queries required: {min_queries} (2x number of domains for DNSSEC overhead analysis)")
    
    while True:
        try:
            query_count = int(input(f"Enter number of queries (minimum {min_queries}): ").strip())
            if query_count >= min_queries:
                config['query_count'] = query_count
                break
            else:
                print(f"❌ Please enter at least {min_queries} queries for proper DNSSEC overhead analysis")
        except ValueError:
            print("❌ Please enter a valid number")
    
    config['rate_limit'] = float(input("Enter query rate (queries/sec, default 100): ") or "100")
    config['capture_interface'] = input("Enter capture interface (default 'wlan1'): ").strip() or 'wlan1'
    config['timeout'] = int(input("Enter timeout in ms (default 5000): ") or "5000")
    
    print("🔍 DNSSEC Analysis: First half of queries will be DNSSEC OFF, second half will be DNSSEC ON")
    
    return config


async def main():
    """Main entry point."""
    args = parse_arguments()
    
    # Check for root privileges for PCAP capture
    if os.geteuid() != 0:
        print("⚠️  Warning: Running without root privileges. PCAP capture may not work.")
        print("   Consider running with sudo for full functionality.")
    
    try:
        # Load configuration
        if args.config:
            yang_manager = YANGConfigManager()
            config = yang_manager.load_config(args.config)
        else:
            # Use command line arguments or interactive mode
            if all([args.ip, args.queries]):
                config = {
                    'target_ip': args.ip,
                    'port': args.port,
                    'query_count': args.queries,
                    'rate_limit': args.rate,
                    'domains': load_domains_from_file(args.domains) if args.domains else ['example.com', 'google.com'],
                    'capture_interface': args.interface,
                    'timeout': args.timeout / 1000.0  # Convert to seconds
                }
            else:
                config = interactive_config()
        
        # Validate configuration
        if not config['domains']:
            print("❌ No domains specified for testing")
            sys.exit(1)
        
        # Validate minimum queries for DNSSEC overhead analysis
        min_queries = len(config['domains']) * 2
        if config['query_count'] < min_queries:
            print(f"❌ Minimum queries required: {min_queries} (2x number of domains)")
            print(f"   Current query count: {config['query_count']}")
            print(f"   Domains: {len(config['domains'])}")
            sys.exit(1)
        
        # Create and run benchmark
        benchmark = DNSSECBenchmark(config)
        await benchmark.run_benchmark()
        
    except KeyboardInterrupt:
        print("\n🛑 Benchmark interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
