# DNSSEC Resolver Performance Benchmarking Tool

A comprehensive Python-based tool for benchmarking DNSSEC resolver performance using YANG-based configuration and PCAP capture, designed to run on Kali Linux.

## 🚀 Features

- **YANG Model Configuration**: Based on draft-ietf-bmwg-network-tester-cfg
- **PCAP Capture**: Real-time packet capture and analysis
- **DNSSEC Testing**: Comprehensive DNSSEC validation overhead measurement
- **Cache Efficiency Analysis**: Query cache hit/miss ratio calculation
- **Multiple Output Formats**: CSV, JSON, and visualization plots
- **CLI Interface**: Command-line and interactive configuration modes
- **Async Performance**: High-performance async DNS query engine

## 📋 Requirements

- Python 3.8+
- Kali Linux (recommended)
- Root privileges (for PCAP capture)
- Network access to target DNS resolvers

## 🛠️ Installation

1. **Clone or download the project files**

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Install system dependencies** (on Kali Linux):
   ```bash
   sudo apt update
   sudo apt install python3-pip python3-dev libpcap-dev
   sudo apt install pyang  # For YANG model validation
   ```

4. **Set up directory structure**:
   ```bash
   sudo mkdir -p /etc/dnssec-benchmark/config/
   sudo chown $USER:$USER /etc/dnssec-benchmark/config/
   ```

## 📖 Usage

### Command Line Interface

```bash
# Basic usage with command line arguments
sudo python3 benchmark.py --ip 8.8.8.8 --queries 1000 --domains sample_domains.txt

# Advanced usage with custom parameters
sudo python3 benchmark.py \
    --ip 1.1.1.1 \
    --port 53 \
    --queries 500 \
    --rate 50 \
    --dnssec true \
    --domains sample_domains.txt \
    --interface eth0 \
    --timeout 3000

# Using YANG configuration file
sudo python3 benchmark.py --config benchmark_config.json
```

### Interactive Mode

```bash
# Run without arguments for interactive configuration
sudo python3 benchmark.py
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--ip` | Target DNS resolver IP address | Required |
| `--port` | DNS resolver port | 53 |
| `--queries` | Number of queries to send | Required |
| `--rate` | Query rate (queries/second) | 100 |
| `--dnssec` | Enable DNSSEC validation | true |
| `--domains` | Path to domain list file | Required |
| `--interface` | Network interface for capture | any |
| `--timeout` | Query timeout (ms) | 5000 |
| `--config` | YANG JSON configuration file | - |

## 📁 Configuration

### YANG Model

The tool uses a YANG model (`dnssec-benchmark.yang`) based on the IETF benchmarking methodology. Key configuration elements:

```yang
container benchmark-session {
  leaf target-ip { ... }
  leaf port { ... }
  leaf dnssec-enabled { ... }
  leaf query-count { ... }
  leaf rate-limit { ... }
  list domains { ... }
}
```

### Sample Configuration

Create a `benchmark_config.json` file:

```json
{
  "target_ip": "8.8.8.8",
  "port": 53,
  "dnssec_enabled": true,
  "query_count": 1000,
  "rate_limit": 100.0,
  "timeout": 5000,
  "capture_interface": "any",
  "domains": [
    "example.com",
    "google.com",
    "cloudflare.com"
  ]
}
```

### Domain List Format

Create a text file with one domain per line:

```
example.com
google.com
cloudflare.com
github.com
```

## 📊 Output

### CSV Results (`results/results.csv`)

| Column | Description |
|--------|-------------|
| timestamp | Query timestamp |
| domain | Domain name queried |
| query_id | DNS query ID |
| latency_ms | Response latency in milliseconds |
| cache_status | HIT or MISS |
| dnssec_enabled | Whether DNSSEC was enabled |
| dnssec_overhead_ms | DNSSEC validation overhead |

### JSON Results (`results/results.json`)

```json
{
  "config": { ... },
  "summary": {
    "total_queries": 1000,
    "successful_responses": 950,
    "average_latency": 45.2,
    "cache_hit_ratio": 75.5,
    "dnssec_overhead": 12.3
  },
  "results": [ ... ]
}
```

### Visualization Plots (`results/plots/`)

- `latency_distribution.png`: Histogram of query latencies
- `cache_ratio.png`: Pie chart of cache hit/miss ratio
- `dnssec_overhead.png`: Bar chart comparing DNSSEC vs non-DNSSEC latencies

## 🔧 Architecture

### Core Components

1. **benchmark.py**: Main entry point with CLI interface
2. **capture.py**: PCAP packet capture and DNS analysis
3. **metrics.py**: Performance metrics calculation
4. **yang_config.py**: YANG model validation and configuration management

### Data Flow

```
CLI Input → YANG Config → DNS Queries → PCAP Capture → Metrics Calculation → Output Generation
```

## 📈 Metrics

### Latency Analysis
- Mean, median, 95th, 99th percentiles
- Standard deviation and variance
- Min/max latencies

### Cache Efficiency
- Cache hit ratio calculation
- TTL-based cache detection
- Repeated query analysis

### DNSSEC Overhead
- Comparison of signed vs unsigned queries
- Validation failure detection
- RRSIG presence analysis

## 🐛 Troubleshooting

### Common Issues

1. **Permission Denied for PCAP Capture**
   ```bash
   sudo python3 benchmark.py [options]
   ```

2. **No Packets Captured**
   - Check network interface name
   - Verify target IP is reachable
   - Ensure firewall allows DNS traffic

3. **YANG Validation Errors**
   ```bash
   sudo apt install pyang
   pyang dnssec-benchmark.yang
   ```

4. **Import Errors**
   ```bash
   pip install -r requirements.txt
   ```

### Logs

Check `logs/benchmark.log` for detailed error information and debugging output.

## 🔒 Security Considerations

- Requires root privileges for PCAP capture
- Uses raw sockets for packet capture
- Validates all input configurations
- Logs all operations for audit trails

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📚 References

- [IETF Benchmarking Methodology Working Group](https://datatracker.ietf.org/wg/bmwg/)
- [draft-ietf-bmwg-network-tester-cfg](https://tools.ietf.org/html/draft-ietf-bmwg-network-tester-cfg)
- [DNSSEC RFC 4033-4035](https://tools.ietf.org/html/rfc4033)

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section
2. Review the logs in `logs/benchmark.log`
3. Create an issue with detailed error information

---

**Note**: This tool is designed for network performance testing and benchmarking. Ensure you have proper authorization before testing against external DNS resolvers.
