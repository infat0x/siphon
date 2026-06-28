# Distributed Scanning

For massive targets (e.g., scanning all of `.gov`), a single machine may not have enough bandwidth.

## Sharding
You can split your target list into chunks and run Siphon across multiple VPS instances (like DigitalOcean or AWS EC2).

## Aggregation
After the distributed scans finish, use `jq` to merge the JSON reports:
```bash
jq -s 'flatten' vps1.json vps2.json vps3.json > final_report.json
```
