#!/bin/bash

set -e

echo "📡 [1] Setting up Python virtual environment..."
VENV_DIR=".polling_venv"

if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    echo "✅ Virtual environment created at $VENV_DIR"
fi

source "$VENV_DIR/bin/activate"
pip install --quiet matplotlib pandas

# 로컬 IP 가져오기
LOCAL_IP=$(ipconfig getifaddr en0)
echo "🌐 Local IP detected: $LOCAL_IP"

echo "📦 [2] Capturing outbound packets from $LOCAL_IP..."
sudo tcpdump -tt -i any tcp and port 80 or port 443 and src "$LOCAL_IP" -c 500 -w polling.pcap

echo "📄 [3] Extracting timestamps and destination IPs..."
tshark -r polling.pcap -T fields -e frame.time_epoch -e ip.dst > packets.csv

echo "📊 [4] Resolving destination IPs to hostnames & visualizing..."

python3 <<EOF
import pandas as pd
import matplotlib.pyplot as plt
import socket

# Load packet data
df = pd.read_csv("packets.csv", sep="\t", names=["time", "dst"])
df["time"] = pd.to_numeric(df["time"], errors="coerce")
df = df.dropna()

# IP → hostname mapping
ip_to_host = {}
for ip in df["dst"].unique():
    try:
        host = socket.gethostbyaddr(ip)[0]
    except Exception:
        host = ip
    ip_to_host[ip] = host

# Replace IPs with hostnames
df["host"] = df["dst"].map(ip_to_host)

# Plotting
grouped = df.groupby("host")

plt.figure(figsize=(14, max(6, len(grouped) * 0.6)))  # 동적 높이 조정
for host, group in grouped:
    plt.scatter(group["time"], [host]*len(group), s=10)

plt.xlabel("Time (epoch)")
plt.ylabel("Destination Host")
plt.title("Polling Detection by Host (Auto Resolved)")
plt.tight_layout()
plt.savefig("polling_activity.png")
print("✅ Saved graph to polling_activity.png")
EOF

deactivate
