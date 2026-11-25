# Network_Intrusion_detection
network intrusion detetcion system is a System dvelopment project courses lab project

## Dataset
Download CICIDS2017 (MachineLearningCVE CSVs) from https://www.unb.ca/cic/datasets/ids-2017.html and place them in a MachineLearningCVE/ folder.

## Setup
Create `nids-platform/.env` (it is gitignored) with a secret of your own:

    JWT_SECRET=your-random-string-here

Generate one with: `python -c "import secrets; print(secrets.token_hex(32))"`

Then run `docker compose up --build` inside `nids-platform/`.

## Suricata Alert Forwarder (Raspberry Pi)

`MachineLearningCVE/suricata_forwarder.py` tails `/var/log/suricata/eve.json` on the Raspberry Pi and forwards Suricata alerts to `POST /api/alerts/ingest` using your existing `SENSOR_KEY`.

### 1. Copy files to the Pi
```bash
scp MachineLearningCVE/suricata_forwarder.py MachineLearningCVE/suricata-forwarder.service pi@<PI_IP>:/tmp/
```

### 2. Create `/etc/nids-sensor.env` on the Pi (root-only permissions)
```bash
sudo tee /etc/nids-sensor.env > /dev/null <<'EOF'
PLATFORM_URL=http://<PLATFORM_HOST_IP>:8088
SENSOR_KEY=<YOUR_SENSOR_KEY_FROM_SETTINGS>
EVE_PATH=/var/log/suricata/eve.json
EOF
sudo chmod 600 /etc/nids-sensor.env
```

Optional flags:
- `FORWARD_DECODER_EVENTS=1` — forward `SURICATA ` decoder/protocol events (ignored by default)
- `FORWARD_TEST_RULE=1` — forward SID `1000001` test alerts (ignored by default)

### 3. Install and enable the systemd service
```bash
sudo mkdir -p /opt/nids-sensor
sudo cp /tmp/suricata_forwarder.py /opt/nids-sensor/suricata_forwarder.py
sudo chmod 755 /opt/nids-sensor/suricata_forwarder.py
sudo cp /tmp/suricata-forwarder.service /etc/systemd/system/suricata-forwarder.service
sudo systemctl daemon-reload
sudo systemctl enable --now suricata-forwarder.service
```

### 4. Check status and logs
```bash
sudo systemctl status suricata-forwarder.service
sudo journalctl -u suricata-forwarder.service -f
```

