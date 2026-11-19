# NetScope 2.0 Privacy Policy & Disclosures

1. **Zero Data Collection**: NetScope does not collect, harvest, monetize, or transmit any user metrics, identifiers, or network activities.
2. **Local Storage**: All SQLite database files, historical bandwidth telemetry, DNS logs, and alerts remain stored exclusively on your local disk at `~/.local/share/netscope/`.
3. **External Lookups**: If external public IP or geolocation resolution is explicitly turned on in Settings, only public IP addresses are sent to the user's selected endpoint (`ip-api` / `ipify`). Private network ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, and loopback) are never queried externally.
