# Real-time traffic capture adapter

`live_capture.py` is an optional live-ingestion component for SAHE Cloud IDS/IPS. It uses Scapy/Npcap to capture authorized TCP/UDP traffic, aggregates packets into bidirectional flows, converts each flow into the 12 features expected by the current detection model, and submits completed flows to `POST /detect`.

The existing backend then performs the normal workflow:

```text
packet capture -> flow aggregation -> /detect -> ML prediction -> severity -> event -> WebSocket -> Live Attacks
```

This is a defensive monitoring component. Use it only on a network and interface you own or are explicitly authorized to monitor. It does not generate attacks and does not perform firewall blocking itself.

## Windows setup

1. Install Wireshark and enable **Npcap** during installation.
2. Open PowerShell in the project root.
3. Install the optional dependencies:

```powershell
python -m pip install -r tools\requirements-live.txt
```

4. Start the backend and frontend as documented in the project handbook.
5. List capture interfaces:

```powershell
python tools\live_capture.py --list-interfaces
```

6. Start capture using the interface name shown by the previous command:

```powershell
python tools\live_capture.py --interface "Wi-Fi" --api-url http://127.0.0.1:8000
```

If the interface name contains spaces, keep the quotes. Use `--bpf "tcp or udp"` to retain the default capture filter, or provide a narrower authorized filter such as `--bpf "tcp port 22"`.

## Dry-run validation

Before sending data to the backend, verify the packet-to-feature conversion without making API calls:

```powershell
python tools\live_capture.py --interface "Wi-Fi" --dry-run
```

The tool prints a JSON request after a flow has been inactive for the configured timeout. Use `--flow-timeout 5` to submit flows after five seconds of inactivity.

## Live dashboard test

1. Keep the Overview or Live Attacks page open until it reports `Live feed: open`.
2. Start `live_capture.py`.
3. Generate only normal authorized traffic, for example open a website you are allowed to access or connect to a service on your own lab machine.
4. Wait for flows to become inactive.
5. The adapter posts each flow to `/detect`.
6. Malicious model predictions are broadcast to Live Attacks. Benign predictions are logged but are not broadcast as attack alerts.

The included synthetic model is not trained to guarantee accurate classification of arbitrary real traffic. Therefore, a real capture may correctly produce benign results or may be classified unreliably until a model trained on representative official or local data is installed.

## Troubleshooting

- **Npcap/capture permission error:** run the terminal with the permissions required by the capture interface and verify Npcap is installed.
- **No detections:** confirm the backend is reachable at `http://127.0.0.1:8000/health`, confirm a model is loaded, and wait for flow timeout.
- **422 missing features:** the saved model expects a different feature manifest than the adapter. Train or install a model using the same 12-feature schema.
- **No Live Attacks alert:** the adapter may be submitting benign flows. Check the adapter terminal and the backend response; only malicious predictions are broadcast.
- **Wrong interface:** run `--list-interfaces` and use the exact returned name.

The adapter is intentionally separate from the FastAPI process so packet capture permissions, capture failures, and high-volume traffic cannot silently destabilize the API service.
