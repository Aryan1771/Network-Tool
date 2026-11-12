# Uploadable website samples

These small, offline-only files exercise the website's PCAP ingestion and NS-2
trace upload flows. The packet captures use documentation-only IP addresses;
they are data files and do not generate network traffic.

## PCAP upload

In **Live Traffic → Source B: PCAP Artifact Upload**, select any capture below.
Each upload is preserved in the Evidence Vault, hashed, parsed, and checked by
the detection rules. Uploads add records to the local application database, so
use a disposable project database if you want to repeat a clean run. These
uploads are regular evidence records and are not removed by the demo-data reset.

| File | Expected behavior |
| --- | --- |
| `uploads/normal_traffic.pcap` | Normal TCP handshakes and DNS requests; no alert expected. |
| `uploads/port_scan.pcap` | Port scan alert for 25 destination ports in a short window. |
| `uploads/brute_force.pcap` | Repeated SSH connection attempts; brute-force alert. |
| `uploads/syn_flood.pcap` | High-rate SYN-only traffic; SYN-flood alert. |
| `uploads/data_exfiltration.pcap` | High-volume UDP transfer; data-exfiltration alert. |
| `uploads/mixed_activity.pcapng` | PCAPNG format check plus port-scan and SSH-attempt alerts. |

## NS-2 trace upload

In **NS-2 Simulation → Upload Custom NS-2 Trace**, select one of:

| File | Expected metrics |
| --- | --- |
| `ns2/normal_trace.tr` | High packet delivery, no drops. |
| `ns2/packet_loss_trace.tr` | Non-zero packet loss. |
| `ns2/flooding_trace.tr` | High traffic volume and a non-zero drop ratio. |

## Recreate the samples

Run `python tests/fixtures/generate_upload_samples.py`. It uses Scapy, which is
already listed in the project requirements, and writes deterministic fixtures
to this directory.
