# Leakage Audit Report

- HIGH risk columns: ['flow_id', 'source_ip', 'destination_ip', 'timestamp']
- MEDIUM risk columns: ['source_port', 'destination_port']
- LOW risk / near-constant columns: none found
- Suspected label-encoding columns: ['label']

## Per-column detail

| Column | Risk | Reason | n_unique | Constant |
|---|---|---|---|---|
| flow_id | HIGH | column name matches known high-risk identifier pattern (flow/IP/timestamp) | 320 | False |
| source_ip | HIGH | column name matches known high-risk identifier pattern (flow/IP/timestamp) | 40 | False |
| destination_ip | HIGH | column name matches known high-risk identifier pattern (flow/IP/timestamp) | 8 | False |
| source_port | MEDIUM | column name matches known port-identifier pattern; may carry legitimate signal but also overfitting risk | 320 | False |
| destination_port | MEDIUM | column name matches known port-identifier pattern; may carry legitimate signal but also overfitting risk | 3 | False |
| protocol | NONE | no known leakage indicator matched | 2 | False |
| timestamp | HIGH | column name matches known high-risk identifier pattern (flow/IP/timestamp) | 320 | False |
| flow_duration | NONE | no known leakage indicator matched | 317 | False |
| total_fwd_packets | NONE | no known leakage indicator matched | 25 | False |
| total_backward_packets | NONE | no known leakage indicator matched | 12 | False |
| total_length_of_fwd_packets | NONE | no known leakage indicator matched | 25 | False |
| total_length_of_bwd_packets | NONE | no known leakage indicator matched | 18 | False |
| fwd_packet_length_mean | NONE | no known leakage indicator matched | 5 | False |
| bwd_packet_length_mean | NONE | no known leakage indicator matched | 5 | False |
| flow_bytes_s | NONE | no known leakage indicator matched | 320 | False |
| flow_packets_s | NONE | no known leakage indicator matched | 318 | False |
| label | NONE | no known leakage indicator matched | 8 | False |
| source_file | NONE | no known leakage indicator matched | 8 | False |

## Notes
- Column 'label' contains values overlapping the label set — review manually.