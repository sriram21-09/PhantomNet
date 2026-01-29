/* =========================
   NORMAL SSH EVENT
========================= */
export const normalSSHEvent = {
  eventId: "SSH-001",
  features: {
    packet_length: {
      label: "Packet Length",
      value: 520,
      interpretation: "Normal packet size",
      status: "normal",
    },
    protocol_encoding: {
      label: "Protocol Encoding",
      value: "SSH",
      interpretation: "Known secure protocol",
      status: "normal",
    },
    source_ip_rate: {
      label: "Source IP Event Rate",
      value: 5,
      interpretation: "Low traffic rate",
      status: "normal",
    },
    destination_port_class: {
      label: "Destination Port Class",
      value: "Well-known",
      interpretation: "Expected SSH port usage",
      status: "normal",
    },
    threat_score: {
      label: "Threat Score",
      value: 22,
      interpretation: "Low baseline threat",
      status: "normal",
    },
    malicious_ratio: {
      label: "Malicious Flag Ratio",
      value: 0.05,
      interpretation: "Mostly benign activity",
      status: "normal",
    },
    attack_type_frequency: {
      label: "Attack Type Frequency",
      value: 1,
      interpretation: "No repetitive attack pattern",
      status: "normal",
    },
    time_deviation: {
      label: "Time of Day Deviation",
      value: false,
      interpretation: "Within normal hours",
      status: "normal",
    },
    burst_rate: {
      label: "Burst Rate",
      value: 3,
      interpretation: "Normal traffic burst",
      status: "normal",
    },
    packet_variance: {
      label: "Packet Size Variance",
      value: 0.8,
      interpretation: "Low variance",
      status: "normal",
    },
    honeypot_count: {
      label: "Honeypot Interaction Count",
      value: 1,
      interpretation: "Single honeypot touched",
      status: "normal",
    },
    session_duration: {
      label: "Session Duration (seconds)",
      value: 120,
      interpretation: "Short-lived session",
      status: "normal",
    },
    unique_destinations: {
      label: "Unique Destination Count",
      value: 1,
      interpretation: "No lateral movement",
      status: "normal",
    },
    rolling_deviation: {
      label: "Rolling Average Deviation",
      value: 0.2,
      interpretation: "Stable behavior",
      status: "normal",
    },
    z_score: {
      label: "Z-Score Anomaly",
      value: 0.8,
      interpretation: "Within normal distribution",
      status: "normal",
    },
  },
};

/* =========================
   ANOMALOUS SSH EVENT
========================= */
export const anomalousSSHEvent = {
  eventId: "SSH-ANOM-009",
  features: {
    packet_length: {
      label: "Packet Length",
      value: 1800,
      interpretation: "Abnormally large packet size",
      status: "anomalous",
    },
    protocol_encoding: {
      label: "Protocol Encoding",
      value: "SSH",
      interpretation: "Known protocol",
      status: "normal",
    },
    source_ip_rate: {
      label: "Source IP Event Rate",
      value: 45,
      interpretation: "High event rate – possible brute force",
      status: "anomalous",
    },
    destination_port_class: {
      label: "Destination Port Class",
      value: "Well-known",
      interpretation: "Expected SSH port",
      status: "normal",
    },
    threat_score: {
      label: "Threat Score",
      value: 78,
      interpretation: "High threat score",
      status: "anomalous",
    },
    malicious_ratio: {
      label: "Malicious Flag Ratio",
      value: 0.6,
      interpretation: "High malicious activity",
      status: "anomalous",
    },
    attack_type_frequency: {
      label: "Attack Type Frequency",
      value: 12,
      interpretation: "Repeated attack pattern detected",
      status: "anomalous",
    },
    time_deviation: {
      label: "Time of Day Deviation",
      value: true,
      interpretation: "Off-hour attack activity",
      status: "anomalous",
    },
    burst_rate: {
      label: "Burst Rate",
      value: 18,
      interpretation: "Traffic burst anomaly",
      status: "anomalous",
    },
    packet_variance: {
      label: "Packet Size Variance",
      value: 3.5,
      interpretation: "High variance detected",
      status: "anomalous",
    },
    honeypot_count: {
      label: "Honeypot Interaction Count",
      value: 3,
      interpretation: "Multiple honeypots targeted",
      status: "anomalous",
    },
    session_duration: {
      label: "Session Duration (seconds)",
      value: 620,
      interpretation: "Long-lived suspicious session",
      status: "anomalous",
    },
    unique_destinations: {
      label: "Unique Destination Count",
      value: 6,
      interpretation: "Horizontal scanning behavior",
      status: "anomalous",
    },
    rolling_deviation: {
      label: "Rolling Average Deviation",
      value: 2.4,
      interpretation: "Behavioral drift detected",
      status: "anomalous",
    },
    z_score: {
      label: "Z-Score Anomaly",
      value: 3.1,
      interpretation: "Statistical anomaly confirmed",
      status: "anomalous",
    },
  },
};
