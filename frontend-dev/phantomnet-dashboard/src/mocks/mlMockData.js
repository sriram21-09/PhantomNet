export const normalSSHEvent = {
  eventId: "SSH-001",
  features: {
    packet_length: {
      label: "Packet Length",
      value: 520,
      interpretation: "Normal packet size",
    },
    protocol_encoding: {
      label: "Protocol Encoding",
      value: "SSH",
      interpretation: "Known secure protocol",
    },
    source_ip_rate: {
      label: "Source IP Event Rate",
      value: 5,
      interpretation: "Low traffic rate",
    },
    destination_port_class: {
      label: "Destination Port Class",
      value: "Well-known",
      interpretation: "Expected SSH port usage",
    },
    threat_score: {
      label: "Threat Score",
      value: 22,
      interpretation: "Low baseline threat",
    },
    malicious_ratio: {
      label: "Malicious Flag Ratio",
      value: 0.05,
      interpretation: "Mostly benign activity",
    },
    attack_type_frequency: {
      label: "Attack Type Frequency",
      value: 1,
      interpretation: "No repetitive attack pattern",
    },
    time_deviation: {
      label: "Time of Day Deviation",
      value: false,
      interpretation: "Within normal hours",
    },
    burst_rate: {
      label: "Burst Rate",
      value: 3,
      interpretation: "Normal traffic burst",
    },
    packet_variance: {
      label: "Packet Size Variance",
      value: 0.8,
      interpretation: "Low variance",
    },
    honeypot_count: {
      label: "Honeypot Interaction Count",
      value: 1,
      interpretation: "Single honeypot touched",
    },
    session_duration: {
      label: "Session Duration (seconds)",
      value: 120,
      interpretation: "Short-lived session",
    },
    unique_destinations: {
      label: "Unique Destination Count",
      value: 1,
      interpretation: "No lateral movement",
    },
    rolling_deviation: {
      label: "Rolling Average Deviation",
      value: 0.2,
      interpretation: "Stable behavior",
    },
    z_score: {
      label: "Z-Score Anomaly",
      value: 0.8,
      interpretation: "Within normal distribution",
    },
  },
};