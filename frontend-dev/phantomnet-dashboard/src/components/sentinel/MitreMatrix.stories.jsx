import MitreMatrix from "./MitreMatrix";

export default {
  title: "Components/Sentinel/MitreMatrix",
  component: MitreMatrix,
};

export const DefaultScaffold = {
  args: {
    placeholderCount: 6,
  },
};

export const HeatmapMatrixWithFrequencies = {
  args: {
    techniqueFrequencies: {
      "T1190": 2,  // Low heat (Initial Access)
      "T1059": 14, // High heat (Execution)
      "T1053": 6,  // Medium heat (Persistence)
      "T1068": 1,  // Low heat (Privilege Escalation)
      "T1027": 9,  // High heat (Defense Evasion)
      "T1003": 5,  // Medium heat (Credential Access)
      "T1082": 3,  // Low heat (Discovery)
      "T1021": 12, // High heat (Lateral Movement)
      "T1114": 1,  // Low heat (Collection)
      "T1071": 7,  // Medium heat (C2)
      "T1041": 4,  // Medium heat (Exfiltration)
      "T1486": 18, // High heat (Impact)
    },
  },
};

export const HighThreatHeatmap = {
  args: {
    techniqueFrequencies: [
      { id: "T1059", count: 24 },
      { id: "T1003", count: 16 },
      { id: "T1021", count: 11 },
      { id: "T1027", count: 15 },
      { id: "T1486", count: 20 },
      { id: "T1190", count: 8 },
    ],
  },
};
