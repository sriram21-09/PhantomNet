import FeatureVector from "./FeatureVector";
import {
  normalSSHEvent,
  anomalousSSHEvent,
} from "../mocks/mlMockData.js";

export default {
  title: "Components/FeatureVector",
  component: FeatureVector,
};

export const NormalSSH = {
  args: {
    eventId: normalSSHEvent.eventId,
    featureVector: normalSSHEvent.features,
  },
};

export const AnomalousSSH = {
  args: {
    eventId: anomalousSSHEvent.eventId,
    featureVector: anomalousSSHEvent.features,
  },
};
