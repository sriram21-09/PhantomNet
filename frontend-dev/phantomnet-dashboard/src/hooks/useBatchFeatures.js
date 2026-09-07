import { useEffect, useState } from "react";
import { getBatchFeatures } from "../api/mlClient";
import { normalSSHEvent } from "../mocks/mlMockData";

const useBatchFeatures = (eventIds = []) => {
  const [data, setData] = useState([]);

  useEffect(() => {
    if (!eventIds.length) return;

    const fetchBatchFeatures = async () => {
      try {
        const response = await getBatchFeatures(eventIds);
        setData(response);
      } catch {
        const fallbackData = eventIds.map((id) => ({
          eventId: id,
          features: normalSSHEvent,
        }));
        setData(fallbackData);
      }
    };

    fetchBatchFeatures();
  }, [eventIds]);

  return { data };
};

export default useBatchFeatures;
