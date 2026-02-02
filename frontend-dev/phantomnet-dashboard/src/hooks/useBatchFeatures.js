import { useEffect, useState } from "react";
import { getBatchFeatures } from "../api/mlClient";
import { normalSSHEvent } from "../mocks/mlMockData";

const useBatchFeatures = (eventIds = []) => {
  const [data, setData] = useState([]);
  const [_loading, setLoading] = useState(false);
  const [_error, setError] = useState(null);

  useEffect(() => {
    if (!eventIds.length) return;

    const fetchBatchFeatures = async () => {
      setLoading(true);
      try {
        const response = await getBatchFeatures(eventIds);
        setData(response);
      } catch (err) {
        console.warn("Batch API failed, using mock data");
        const fallbackData = eventIds.map((id) => ({
          eventId: id,
          features: normalSSHEvent,
        }));
        setData(fallbackData);
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchBatchFeatures();
  }, [eventIds]);

  // 🔹 ADD THIS BLOCK (Step 5)
  useEffect(() => {
    if (_loading) {
      console.debug("Batch features loading...");
    }
    if (_error) {
      console.debug("Batch features error:", _error);
    }
  }, [_loading, _error]);

  return { data };
};

export default useBatchFeatures;
