import React from 'react';
import FeatureImportanceChart from '../phantomnet-dashboard/src/components/ml/FeatureImportanceChart';

export default {
  title: 'ML/FeatureImportanceChart',
  component: FeatureImportanceChart,
};

const mockData = [
  { name: 'Request Volume', value: 0.85 },
  { name: 'Unique IPs', value: 0.62 },
  { name: 'Payload Size', value: 0.45 },
  { name: 'Header Entropy', value: 0.38 },
  { name: 'Session Duration', value: 0.21 },
  { name: 'Unusual Port', value: 0.15 },
];

export const Default = () => (
  <div style={{ padding: '20px', maxWidth: '600px', background: '#020617' }}>
    <FeatureImportanceChart data={mockData} />
  </div>
);

export const Loading = () => (
    <div style={{ padding: '20px', maxWidth: '600px', background: '#020617' }}>
      <FeatureImportanceChart data={[]} />
    </div>
);
