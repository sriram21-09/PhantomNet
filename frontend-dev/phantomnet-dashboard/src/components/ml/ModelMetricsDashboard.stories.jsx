import React from 'react';
import ModelMetricsDashboard from '../phantomnet-dashboard/src/components/ml/ModelMetricsDashboard';

export default {
  title: 'ML/ModelMetricsDashboard',
  component: ModelMetricsDashboard,
};

export const Default = () => (
  <div style={{ background: '#020617', minHeight: '100vh' }}>
    <ModelMetricsDashboard />
  </div>
);
