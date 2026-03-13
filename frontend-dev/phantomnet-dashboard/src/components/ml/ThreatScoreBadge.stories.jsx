import React from 'react';
import ThreatScoreBadge from '../phantomnet-dashboard/src/components/ml/ThreatScoreBadge';

export default {
  title: 'ML/ThreatScoreBadge',
  component: ThreatScoreBadge,
  argTypes: {
    score: { control: { type: 'range', min: 0, max: 100, step: 1 } },
    size: { control: { type: 'select', options: ['sm', 'md', 'lg'] } },
  },
};

const Template = (args) => <ThreatScoreBadge {...args} />;

export const Low = Template.bind({});
Low.args = {
  score: 15,
  size: 'md',
};

export const Medium = Template.bind({});
Medium.args = {
  score: 45,
  size: 'md',
};

export const High = Template.bind({});
High.args = {
  score: 82,
  size: 'md',
};

export const Critical = Template.bind({});
Critical.args = {
  score: 98,
  size: 'lg',
};

export const Small = Template.bind({});
Small.args = {
  score: 60,
  size: 'sm',
};
