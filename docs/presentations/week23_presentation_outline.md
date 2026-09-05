# PhantomNet Sentinel: Project Presentation Deck Outline

## Slide 1: Title Slide
* **Title:** PhantomNet Sentinel: AI-Driven Cyber Defense
* **Subtitle:** Final Project Presentation (Week 23)
* **Speaker:** Sriram
* **Media:** (Optional) Project Logo

## Slide 2: Problem Statement & Objectives
* **Headline:** The Challenge in Modern SOCs
* **Content:**
  * High alert fatigue and false positive rates.
  * Time-consuming manual incident response documentation.
  * Difficulty in correlating dispersed attack vectors.
* **Objective:** Build an end-to-end Honeypot, ML Detection, and LLM Narrative synthesis pipeline.

## Slide 3: System Architecture Overview
* **Headline:** PhantomNet Architecture
* **Visual:** `docs/diagrams/1 SYSTEM ARCHITECTURE DIAGRAM.png`
* **Content:**
  * Honeypot & Packet Capture Engine
  * ML Threat Detection Engine (Random Forest + Isolation Forest)
  * LLM Narrative Generation (Ollama / Mistral)
  * Sentinel Dashboard Frontend

## Slide 4: Machine Learning Threat Detection
* **Headline:** Identifying Threats with High Precision
* **Visual:** Embedded snippet of F1-score benchmarks (F1-Score: 0.97)
* **Content:**
  * Hybrid approach: Anomaly Detection (Isolation Forest) + Supervised Classifier (Random Forest/LSTM).
  * Feature Engineering: Protocol analysis, Network flow metrics, and Behavioral heuristics.
  * SMOTE used for handling class imbalances.

## Slide 5: LLM-Powered Incident Playbooks
* **Headline:** Automated Playbook Generation
* **Media Assets:** `demos/sentinel_v3_demo.mp4` / `demos/sentinel_v3_demo.gif`
* **Content:**
  * Ollama integration serving Mistral-7B (Primary) and Gemma-2B (Fallback).
  * Dynamic Jinja2 templating system for structured outputs.
  * Few-Shot Prompt engineering to guide narrative tone and accuracy.
  * Hardware benchmark: 2.4s avg generation latency on GPU.

## Slide 6: Dynamic Threat Scoring & Campaign Modeling
* **Headline:** Prioritizing Threats Effectively
* **Media Assets:** `demos/demo_dashboard_walkthrough.mp4` / `demos/demo_dashboard_walkthrough.gif` (Highlighting Campaign Timeline & MITRE Heatmap)
* **Content:**
  * Quality Scoring Engine (0-100) based on ML confidence, IOC density, and multi-source verification.
  * Campaign Density Modeling aggregating events into time-series buckets to visualize lateral movement and sustained attacks.

## Slide 7: End-to-End Pipeline Demonstration & Threat Intelligence Sharing
* **Headline:** Sentinel Pipeline & TAXII 2.1 Dissemination In Action
* **Media Assets:** `demos/demo_pipeline_e2e.mp4` / `demos/demo_pipeline_e2e.gif` and `demos/demo_ids_taxii.mp4` / `demos/demo_ids_taxii.gif`
* **Content:**
  * Walkthrough from Honeypot ingestion to Playbook generation.
  * Displaying the generated MITRE ATT&CK mappings, Snort/Sigma rules, and containment steps.
  * Real-time TAXII 2.1 collection discovery and STIX 2.1 bundle dissemination.

## Slide 8: Future Work & Enhancements
* **Headline:** Roadmap and Scalability
* **Content:**
  * Distributed deployment across multiple cloud regions.
  * Active integration with SIEM (Splunk, Elastic).
  * Fine-tuning LLMs on proprietary incident datasets.

## Slide 9: Q&A
* **Headline:** Questions?
* **Content:** Thank you for your time.
