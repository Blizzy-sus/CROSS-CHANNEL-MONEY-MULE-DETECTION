# Cross-Channel Money Mule Detection System

## Overview

This project is a hybrid fraud detection platform designed to detect coordinated money mule activity across financial channels using:

- Random Forest Machine Learning
- Graph-Based Behavioral Features
- Rule-Based Risk Scoring
- SHAP Explainability
- Behavioral Drift Detection
- Adaptive Thresholding

The system simulates fraud attack patterns (Fan-In, Fan-Out) and classifies mule roles within coordinated rings.

---

## Project Structure

```
backend/
frontend/
Initially used/
```

- **backend/** → Core fraud logic, simulation, detection, training
- **frontend/** → Streamlit dashboard
- **Initially used/** → Early prototype versions (kept for development history)

---

## Features

- Hybrid Rule + ML detection
- Graph-based behavioral modeling
- SHAP explainability
- Fraud role classification
- Behavioral drift detection
- Adaptive thresholding system
- Interactive Streamlit dashboard

---

## Installation

Clone the repository:

```
git clone https://github.com/kausik-gh/CROSS-CHANNEL-MONEY-MULE-DETECTION.git
```

Install dependencies:

```
pip install -r requirements.txt
```

Run the application:

```
streamlit run frontend/streamlit_app.py
```

---

## Purpose

This system demonstrates a research-oriented approach to cross-channel fraud detection using hybrid AI techniques and graph analytics.

---

## Author

Kausik GH  
