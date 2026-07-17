# Phishing Website Detection System Using Machine Learning

A real-time phishing website detection system that leverages an XGBoost machine learning model to identify malicious URLs. The project consists of a Python Flask backend API for URL analysis and a Chrome Extension frontend that seamlessly integrates into the browser to protect users as they browse the web.

## Features

- **Real-Time Protection**: Evaluates websites instantly upon opening them in the browser.
- **Machine Learning Powered**: Uses an XGBoost classifier combined with Natural Language Processing (NLP) to detect phishing patterns.
- **Content & URL Analysis**: Analyzes both the structure of the URL and the textual content of the webpage to determine its legitimacy.
- **Lightweight Extension**: Non-intrusive Chrome Extension that runs quietly in the background.

## Project Architecture

1. **Machine Learning Model**: Built using Jupyter Notebook (`phishing website detection system.ipynb`), relying on datasets to extract features and train an XGBoost model.
2. **Backend API (`/backend`)**: A Flask application that exposes endpoints for the extension to communicate with. It uses `pickle` to load the pre-trained ML models and vectorizers.
3. **Chrome Extension (`/chrome_extension`)**: The user interface. It captures the current tab's URL and content, sending it to the backend for verification.

## Getting Started

### 1. Setting up the Backend

Make sure you have Python installed, then follow these steps:

```bash
# Navigate to the backend directory
cd backend

# (Optional) Create a virtual environment
python -m venv venv
# On Windows: venv\Scripts\activate
# On Mac/Linux: source venv/bin/activate

# Install the required dependencies
pip install -r requirements.txt

# Run the Flask server
python app.py
```
The backend server should now be running locally on `http://127.0.0.1:5000`.

### 2. Installing the Chrome Extension

1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** using the toggle switch in the top right corner.
3. Click on the **Load unpacked** button.
4. Select the `chrome_extension` folder located inside this project directory.
5. The extension should now appear in your browser. Pin it to your toolbar for easy access!

## How to Use

1. Ensure your backend Flask server is running.
2. Browse the web normally.
3. Click on the extension icon in your Chrome toolbar to view the status of the current page. If the page is detected as phishing, the extension will alert you.

## Repository Structure

- `/backend` - Contains the Flask API, the serialized ML models (`.pkl` files), and requirements.
- `/chrome_extension` - Contains the frontend popup, background scripts, and manifest file.
- `/Dataset` - The dataset used for training the machine learning model.
- `phishing website detection system.ipynb` - The data exploration and model training notebook.
