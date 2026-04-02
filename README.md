# Phishing_detection_model beta v1.2
PHISHING WEBSITE DETECTION SYSTEM
(URL BASED MACHINE LEARNING MODEL)

Project Overview
----------------
This project presents a phishing website detection system that analyzes website URLs and predicts whether the website is Safe, Suspicious, or Phishing. The system is designed as a user-friendly web application that allows users to enter a URL and receive an instant risk evaluation.

Phishing websites attempt to trick users into entering sensitive information such as login credentials, banking details, and personal information by imitating legitimate websites. The goal of this project is to provide a smart detection system that can identify suspicious patterns in URLs and help prevent cyber fraud.

The project uses both rule-based detection techniques and machine learning concepts to improve detection accuracy and reliability.

--------------------------------------------------

Working Principle
-----------------
The system accepts a URL as input from the user interface and performs feature extraction on the URL. The extracted features are then analyzed using phishing detection logic.

The application evaluates multiple characteristics of the URL such as:

• URL length
• presence of suspicious keywords
• presence of special characters
• domain structure
• number of subdomains
• HTTPS protocol usage
• use of IP address instead of domain
• suspicious top level domains

Based on these features, the system calculates a risk score and classifies the URL into one of three categories:

Safe Website
Suspicious Website
Phishing Website

The result is displayed visually with explanation of detected risk factors.

--------------------------------------------------

Main Functions
--------------
scanURL()

This function performs the main phishing detection process. It extracts URL features, calculates risk score, and updates the user interface with classification results.

clearInput()

This function resets the input field and clears previous results from the interface.

randomURL()

This function loads a random test URL to demonstrate system functionality.

addHistory()

Stores previously scanned URLs with classification result and timestamp.

displayHistory()

Displays the previously scanned URLs for reference.

copyReport()

Copies the phishing detection explanation to clipboard for reporting or documentation purposes.

animateBar()

Animates the progress bar based on calculated risk score.

--------------------------------------------------

New Additions and Unique Features
---------------------------------
This project includes several unique features that improve usability and demonstrate advanced design thinking:

Interactive User Interface
A modern UI design with progress bar, color indicators, and clear output explanation improves user understanding of results.

Risk Score Visualization
The system calculates and displays a numerical risk score to show the probability of phishing.

Explainable Output
The system provides reasons for classification instead of only showing a prediction result.

History Tracking
Previously scanned URLs are stored and displayed for comparison and reference.

Random URL Testing
A built-in feature allows testing the system quickly using sample URLs.

Copy Report Feature
Users can copy scan results easily for documentation or reporting.

Enter Key Support
Users can press Enter to scan URL quickly.

Responsive Design
The interface is designed to work across different screen sizes.

Modular JavaScript Structure
Functions are separated logically for easy improvement and machine learning integration.

--------------------------------------------------

Use of Machine Learning
-----------------------
The current version of the project demonstrates rule-based feature extraction which forms the basis for machine learning model training.

Machine learning can improve the system by learning patterns from large datasets of phishing and legitimate URLs.

Future versions of the project can include:

Logistic Regression
Decision Tree
Random Forest
Support Vector Machine
Neural Networks

Machine learning models can be trained using datasets containing phishing and legitimate URLs. The model will learn patterns and predict whether new URLs are malicious.

Feature extraction used in this project can directly be used as input features for machine learning training.

Example features for ML model:

URL length
Number of dots
Number of special characters
Keyword presence
Subdomain count
HTTPS presence
IP address usage
Domain length

Machine learning integration will increase accuracy and allow detection of previously unseen phishing websites.

--------------------------------------------------

Technologies Used
-----------------
HTML
CSS
JavaScript
Machine Learning Concepts
URL Feature Extraction
Pattern Matching

Future Implementation:
Python
Flask
Scikit-learn
Dataset Training

--------------------------------------------------

Applications
------------
Cyber security tools
Browser security extensions
Fraud detection systems
Educational security projects
Network monitoring tools

--------------------------------------------------

Future Scope
------------
Integration with real machine learning models
Real-time website monitoring
Browser extension development
Executable desktop application version
API-based phishing detection
Database integration for phishing URLs
Improved UI design
Higher accuracy prediction models

--------------------------------------------------

Conclusion
----------
The phishing website detection system demonstrates how URL-based feature extraction combined with machine learning concepts can help detect fraudulent websites. The system provides a foundation for further development into a fully automated cyber security tool.

This project highlights the importance of explainable AI, user-friendly interface design, and practical machine learning applications in cybersecurity.
