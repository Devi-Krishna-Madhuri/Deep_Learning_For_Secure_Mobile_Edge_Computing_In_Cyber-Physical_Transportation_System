# Deep Learning for Secure Mobile Edge Computing in Cyber-Physical Transportation Systems

This is a Flask-based web application for classifying network attacks using a pre-trained Convolutional Neural Network (CNN) model. The system allows users to register,Admin can log in and predict the type of network attack based on input parameters. It also includes an admin dashboard for viewing prediction history.

## Features

- User registration and login
- Network attack prediction using a pre-trained CNN model
- Email alerts for detected attacks
- Admin dashboard for viewing prediction history
- SQLite database for storing user and prediction data

## Technologies Used

- **Flask**: Web framework for Python
- **SQLite**: Lightweight database for storing user and prediction data
- **TensorFlow/Keras**: Pre-trained CNN model for attack classification
- **Pandas/NumPy**: Data preprocessing
- **Joblib**: For loading scaler and label encoders
- **Bootstrap**: Front-end styling
- **JavaScript**: Dynamic error handling and form submission

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/network-attack-classification.git
   cd network-attack-classification