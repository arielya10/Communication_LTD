# Cyber Project
Web application designed for secure communication and user management. It features user registration, login, password recovery, and change password functionalities. The application uses Flask for backend development and SQLAlchemy for database management, ensuring a robust and secure user experience.


## Features
- User registration and login system.
- Email verification for password reset.
- Password complexity checks and dictionary-based weak password prevention.
- Account lockout mechanism after a defined number of failed login attempts.

## Installation

To get this application running on your local environment, follow these steps:

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/arielya10/Cyber-Project 
   cd Cyber-Project
   ```
2. **Set up a Virtual Environment:**
   ```bash
    python -m venv venv
    venv\Scripts\activate
   ```
3. **Install Required Packages:**
   ```bash
   pip install -r requirements.txt
   ```

## Usage

```bash
python app.py
```
Once the application is running, navigate to http://127.0.0.1:5000 in your web browser to start using the application.
