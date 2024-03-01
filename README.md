
<p align="center">
    <h1 align="center">Communication_LTD</h1>
</p>

<p align="center">
		<em>Developed with the software and tools below:</em>
</p>

<p align="center">
	<img src="https://img.shields.io/badge/HTML5-E34F26.svg?style=flat&logo=HTML5&logoColor=white" alt="HTML5">
	<img src="https://img.shields.io/badge/Jinja-B41717.svg?style=flat&logo=Jinja&logoColor=white" alt="Jinja">
	<img src="https://img.shields.io/badge/Python-3776AB.svg?style=flat&logo=Python&logoColor=white" alt="Python" width= '65'>
   <img src="https://img.shields.io/badge/Flask-000000.svg?style=flat&logo=Flask&logoColor=white" alt="Flask">
   <img src="https://img.shields.io/badge/SQLite-07405E?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite" width= '65'>
	<img src="https://img.shields.io/badge/JSON-000000.svg?style=flat&logo=JSON&logoColor=white" alt="JSON" >

</p>
<hr>
<p align="center">
  <img src="https://i.imgur.com/Oe8lWXh.png" width="600"/>
</p>

##  Quick Links

> - [ Overview](#-overview)
> - [ Features](#-features)
> - [ Repository Structure](#-repository-structure)
> - [ Modules](#-modules)
> - [ Getting Started](#-getting-started)
>   - [ Installation](#-installation)
>   - [ Running Communication_LTD](#-running-Communication_LTD)
> - [ Project Roadmap](#-project-roadmap)
> - [ Contributing](#-contributing)
> - [ License](#-license)
> - [ Acknowledgments](#-acknowledgments)

---

##  Overview

Communication_LTD is a flask-based cybersecurity application focusing on reliable user authentication and management. It offers features like secure password recovery, diligent user registration, and robust session management, underpinned by secure configurations, SQL interfacing, and email services. The main purpose of this project is to demonstrate secure versus unsecure code engineering. The use of responsive templates ensures optimal user interaction. Overall, it aims to secure web applications by strengthening user authentication and enhancing data integrity.

---

##  Features

|    |   Feature         | Description |
|----|-------------------|---------------------------------------------------------------|
| ⚙️  | **Architecture**  | The project is deeply tied to a Flask server with SQLite database, major parts being user authentication, mail service, and database operations. |
| 🔩 | **Code Quality**  | The code follows a structured approach with good use of object-oriented principles. Possible improvement: addition of docstrings/comments for better readability. |
| 📄 | **Documentation** | Minimal documentation available. Further explanations of the project's functionality and how to use/setup the project would be beneficial. |
| 🔌 | **Integrations**  | The project integrates core Python libraries and Flask modules with SQLite database for functioning. It uses Flask-Mail for notifications. |
| 🧩 | **Modularity**    | Good modularity with separate files handling configuration, utility functions, database models, and application logic. |
| 🧪 | **Testing**       | No explicit testing framework appears to be used, which is a significant gap and it needed for maintainability. |
| ⚡️  | **Performance**   | The project is relatively lightweight and should have good performance. Efficiency and speed services will depend on the host machine. |
| 🛡️ | **Security**      | Password and login security is implemented (length, complexity rules), there's an effort to ensure data protection and access control using Flask. |
| 📦 | **Dependencies**  | Key dependencies include Python's standard libraries, Flask and its extensions, SQLite, and greenlet. |


---

##  Repository Structure

```sh
└── Communication_LTD/
    ├── README.md
    ├── app.py
    ├── config.json
    ├── functions.py
    ├── instance
    │   └── site.db
    ├── models.py
    ├── requirements.txt
    ├── rockyou.txt
    ├── static
    │   └── images
    │       ├── Logo.png
    │       └── favicon.png
    ├── templates
    │   ├── home.html
    │   ├── login.html
    │   ├── password_recovery.html
    │   └── register.html
    └── vuln_app.py
```

---

##  Modules

<details closed><summary>.</summary>

| File                                                                                        | Summary                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ---                                                                                         | ---                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| [rockyou.txt](https://github.com/arielya10/Communication_LTD/blob/master/rockyou.txt)           | The "rockyou.txt" file contains a list of these compromised passwords, which are often utilized by security professionals and hackers for password cracking and security testing purposes. The file serves as a cautionary reminder of the importance of strong, unique passwords and the risks associated with poor password management practices..                                                                                           |
| [config.json](https://github.com/arielya10/Communication_LTD/blob/master/config.json)           | The config.json file in the Communication_LTD repository centrally defines the system's security policies such as password length, complexity rules, password history, and maximum login attempts — an important configuration asset. It also specifies the dictionary file for password validation, the secret key, and mail server settings for notifications.                                                                                             |
| [app.py](https://github.com/arielya10/Communication_LTD/blob/master/app.py)                     | This app.py script initiates the main Flask application for the Communication_LTD repository. It imports necessary modules, loads configurations from a JSON file, applies them to the Flask app, and establishes email service through Flask-Mail. Furthermore, it sets a secret key for managing user sessions securely.                                                                                                                 |
| [vuln_app.py](https://github.com/arielya10/Communication_LTD/blob/master/vuln_app.py)           | vulnerable version of the app. py, its vulnerable to SQL injection and stored XSS. The login page can be hacked by writing "username'-- -" In the login page. The registarion/add users pages can be hacked writing `email@gmail.com'; DROP TABLE customer; --`                                                                                                                |
| [functions.py](https://github.com/arielya10/Communication_LTD/blob/master/functions.py)         | This code snippet can be found in the functions.py file within the Communication_LTD repository. It includes vital functions for establishing a connection to the database and updating a user's password. Interacting with the SQLite database, these methods contribute to the overall user authentication and manage crucial password update operations.                                                                                                  |
| [models.py](https://github.com/arielya10/Communication_LTD/blob/master/models.py)               | The models.py script in the Communication_LTD repository serves as the central database management module. The script is responsible for initializing the SQLite database, creating user and customer tables, establishing a database connection, and removing all data from the database. This underpins the data-oriented operations in the repository, setting up the necessary data schema, facilitating data interactions, and ensuring data integrity. |
| [requirements.txt](https://github.com/arielya10/Communication_LTD/blob/master/requirements.txt) | The requirements.txt file lists all dependencies needed for the Communication_LTD. Besides the mandatory Flask modules, it includes packages for templating (Jinja2), SQL interfacing (SQLAlchemy), and sending emails (Flask-Mail). This ensures project portability and replicability across different environments.                                                                                                                                       |                                                                                                                           |

</details>

<details closed><summary>templates</summary>

| File                                                                                                              | Summary                                                                                                                                                                                                                                                                                                                                                                                                  |
| ---                                                                                                               | ---                                                                                                                                                                                                                                                                                                                                                                                                      |
| [password_recovery.html](https://github.com/arielya10/Communication_LTD/blob/master/templates/password_recovery.html) | The password_recovery.html is a part of the Communication_LTD repository acting as the user interface for the password recovery feature. It uses BootStrap for design standardization. It displays the company logo and creates the structure for the password recovery form. The final result is communicating with other parts of the infrastructure to confirm/user's identity and reset their passwords. |
| [login.html](https://github.com/arielya10/Communication_LTD/blob/master/templates/login.html)                         | The login.html is part of the templates directory in the Communication_LTD repository. It defines the structure and appearance of the user login page for the application Communication_LTD. Additionally, it provides responsive design for different screen sizes, integrates Bootstrap for UI styling, and includes images from the static directory for branding elements.                               |
| [register.html](https://github.com/arielya10/Communication_LTD/blob/master/templates/register.html)                   | The register.html file provides the interface for user registration in the Communication_LTD platform. It incorporates visual elements, user form inputs, and applies Bootstrap for a responsive layout. It also enables dynamic linking to static assets like the website's favicon and logo.                                                                                                               |
| [home.html](https://github.com/arielya10/Communication_LTD/blob/master/templates/home.html)                           | The code in templates/home.html constitutes the repository's homepage user interface for Communication_LTD. It uses Bootstrap for styling and allows displaying the site's logo, title, and welcome message. It also includes a responsive design for optimal viewing across different device screens. You can choose if you want the page to be vulnerable to XSS by changing the code at the button on the file. XSS example attack: `<img src=x onerror="window.location='https://www.google.com'">`                                                            |

</details>

---

##  Getting Started

***Requirements***

Ensure you have the following dependencies installed on your system:

* **Python**

###  Installation

1. Clone the Communication_LTD repository:

```sh
git clone https://github.com/arielya10/Communication_LTD
```

2. Change to the project directory:

```sh
cd Communication_LTD
```

3. Create virtual environment:

```sh
python -m venv venv
```
4. Activate the virtual environment:

```sh
venv\Scripts\activate.bat
```

5. Install the dependencies:

```sh
pip install -r requirements.txt
```

###  Running Communication_LTD

Use the following command to run Communication_LTD:

```sh
python app.py
```
Once the application is running, navigate to http://127.0.0.1:5000 in your web browser to start using the application.


---





##  Contributing

Contributions are welcome! Here are several ways you can contribute:

- **[Submit Pull Requests](https://github.com/arielya10/Communication_LTD/blob/main/CONTRIBUTING.md)**: Review open PRs, and submit your own PRs.
- **[Join the Discussions](https://github.com/arielya10/Communication_LTD/discussions)**: Share your insights, provide feedback, or ask questions.
- **[Report Issues](https://github.com/arielya10/Communication_LTD/issues)**: Submit bugs found or log feature requests for Communication_LTD.

<details closed>
    <summary>Contributing Guidelines</summary>

1. **Fork the Repository**: Start by forking the project repository to your GitHub account.
2. **Clone Locally**: Clone the forked repository to your local machine using a Git client.
   ```sh
   git clone https://github.com/arielya10Communication_LTD
   ```
3. **Create a New Branch**: Always work on a new branch, giving it a descriptive name.
   ```sh
   git checkout -b new-feature-x
   ```
4. **Make Your Changes**: Develop and test your changes locally.
5. **Commit Your Changes**: Commit with a clear message describing your updates.
   ```sh
   git commit -m 'Implemented new feature x.'
   ```
6. **Push to GitHub**: Push the changes to your forked repository.
   ```sh
   git push origin new-feature-x
   ```
7. **Submit a Pull Request**: Create a PR against the original project repository. Clearly describe the changes and their motivations.

Once your PR is reviewed and approved, it will be merged into the main branch.

</details>

---

##  License

This project is protected under the [SELECT-A-LICENSE](https://choosealicense.com/licenses) License. For more details, refer to the [LICENSE](https://choosealicense.com/licenses/) file.

---

##  Acknowledgments

- List any resources, contributors, inspiration, etc. here.

[**Return**](#-quick-links)

---
