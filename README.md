## E-Signature Project (Group 2)
## Slide:
https://www.canva.com/design/DAGltAtyVf4/iP2LndppxmIl0_0UOlOBgw/edit?utm_content=DAGltAtyVf4&utm_campaign=designshare&utm_medium=link2&utm_source=sharebutton

# Permission Slip Manager with Digital Signatures

## Description

This project is an educational web application designed to manage school permission slips. It demonstrates the implementation of a digital signature workflow using RSA "Hash & Sign" cryptography for verifying the authenticity and integrity of submitted forms. The application features distinct roles for administrators (to create and manage forms) and parents (to view and digitally sign forms).

## Key Features

* **Admin Panel:**
    * Secure admin login.
    * Create new permission slip forms (title, description, student name, parent email).
    * View a list of all created forms with their current status (Pending, Signed).
    * View a basic audit trail for each form (creation, signing attempts, digital signature creation).
* **Parent Portal:**
    * Lookup forms assigned to a specific parent email.
    * View details of pending permission slips.
    * Digitally sign forms using an RSA "Hash & Sign" approach:
        * Form data is hashed (SHA-256).
        * The hash is signed using a parent-specific RSA private key.
        * The cryptographic signature is stored with the form.
    * Visual signature capture (typed name and drawn signature on canvas) for user experience, complementing the cryptographic signature.
* **Security & Robustness:**
    * Admin authentication with hashed passwords (bcrypt) and session management.
    * Server-side input validation for form creation.
    * Generation and simplified storage of RSA key pairs for parents (for educational demonstration).

## Technologies Used

* **Backend:** Node.js, Express.js
* **Database:** SQLite3
* **Cryptography:** Node.js `crypto` module (for SHA-256 hashing, RSA key pair generation, RSA signing).
* **Frontend:** HTML, CSS, Vanilla JavaScript
* **Key Libraries:**
    * `bcrypt`: For password hashing.
    * `express-session` & `connect-sqlite3`: For session management.
    * `express-validator`: For server-side input validation.
    * `signature_pad` (by Szymon Nowak): For the canvas-based signature drawing on the frontend.

## Setup and Installation

To run this project locally:

1.  **Prerequisites:**
    * Node.js (which includes npm) installed on your system.
    * Git installed on your system.

2.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/1tonight/crypto.git](https://github.com/1tonight/crypto.git) 
    cd crypto 

3.  **Install Dependencies:**
    Navigate to the project's root directory (where `package.json` is located) and run:
    ```bash
    npm install
    ```

4.  **Database Initialization & Admin User Creation:**
    * **Important:** If a `permissions.db` or `sessions.db` file exists from a previous run, delete it for a clean setup.
    * Run the server **once** to create the database schema:
        ```bash
        node server.js
        ```
        Wait for the confirmation, then stop the server (Ctrl+C).
    * Create your initial admin user (edit `create-admin.js` to set your desired email and password first):
        ```bash
        node create-admin.js
        ```

5.  **Run the Application:**
    ```bash
    node server.js
    ```
    The application should now be running at `http://localhost:3000`.

## How to Use

1.  Open your web browser and navigate to `http://localhost:3000`.
2.  **Admin:**
    * Click "Access Admin Panel" and log in with the credentials you set up via `create-admin.js`.
    * Create new permission slip forms.
    * View the list of forms and their status. You can click "View Audit" to see the logged events, including the digital signature creation and the document hash.
3.  **Parent:**
    * Click "Access Parent Portal."
    * Enter the email address associated with a form created by the admin.
    * Click "View & Sign" for a pending form.
    * In the modal, type your name, draw your signature on the canvas, and check the consent box.
    * Click "Submit Digital Signature." The backend will generate an RSA key pair for this parent (if one doesn't exist), hash the form data, sign the hash with the private key, and store the cryptographic signature.

## Next Steps / Future Improvements

* **Implement Digital Signature Verification:** Allow admins to click a "Verify Signature" button which uses the parent's public key to cryptographically verify the stored digital signature against the form data.
* **Environment Variables:** Move sensitive configurations (like `SESSION_SECRET`, `PORT`) to a `.env` file.
* **Enhanced UI/UX:** Improve the visual design and user feedback.
* **PDF Generation:** Generate a downloadable PDF of the signed permission slip, potentially embedding the visual signature and a record of the digital signature verification status.
* **More Robust Key Management:** Explore more secure ways to handle private keys for a real-world scenario.

---
