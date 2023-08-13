# jwt-authentication

This is web application that focuses on user Authentication and authorization using technologies like:
1. Express.js
2. Passport.js
3. JWT (JSON Web Tokens)
4. MongoDB

The project's main goal is to provide a secure and user-friendly authentication system for users to register, log in, reset passwords, and access protected routes. Additionally, the project integrates Google OAuth for third-party authentication.

# Features

1. **User Registration:** New users can create accounts by providing their email and password. Passwords are securely hashed before being stored in the database.

2. **Login:** Registered users can log in using their email and password. Additionally, third-party authentication is available through Google OAuth 2.0.

3. **Protected Routes:** Certain routes are protected and can only be accessed by authenticated users. Unauthorized access redirects to the login page.

4. **JWT-Based Authentication:** JSON Web Tokens (JWT) are utilized to manage user sessions. Tokens are sent as part of the request headers for authentication and to access protected routes.

5. **Token Expiry and Renewal:** JWT tokens have a limited lifespan for security. If a token is about to expire, the server automatically renews it to ensure uninterrupted user sessions.

6. **Logout and Session Termination:** Users can log out, which destroys their session and prevents access to protected routes.

7. **Password Reset:** Users who forget their passwords can request a password reset. An email with a reset link is sent, allowing users to set a new password.

8. **Blacklist Tokens:** To enhance security, revoked or compromised tokens can be blacklisted, preventing unauthorized access.

9. **Swagger docs:** For a better understanding of the api endpoints and how they work documentation is provided.

# API Endpoints

1. **POST /user/register:** Create a new user account by providing the required information.
2. **POST /user/login:** Log in with a registered account using email and password.
3. **GET /user/logout:** Log out and destroy the user session.
4. **POST /user/resetPassword:** Reset the user's password by providing a new password.
5. **GET /user/getUser/:id?:** Retrieve user profile information. If an ID is provided, fetch the profile of a specific user.
6. **GET /auth/google:** Initiate Google OAuth 2.0 authentication.
7. **GET /auth/google/callback:** Callback endpoint for Google OAuth 2.0 authentication.
8. **GET /auth/google/success:** Success page after successful Google OAuth authentication.
9. **GET /auth/google/failure:** Page indicating an error during Google OAuth authentication.
10. **/docs:** Api documentation done through swagger ui.

# Getting Started

To use the authentication features of this project, follow these steps:

1. Clone the repository and install dependencies.

2. Configure your environment variables in a .env file, including your MongoDB connection URL, Google OAuth credentials, and session secret.

3. Run the application using npm start or your preferred method.

4. Explore the API endpoints to integrate authentication into your application.

# Screenshot of docs

![image](https://github.com/Ankur5522/jwt-authentication/assets/121228725/e661f660-fb43-406f-b073-7897c248e2c1)


    



