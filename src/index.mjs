import express from 'express';
import bodyParser from 'body-parser';
import dotenv from 'dotenv';
import { CognitoIdentityProviderClient, SignUpCommand, ConfirmSignUpCommand } from "@aws-sdk/client-cognito-identity-provider";
import crypto from "crypto";

dotenv.config();
const app = express();
app.use(bodyParser.json());

const poolData = {
    UserPoolId: process.env.AWS_COGNITO_USER_POOL_ID,
    ClientId: process.env.AWS_COGNITO_CLIENT_ID
};

const generateSecretHash = (username, clientId, clientSecret) => {
    return crypto.createHmac("sha256", clientSecret)
        .update(username + clientId)
        .digest("base64");
};

const client = new CognitoIdentityProviderClient({ region: "eu-west-2" });
//const userPool = new CognitoUserPool(poolData);

// Login Route
// app.post('/login', (req, res) => {
//     const { email, password } = req.body;

//     const user = new CognitoUser({ Username: email, Pool: userPool });
//     const authDetails = new AuthenticationDetails({ Username: email, Password: password });

//     user.authenticateUser(authDetails, {
//         onSuccess: session => {
//             res.json({ message: 'Login successful', token: session.getIdToken().getJwtToken() });
//         },
//         onFailure: err => {
//             res.status(400).json({ error: err.message });
//         }
//     });
// });

// // Logout Route
// app.post('/logout', (req, res) => {
//     const { email } = req.body;
//     const user = new CognitoUser({ Username: email, Pool: userPool });

//     user.signOut();
//     res.json({ message: 'Logout successful' });
// });

app.post('/login', async (req, res) => {
    const { email, confirmCode } = req.body;
    const clientSecret = process.env.AWS_COGNITO_CLIENT_SECRET;
    const secretHash = generateSecretHash(email, poolData.ClientId, clientSecret);

    const params = {
        ClientId: poolData.ClientId,
        Username: email,
        ConfirmationCode: confirmCode,
        SecretHash: secretHash,
    };

    try {
        const command = new ConfirmSignUpCommand(params);
        const result = await client.send(command);
        res.json({ message: 'Verified email.', result });
    } catch (err) {
        console.error("Error during sign-up:", err);
        res.status(400).json({ error: err.message });
    }
});

app.post('/verify', async (req, res) => {
    const { email, confirmCode } = req.body;
    const clientSecret = process.env.AWS_COGNITO_CLIENT_SECRET;
    const secretHash = generateSecretHash(email, poolData.ClientId, clientSecret);

    const params = {
        ClientId: poolData.ClientId,
        Username: email,
        ConfirmationCode: confirmCode,
        SecretHash: secretHash,
    };

    try {
        const command = new ConfirmSignUpCommand(params);
        const result = await client.send(command);
        res.json({ message: 'Verified email.', result });
    } catch (err) {
        console.error("Error during sign-up:", err);
        res.status(400).json({ error: err.message });
    }
});

app.post('/register', async (req, res) => {
    const { email, password, name } = req.body;
    const clientSecret = process.env.AWS_COGNITO_CLIENT_SECRET;
    const secretHash = generateSecretHash(email, poolData.ClientId, clientSecret);

    const params = {
        ClientId: poolData.ClientId,
        Username: email,
        Password: password,
        SecretHash: secretHash,
        UserAttributes: [
            { Name: 'email', Value: email },
            { Name: 'name', Value: name }
        ]
    };

    try {
        const command = new SignUpCommand(params);
        const result = await client.send(command);
        res.json({ message: 'Registration successful, confirm your email.', result });
    } catch (err) {
        console.error("Error during sign-up:", err);
        res.status(400).json({ error: err.message });
    }
});

// Start Server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});