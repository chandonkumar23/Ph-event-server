require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const uri = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

let usersCollection;

async function run() {
    try {
        await client.connect();
        const db = client.db("eventDB");
        usersCollection = db.collection("users");
        console.log(" Connected to MongoDB");
    } catch (err) {
        console.error(" MongoDB connection error:", err);
    }
}
run();


// 🔐 JWT Middleware

const authenticateJWT = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: 'Authorization header missing' });

    const token = authHeader.split(" ")[1];
    if (!token) return res.status(401).json({ message: 'Token missing' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await usersCollection.findOne({ _id: new ObjectId(decoded.userId) });

        if (!user) return res.status(401).json({ message: 'User not found' });

        req.user = {
            id: user._id,
            username: user.username,
            email: user.email,
            photoUrl: user.photoUrl,
        };

        next();
    } catch (err) {
        console.error(" JWT error:", err);
        return res.status(403).json({ message: 'Invalid or expired token' });
    }
};


//  Signup Route

app.post('/signup', async (req, res) => {
    const { username, email, photoUrl, password } = req.body;

    try {
        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ message: 'Email already in use' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await usersCollection.insertOne({
            username,
            email,
            photoUrl,
            password: hashedPassword,
            createdAt: new Date()
        });

        res.status(201).json({
            message: 'User registered successfully',
            userId: result.insertedId
        });
    } catch (err) {
        console.error(" Signup error:", err);
        res.status(500).json({ message: 'Internal server error' });
    }
});


//  Login Route

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await usersCollection.findOne({ username });
        if (!user) return res.status(401).json({ message: 'User not found' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: 'Invalid password' });

        const token = jwt.sign(
            { userId: user._id, username: user.username },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(200).json({
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                photoUrl: user.photoUrl
            }
        });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ message: 'Internal server error' });
    }
});


//  Get Logged-In User

app.get('/api/user/me', authenticateJWT, (req, res) => {
    res.json(req.user); // req.user is set by the JWT middleware
});

app.get('/', (req, res) => {
    res.send(" Event management server is running!");
});

app.listen(port, () => {
    console.log(` Server running on http://localhost:${port}`);
});
