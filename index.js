require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const app = express();
const port = process.env.PORT || 5000;

// Use CORS 
app.use(cors({
  origin: [
    "https://ph-event-chandonkumar23s-projects.vercel.app",
    "http://localhost:5173",
    "https://event-149a2.web.app"
  ],
}));

app.use(express.json());

const uri = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

let usersCollection;
let eventsCollection;

async function run() {
  try {
    await client.connect();
    const db = client.db("eventDB");
    usersCollection = db.collection("users");
    eventsCollection = db.collection("events");
    console.log(" Connected to MongoDB");
  } catch (err) {
    console.error(" MongoDB connection error:", err);
  }
}
run();

// JWT Middleware
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
    console.error("JWT error:", err);
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
};

// Routes

// Signup
app.post('/signup', async (req, res) => {
  if (!usersCollection) return res.status(503).json({ message: "Server not ready" });

  const { username, email, photoUrl, password } = req.body;

  try {
    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) return res.status(409).json({ message: 'Email already in use' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await usersCollection.insertOne({
      username,
      email,
      photoUrl,
      password: hashedPassword,
      createdAt: new Date()
    });

    const token = jwt.sign({ userId: result.insertedId, email }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      message: 'Signup successful',
      token,
      user: {
        id: result.insertedId,
        username,
        email,
        photoUrl
      }
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Login
app.post('/login', async (req, res) => {
  if (!usersCollection) return res.status(503).json({ message: "Try again or reload" });

  const { email, password } = req.body;

  try {
    const user = await usersCollection.findOne({ email });
    if (!user) return res.status(401).json({ message: 'User not found' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid password' });

    const token = jwt.sign({ userId: user._id.toString(), email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    res.status(200).json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        photoUrl: user.photoUrl || null,
      },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
});

// Logged-in user info
app.get('/api/user/me', authenticateJWT, (req, res) => {
  res.json(req.user);
});

// Add Event
app.post('/api/events', async (req, res) => {
  if (!eventsCollection) return res.status(503).json({ message: "Server not ready" });

  const { title, name, dateTime, location, description, attendeeCount, email } = req.body;

  if (!title || !name || !dateTime || !location || !description || !email) {
    return res.status(400).json({ message: 'All fields including email are required' });
  }

  try {
    const result = await eventsCollection.insertOne({
      title,
      name,
      dateTime,
      location,
      description,
      attendeeCount: parseInt(attendeeCount) || 0,
      email,
      createdAt: new Date()
    });

    res.status(201).json({ message: 'Event added successfully', eventId: result.insertedId });
  } catch (err) {
    console.error("Add event error:", err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get All Events
app.get('/api/events', async (req, res) => {
  if (!eventsCollection) return res.status(503).json({ message: "Server not ready" });

  try {
    const events = await eventsCollection.find().sort({ createdAt: -1 }).toArray();
    res.status(200).json(events);
  } catch (err) {
    console.error("Get events error:", err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Join Event
app.patch("/api/events/join/:id", async (req, res) => {
  if (!eventsCollection) return res.status(503).json({ message: "Server not ready" });

  const { id } = req.params;
  try {
    const result = await eventsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $inc: { attendeeCount: 1 } }
    );
    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: "Event not found" });
    }
    res.status(200).json({ message: "Joined event successfully" });
  } catch (err) {
    console.error("Join event error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// My Events by email
app.get('/api/events/:email', async (req, res) => {
  if (!eventsCollection) return res.status(503).json({ message: "Server not ready" });

  try {
    const email = req.params.email;
    const events = await eventsCollection.find({ email }).toArray();
    res.send(events);
  } catch (err) {
    console.error("Get my events error:", err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Update Event
app.put('/api/events/:id', async (req, res) => {
  if (!eventsCollection) return res.status(503).json({ message: "Server not ready" });

  const { id } = req.params;
  const updatedData = req.body;

  try {
    const result = await eventsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updatedData }
    );

    if (result.modifiedCount > 0) {
      res.send({ message: 'Event updated successfully' });
    } else {
      res.status(404).send({ message: 'Event not found or already up to date' });
    }
  } catch (error) {
    console.error("Error updating event:", error);
    res.status(500).send({ message: 'Failed to update event' });
  }
});

// Delete Event
app.delete('/api/events/:id', async (req, res) => {
  if (!eventsCollection) return res.status(503).json({ message: "Server not ready" });

  const { id } = req.params;

  try {
    const result = await eventsCollection.deleteOne({ _id: new ObjectId(id) });

    if (result.deletedCount > 0) {
      res.send({ message: 'Event deleted successfully' });
    } else {
      res.status(404).send({ message: 'Event not found' });
    }
  } catch (error) {
    console.error("Error deleting event:", error);
    res.status(500).send({ message: 'Failed to delete event' });
  }
});

// Root
app.get('/', (req, res) => {
  res.send("🎉 Event management server is running!");
});

app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
});
