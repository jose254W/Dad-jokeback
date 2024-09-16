require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const Groq = require("groq-sdk");
const https = require('https');

const app = express();

app.use(bodyParser.json());
app.use(cors());

mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

const conversationSchema = new mongoose.Schema({
  userId: String,
  title: String,
  messages: [{
    role: String,
    content: String,
    timestamp: { type: Date, default: Date.now }
  }]
});

const Conversation = mongoose.model('Conversation', conversationSchema);

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

const dadJokeSystemMessage = {
    role: 'system',
    content: `You are an AI assistant specializing in dad jokes. Your primary function is to:
  
  1. Tell dad jokes: Provide classic, groan-worthy dad jokes on request.
  2. Explain dad jokes: If asked, break down why a dad joke is funny (or not).
  3. Generate dad jokes: Create new dad jokes based on given topics or themes.
  4. Rate dad jokes: If a user shares a dad joke, rate it on a scale of 1 to 10 for "dad-ness".
  
  Remember, the corniest jokes are often the best dad jokes. Keep it family-friendly and don't be afraid to throw in some puns!`
  };

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Function to generate speech using VoiceRSS API
const generateSpeech = (text) => {
  return new Promise((resolve, reject) => {
    console.log("Generating speech for text:", text);

    const options = {
      method: 'POST',
      hostname: 'voicerss-text-to-speech.p.rapidapi.com',
      port: null,
      path: '/',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        'X-RapidAPI-Key': process.env.VOICERSS_API_KEY,
        'X-RapidAPI-Host': 'voicerss-text-to-speech.p.rapidapi.com'
      }
    };

    const req = https.request(options, function (res) {
      console.log("Request made to VoiceRSS API");

      const chunks = [];

      res.on('data', function (chunk) {
        console.log("Receiving data chunk...");
        chunks.push(chunk);
      });

      res.on('end', function () {
        console.log("Response from VoiceRSS received.");
        const body = Buffer.concat(chunks);
        console.log("Audio data length:", body.length);
        resolve(body);
      });
    });

    req.on('error', (error) => {
      console.error("Error with VoiceRSS request:", error);
      reject(error);
    });

    const postData = new URLSearchParams({
      src: text,
      hl: 'en-us',
      v: 'Mary',
      r: '0',
      c: 'mp3',
      f: '8khz_8bit_mono'
    }).toString();

    console.log("Sending request to VoiceRSS with text:", text);
    
    req.write(postData);
    req.end();
  });
};

app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ error: 'Error registering user' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user && await bcrypt.compare(password, user.password)) {
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.json({ token });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ error: 'Error logging in' });
  }
});

app.post('/api/chat', authenticateToken, async (req, res) => {
  const startTime = Date.now();
  const { message, conversationId } = req.body;
  const userId = req.user.id;

  try {
    const chatHistoryTime = Date.now();
    let conversation;
    if (conversationId) {
      conversation = await Conversation.findOne({ _id: conversationId, userId });
    } else {
      conversation = new Conversation({ userId, title: 'Dad Jokes Conversation', messages: [] });
    }
    if (!conversation) {
      return res.status(404).json({ error: 'Conversation not found' });
    }
    console.log(`Chat history retrieval time: ${Date.now() - chatHistoryTime}ms`);

    conversation.messages.push({ role: 'user', content: message });

    const aiRequestTime = Date.now();
    const completion = await groq.chat.completions.create({
      messages: [
        dadJokeSystemMessage,
        ...conversation.messages.map(msg => ({ role: msg.role, content: msg.content }))
      ],
      model: "llama3-8b-8192",
    });
    console.log(`AI API request time: ${Date.now() - aiRequestTime}ms`);

    const responseMessage = completion.choices[0]?.message?.content || "";

    // Generate audio for the response
    const audioContent = await generateSpeech(responseMessage);

    conversation.messages.push({ role: 'assistant', content: responseMessage });

    const saveTime = Date.now();
    await conversation.save();
    console.log(`Save chat history time: ${Date.now() - saveTime}ms`);

    res.json({ 
      response: responseMessage, 
      conversationId: conversation._id,
      audioContent: audioContent.toString('base64')
    });
    console.log(`Total request time: ${Date.now() - startTime}ms`);
  } catch (error) {
    console.error('Error with Groq API or Text-to-Speech:', error);
    res.status(500).json({ error: 'Error generating response' });
  }
});

app.get('/api/conversations', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const conversations = await Conversation.find({ userId });
    res.json(conversations);
  } catch (error) {
    console.error('Error retrieving conversations:', error);
    res.status(500).json({ error: 'Error retrieving conversations' });
  }
});

app.get('/api/conversation/:id', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const conversationId = req.params.id;

  try {
    const conversation = await Conversation.findOne({ _id: conversationId, userId });
    if (conversation) {
      res.json(conversation);
    } else {
      res.status(404).json({ error: 'Conversation not found' });
    }
  } catch (error) {
    console.error('Error retrieving conversation:', error);
    res.status(500).json({ error: 'Error retrieving conversation' });
  }
});

app.delete('/api/conversation/:id', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const conversationId = req.params.id;

  if (!conversationId) {
    return res.status(400).json({ error: 'Conversation ID is required' });
  }

  try {
    const result = await Conversation.findOneAndDelete({ _id: conversationId, userId });
    if (result) {
      res.json({ message: 'Conversation deleted successfully' });
    } else {
      res.status(404).json({ error: 'Conversation not found or you do not have permission to delete it' });
    }
  } catch (error) {
    console.error('Error deleting conversation:', error);
    if (error.name === 'CastError' && error.kind === 'ObjectId') {
      res.status(400).json({ error: 'Invalid conversation ID format' });
    } else {
      res.status(500).json({ error: 'Error deleting conversation', details: error.message });
    }
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});