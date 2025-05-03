const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors({
    origin: 'https://expenses-frontend-manjusha1002s-projects.vercel.app/',
    credentials: true
}));
app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err.message));

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const expenseSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    amount: Number,
    category: String,
    description: String,
    date: Date
});

const User = mongoose.model('User', userSchema);
const Expense = mongoose.model('Expense', expenseSchema);

const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) return res.status(401).send('Access Denied');
    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch {
        res.status(400).send('Invalid Token');
    }
};

app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashed });
    await user.save();
    res.status(201).send('User registered');
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).send('Invalid credentials');
    }
    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET);
    res.send({ token });
});

app.post('/expenses', authMiddleware, async (req, res) => {
    const expense = new Expense({ ...req.body, userId: req.user._id });
    await expense.save();
    res.status(201).send(expense);
});

app.get('/expenses', authMiddleware, async (req, res) => {
    const expenses = await Expense.find({ userId: req.user._id });
    res.send(expenses);
});

app.put('/expenses/:id', authMiddleware, async (req, res) => {
    const expense = await Expense.findOneAndUpdate(
        { _id: req.params.id, userId: req.user._id },
        req.body,
        { new: true }
    );
    res.send(expense);
});

app.delete('/expenses/:id', authMiddleware, async (req, res) => {
    await Expense.findOneAndDelete({ _id: req.params.id, userId: req.user._id });
    res.sendStatus(204);
});

app.listen(process.env.PORT || 5000, () => console.log('Backend running', `http://localhost:${process.env.PORT}`));
