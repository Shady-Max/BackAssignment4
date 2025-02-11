const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const dotenv = require('dotenv');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

require('dotenv').config();

const saltRounds = 10;
const MAX_ATTEMPTS = 5;
const LOCK_TIME = 10 * 60 * 1000;

const storage = multer.diskStorage({
    destination: './public/uploads/',  // Store files in "public/uploads"
    filename: (req, file, cb) => {
        cb(null, req.session.userId + path.extname(file.originalname)); // Unique filename
    }
})

const upload = multer({
    storage,
    limits: { fileSize: 2 * 1024 * 1024 }, // Limit file size to 2MB
    fileFilter: (req, file, cb) => {
        const fileTypes = /jpeg|jpg|png|gif/;
        const extname = fileTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = fileTypes.test(file.mimetype);

        if (mimetype && extname) {
            return cb(null, true);
        } else {
            return cb(new Error('Only images (JPG, PNG, GIF) are allowed!'));
        }
    }
}).single('profilePicture');

const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.log('MongoDB connection error:', err));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true
}));

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: {type: String, required: true },
    name: {type: String, required: true},
    loginAttempts: {type: Number, required: true, default: 0},
    lockUntil: { type: Date },
    profilePicture: { type: String, default: 'default.png' }
});

userSchema.methods.isLocked = function () {
    return this.lockUntil && this.lockUntil > Date.now();
}

const User = mongoose.model('User', userSchema);

function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        return next();
    } else {
        res.redirect('/login');
    }
}

app.get('/', isAuthenticated, async (req, res) => {
    const user = await User.findById(req.session.userId);
    res.render('home', { user: user });
})

app.get('/register', (req, res) => {
    res.render('register', {errorMessage: null});
})

app.post('/register', (req, res) => {
    const { email, password, name } = req.body;

    if (!email || !password || !name) {
        return res.render('register', { errorMessage: 'All fields are required.' });
    }

    const emailRegex = /\S+@\S+\.\S+/; // Simple email format validation
    if (!emailRegex.test(email)) {
        return res.render('register', { errorMessage: 'Please enter a valid email.' });
    }

    if (password.length < 6) {
        return res.render('register', { errorMessage: 'Password must be at least 6 characters long.' });
    }

    User.findOne({ email: email })
        .then(existingUser => {
            if (existingUser) {
                return res.render('register', { errorMessage: 'Email already exists.' });
            }

            // Hash password and create new user
            bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
                if (err) {
                    return res.status(500).send('Error hashing password');
                }

                const newUser = new User({ email, password: hashedPassword, name });
                newUser.save()
                    .then(() => res.redirect('/login'))
                    .catch(err => res.status(500).send('Error saving user'));
            });
        })
        .catch(err => res.status(500).send('Error checking user'));
})

app.get('/login', (req, res) => {
    res.render('login', {errorMessage: null});
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.render('login', { errorMessage: 'Both fields are required.' });
    }

    // Check if user exists
    User.findOne({ email: email })
        .then(async (user) =>{
            if (!user) {
                return res.render('login', { errorMessage: 'Invalid email or password' });
            }

            if (user.isLocked()) {
                if (user.lockUntil < Date.now()) {
                    user.loginAttempts = 0;
                    user.lockUntil = undefined;
                    await user.save();
                } else {
                    return res.render('login', {errorMessage: 'Your account is locked. Try again later'});
                }
            }

            // Compare passwords
            bcrypt.compare(password, user.password, async (err, isMatch) => {
                if (err || !isMatch) {
                    user.loginAttempts += 1;
                    if (user.loginAttempts >= MAX_ATTEMPTS) {
                        user.lockUntil = Date.now() + LOCK_TIME;
                    }
                    await user.save();
                    return res.render('login', { errorMessage: 'Invalid email or password' });
                }
                user.loginAttempts = 0;
                user.lockUntil = undefined;
                await user.save();
                req.session.userId = user._id;
                res.redirect('/');
            });
        })
        .catch(err => res.status(500).send('Error during login'));
})

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
})

app.get('/profile', isAuthenticated, async (req, res) => {
    const user = await User.findById(req.session.userId);
    res.render('profile', { user: user });
})

app.post('/update-profile', async (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    const { email, name } = req.body;
    const user = await User.findById(req.session.userId);

    // Update user data
    user.email = email || user.email;
    user.name = name || user.name;

    await user.save();
    res.redirect('/profile');
})

app.post('/upload-profile', (req, res) => {
    if (!req.session.userId) {
        return res.status(403).send("Unauthorized. Please log in.");
    }

    upload(req, res, async (err) => {
        if (err) {
            return res.status(400).send(err.message);
        }

        // Update user profile picture in database
        const user = await User.findById(req.session.userId);
        user.profilePicture = `/uploads/${req.file.filename}`; // Store relative path
        await user.save();

        res.redirect('/profile');
    });
})

app.post('/delete-profile-picture', async (req, res) => {
    if (!req.session.userId) {
        return res.status(403).send("Unauthorized. Please log in.");
    }

    const user = await User.findById(req.session.userId);

    // Prevent deletion of default profile picture
    if (user.profilePicture !== '/uploads/default.png') {
        const filePath = `./public${user.profilePicture}`;

        // Check if the file exists before attempting to delete
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }

        // Reset profile picture to default
        user.profilePicture = '/uploads/default.png';
        await user.save();
    }

    res.redirect('/profile');
})

app.post('/delete-account', async (req, res) => {
    if (!req.session.userId) {
        return res.status(403).send("Unauthorized. Please log in.");
    }

    const user = await User.findById(req.session.userId);

    // Remove profile picture if it's not the default
    if (user.profilePicture !== '/uploads/default.jpg') {
        const filePath = `./public${user.profilePicture}`;

        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }
    }

    // Delete the user from the database
    await User.findByIdAndDelete(req.session.userId);

    // Destroy session and redirect to home
    req.session.destroy(() => {
        res.redirect('/');
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
})