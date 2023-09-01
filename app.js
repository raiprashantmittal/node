const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const mongoose = require('mongoose');
const db = require('./db');
const User = require('./user');

const app = express();
const PORT = 4000;

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));
app.use(bodyParser.json());

mongoose.connect('mongodb://localhost:27017/signupFormDB', {
    useNewUrlParser: true,
    useUnifiedTopology: true
  })
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch(err => {
    console.error('Error connecting to MongoDB:', err);
  });

app.set('view engine', 'ejs');

function generateResetToken() {
  const token = crypto.randomBytes(32).toString('hex');
  return token;
}

app.get('/', (req, res) => {
  res.render('signup');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/reset', (req, res) => {
  res.render('reset');
});

app.get('/new_pass', (req, res) => {
  res.render('new_pass');
});

app.get('/dashboard', (req, res) => {
  res.render('dashboard');
});

app.get('/editprofile', (req, res) => {
  res.render('editprofile');
});

app.post('/signup', async (req, res) => {
  if (!req.body.username || !req.body.password) return res.send(401).send("Some data not found");
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    const newUser = new User({
      username: req.body.username,
      email: req.body.email,
      password: hashedPassword,
    });

    await newUser.save();
    res.status(200).send('User registered successfully');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error saving user to the database');
  }
});

app.post('/login', async (req, res) => {
  try {
    const user = await User.findOne({
      username: req.body.username
    });

    if (user) {
      const passwordMatch = await bcrypt.compare(req.body.password, user.password);

      if (passwordMatch) {
        res.status(200).redirect('/dashboard');
      } else {
        res.status(401).send('Incorrect password');
      }
    } else {
      res.status(404).send('User not found');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Login error');
  }
});

app.post('/reset', async (req, res) => {
  try {
    const user = await User.findOne({
      email: req.body.email
    });

    if (user) {
      const resetToken = generateResetToken();
      user.resetToken = resetToken;
      await user.save();

      res.redirect(`/new_pass?token=${resetToken}`);
    } else {
      res.status(404).json({
        message: 'Email Address is invalid'
      });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: 'Internal server error'
    });
  }
});

app.post('/new_pass', async (req, res) => {
  try {
    const token = req.body.token;
    const newPassword = req.body.password;

    const user = await User.findOne({
      resetToken: token
    });

    if (user) {
      const saltRounds = 10;
      const salt = await bcrypt.genSalt(saltRounds)

      const hashedPassword = await bcrypt.hash(newPassword, salt);

      user.password = hashedPassword;
      user.resetToken = undefined;
      await user.save();

      res.status(200).json({
        message: 'Password reset successful'
      });
    } else {
      res.status(401).json({
        message: 'Invalid token'
      });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: 'Reset password error'
    });
  }
});

app.post('/editprofile', async (req, res) => {
  const {
    newUsername
  } = req.body;
  if (!newUsername) {
    return res.status(400).json({
      message: 'New username is required'
    });
  }

  try {
    // Find the user by their existing username
    const user = await User.findOne({
      username: req.body.currentUsername
    });

    if (!user) {
      return res.status(404).json({
        message: 'User not found'
      });
    }

    user.username = newUsername;

    await user.save();

    res.status(200).json({
      message: 'Username updated successfully',
      user
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: 'Error updating username',
      error: err.message
    });
  }
});


app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});