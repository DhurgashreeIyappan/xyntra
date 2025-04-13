const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');

const app = express();
const PORT = 5000;

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'mugiwaranoluffy004m@gmail.com',
    pass: 'fljf xrbm fhqe nbjo'
  }
});

// ✅ Middleware
app.use(cors());
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// ✅ MongoDB Connect
mongoose.connect('mongodb://127.0.0.1:27017/aftervault')
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// ✅ Multer File Upload Setup
const upload = multer({ dest: 'uploads/' });

// ========== SCHEMAS ==========
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  phone: String,
  dob: String,
  password: String,
  inactiveDays: Number,
  otp: { type: String, default: null },
  otpExpiry: { type: Date, default: null },
  lastLoginDate: {type: Date,default: null}
});

const User = mongoose.model('User', userSchema);

// Admin Schema
const adminSchema = new mongoose.Schema({
  email: String,
  password: String, // or hashedPassword if you hash it later
  otp: { type: String, default: null },
  otpExpiry: { type: Date, default: null }
});
const Admin = mongoose.model('Admin', adminSchema);


const assetSchema = new mongoose.Schema({
  userEmail: String,
  docName: String,
  encryptedPasswordText: String,
  filePath: String,
  key: String,
  iv: String
});
const Asset = mongoose.model('Asset', assetSchema);

const trustedContactSchema = new mongoose.Schema({
  userEmail: String,
  contactName: String,
  contactEmail: String,
  relation: String,
  addedAt: { type: Date, default: Date.now }
});
const TrustedContact = mongoose.model('TrustedContact', trustedContactSchema);

const willSchema = new mongoose.Schema({
  userEmail: String,
  title: String,
  encryptedMessage: String,
  assignedTo: String,
  iv: String,
  key: String,
  createdAt: { type: Date, default: Date.now }
});
const Will = mongoose.model('Will', willSchema);

// ========== ENCRYPTION HELPER ==========
function encrypt(data, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  return { encryptedData: encrypted.toString('hex'), iv: iv.toString('hex') };
}

// ========== SIGNUP ==========
app.post('/signup', async (req, res) => {
  const { username, email, dob, phone, password } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(409).json({ message: 'Email already exists' });

    const newUser = new User({ username, email, dob, phone, password });
    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});


app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if the email belongs to an admin
    const adminEntry = await Admin.findOne({ email });
    if (adminEntry && adminEntry.password === password) {
      // Generate OTP for admin
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const expiry = new Date(Date.now() + 5 * 60 * 1000); // OTP expires in 5 minutes

      // Save OTP for admin
      await Admin.findOneAndUpdate({ email }, { otp, otpExpiry: expiry });

      // Send OTP to admin's email
      await transporter.sendMail({
        from: '"AfterVault Team" <mugiwaranoluffy004m@gmail.com>',
        to: email,
        subject: 'Your OTP for Admin Login',
        html: `<p>Your OTP is <b>${otp}</b>. It expires in 5 minutes.</p>`
      });

      return res.json({ status: 'OTP_SENT', message: 'OTP sent to your email.', redirect: '/admin-portal.html' });
    }

    // Check if the email belongs to a user
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (user.password !== password)
      return res.status(401).json({ message: 'Incorrect password' });

    // Generate OTP for user login
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = new Date(Date.now() + 5 * 60 * 1000); // OTP expires in 5 minutes

    const updatedUser = await User.findOneAndUpdate(
      { email },
      { $set: { otp, otpExpiry: expiry } },
      { new: true }
    );

    // Send OTP to user's email
    await transporter.sendMail({
      from: '"AfterVault Team" <mugiwaranoluffy004m@gmail.com>',
      to: email,
      subject: 'Your OTP for Login',
      html: `<p>Your OTP is <b>${otp}</b>. It expires in 5 minutes.</p>`
    });



    res.json({ status: 'OTP_SENT', message: 'OTP sent to your email.', redirect: '/dashboard.html' });
  } catch (err) {
    console.error('Login OTP error:', err);
    res.status(500).json({ message: 'Server error during login' });
  }
  
});

// ========== VERIFY OTP ==========

app.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  try {
    // Check if the email belongs to an admin
    const admin = await Admin.findOne({ email });
    if (admin) {
      if (admin.otp === otp && new Date() < admin.otpExpiry) {
        // ✅ Update lastLoginDate for admin
        admin.lastLoginDate = new Date();

        // Clear OTP after successful verification
        admin.otp = null;
        admin.otpExpiry = null;
        await admin.save();

        return res.json({ status: 'OK', redirect: '/admin-portal.html' });
      } else {
        return res.status(400).json({ status: 'ERROR', message: 'Invalid or expired OTP' });
      }
    }

    // Check if the email belongs to a user
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ status: 'ERROR', message: 'User not found' });

    if (user.otp === otp && new Date() < user.otpExpiry) {
      // ✅ Update lastLoginDate for user
      user.lastLoginDate = new Date();

      // Clear OTP after successful verification
      user.otp = null;
      user.otpExpiry = null;
      await user.save();

      return res.json({ status: 'OK', redirect: '/dashboard.html' });
    } else {
      return res.status(400).json({ status: 'ERROR', message: 'Invalid or expired OTP' });
    }

  } catch (err) {
    console.error('Error verifying OTP:', err);
    res.status(500).json({ status: 'ERROR', message: 'Error verifying OTP' });
  }
});




// ========== ENCRYPTED ASSET UPLOAD ==========
app.post('/upload-assets', upload.single('document'), async (req, res) => {
  try {
    const { docName, passwordText, email } = req.body;
    const documentPath = req.file.path;

    const key = crypto.randomBytes(32).toString('hex');
    const { encryptedData: encPwd, iv: ivPwd } = encrypt(passwordText || '', key);
    const fileBuffer = fs.readFileSync(documentPath);
    const { encryptedData: encFile, iv: ivFile } = encrypt(fileBuffer, key);

    const encryptedFilePath = `uploads/encrypted_${Date.now()}.pdf`;
    fs.writeFileSync(encryptedFilePath, Buffer.from(encFile, 'hex'));

    await Asset.create({
      userEmail: email,
      docName,
      encryptedPasswordText: JSON.stringify({ iv: ivPwd, data: encPwd }),
      filePath: encryptedFilePath,
      key,
      iv: ivFile
    });

    res.json({ message: 'Encrypted upload successful.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error during upload.' });
  }
});

// ========== TRUSTED CONTACTS ==========
app.get('/get-trusted-contacts', async (req, res) => {
  const { email } = req.query;
  try {
    const contacts = await TrustedContact.find({ userEmail: email });
    res.json({ contacts });
  } catch (err) {
    res.status(500).json({ message: 'Error fetching trusted contacts.' });
  }
});

app.post('/add-trusted-contact', async (req, res) => {
  const { email, contactName, contactEmail, relation } = req.body;
  if (!contactName || !contactEmail || !relation)
    return res.status(400).json({ message: 'All fields are required.' });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const newContact = new TrustedContact({
      userEmail: email,
      contactName,
      contactEmail,
      relation
    });
    await newContact.save();

    await transporter.sendMail({
      from: '"AfterVault Team" <mugiwaranoluffy004m@gmail.com>',
      to: contactEmail,
      subject: `You've been added as a Trusted Contact`,
      html: `
        <h3>Hello ${contactName},</h3>
        <p>${user.username} has added you as a <strong>trusted contact</strong> on AfterVault.</p>
        <p>They trust you to help manage their digital legacy.</p>
        <p>— AfterVault Team</p>`
    });

    res.status(201).json({ message: 'Trusted contact added and notified!' });
  } catch (err) {
    res.status(500).json({ message: 'Server error while adding trusted contact.' });
  }
});

// ========== USER PROFILE ==========
app.get('/get-user', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'Email is required' });

  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ error: 'User not found' });

  res.json(user);
});

app.put('/update-user', async (req, res) => {
  const { email, username, dob, phone } = req.body;
  try {
    const result = await User.updateOne(
      { email },
      { $set: { username, dob, phone } }
    );

    if (result.modifiedCount > 0) {
      res.json({ message: 'User updated successfully.' });
    } else {
      res.status(400).json({ message: 'No changes made.' });
    }
  } catch (err) {
    res.status(500).json({ message: 'Server error during update.' });
  }
});

// ========== SAVE WILL ==========
app.post('/save-will', async (req, res) => {
  const { title, message, assignedTo, email } = req.body;
  try {
    const key = crypto.randomBytes(32).toString('hex');
    const { encryptedData, iv } = encrypt(message, key);

    await Will.create({
      userEmail: email,
      title,
      encryptedMessage: encryptedData,
      assignedTo,
      iv,
      key
    });

    res.json({ message: 'Will saved successfully!' });
  } catch (err) {
    res.status(500).json({ message: 'Error saving will.' });
  }
});

// ========== COMBINED USER + TRUSTED CONTACTS LIST ==========

app.get('/admin/all-users-with-trusted-contacts', async (req, res) => {
  try {
    // Include lastLoginDate in the projection
    const users = await User.find({}, 'email username lastLoginDate');

    const result = await Promise.all(users.map(async (user) => {
      const contacts = await TrustedContact.find(
        { userEmail: user.email },
        'contactName contactEmail relation'
      );
      return {
        email: user.email,
        username: user.username,
        lastLoginDate: user.lastLoginDate, // Send it to frontend
        trustedContacts: contacts
      };
    }));

    res.json(result);
  } catch (err) {
    console.error('Error fetching combined data:', err);
    res.status(500).json({ message: 'Server error fetching user-contact data.' });
  }
});


const updateLoginActivity = async (email) => {
  const userCollection = db.collection("users");
  const userDoc = await userCollection.findOne({ email });

  const now = new Date();
  let inactiveDays = 0;

  if (userDoc && userDoc.lastLoginDate) {
    const lastLogin = userDoc.lastLoginDate;
    const diffTime = now - lastLogin;
    inactiveDays = Math.floor(diffTime / (1000 * 60 * 60 * 24)); // Convert time to days
  }

  await userCollection.updateOne(
    { email }, // Use email as the key
    {
      $set: {
        lastLoginDate: now,
        inactiveDays: inactiveDays,
      },
      $push: {
        loginHistory: now, // Adding the new login timestamp to loginHistory array
      },
      $setOnInsert: {
        isInactiveTrigger: inactiveDays >= 180, // Mark for post-mortem if inactive for 180+ days
      },
    }
  );
};

const updateInactiveDays = async () => {
  const userCollection = db.collection("users");
  const users = await userCollection.find({}).toArray(); // Get all users

  const now = new Date();

  // Use a bulk operation for efficiency
  const bulkOps = [];

  users.forEach((user) => {
    if (user.lastLoginDate) {
      const lastLogin = user.lastLoginDate;
      const diffDays = Math.floor((now - lastLogin) / (1000 * 60 * 60 * 24));

      bulkOps.push({
        updateOne: {
          filter: { email: user.email }, // Use email as the key
          update: {
            $set: {
              inactiveDays: diffDays,
              isInactiveTrigger: diffDays >= 180, // Mark for post-mortem actions if inactive for more than 180 days
            },
          },
        },
      });
    }
  });

  if (bulkOps.length > 0) {
    await userCollection.bulkWrite(bulkOps); // Execute the bulk update for all users
  }
};


// ========== SERVER START ==========
app.listen(PORT, () => {
  console.log(`🚀 AfterVault server live @ http://localhost:${PORT}`);
});
