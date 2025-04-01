const router = require('express').Router();
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const auth = require('../middleware/auth');
const fs = require('fs');
const path = require('path');

// Initialize Cloudinary with direct values
cloudinary.config({
  cloud_name: 'dgip6aby7',
  api_key: '482884346458396',
  api_secret: 'SgL85Zb0_4k3jITUjEoNetlYab8'
});

// Verify Cloudinary configuration
const config = cloudinary.config();
console.log('Cloudinary Configuration Status:', {
  hasCloudName: !!config.cloud_name,
  hasApiKey: !!config.api_key,
  hasApiSecret: !!config.api_secret
});

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, '../uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configure local storage first
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

// Configure multer with local storage
const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  }
});

// Register route
router.post('/register', upload.single('profileImage'), async (req, res) => {
  try {
    console.log('Registration request body:', req.body);
    const { username, email, password, preferences } = req.body;

    // Validate required fields
    if (!username || !email || !password) {
      if (req.file) fs.unlinkSync(req.file.path);
      return res.status(400).json({ message: 'Username, email, and password are required' });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      if (req.file) fs.unlinkSync(req.file.path);
      return res.status(400).json({ message: 'Invalid email format' });
    }

    // Check for existing user
    const existingUser = await User.findOne({ 
      $or: [
        { email: email.toLowerCase() }, 
        { username: username.toLowerCase() }
      ] 
    });

    if (existingUser) {
      if (req.file) fs.unlinkSync(req.file.path);
      return res.status(400).json({ 
        message: existingUser.email === email.toLowerCase() 
          ? 'Email already registered' 
          : 'Username already taken'
      });
    }

    // Handle profile image upload
    let profileImageUrl = '';
    if (req.file) {
      try {
        const result = await cloudinary.uploader.upload(req.file.path);
        profileImageUrl = result.secure_url;
        fs.unlinkSync(req.file.path);
      } catch (uploadError) {
        console.error('Cloudinary upload error:', uploadError);
        if (req.file) fs.unlinkSync(req.file.path);
        return res.status(500).json({ message: 'Failed to upload image' });
      }
    }

    // Parse preferences
    let parsedPreferences = [];
    try {
      parsedPreferences = preferences ? JSON.parse(preferences) : [];
    } catch (error) {
      console.error('Error parsing preferences:', error);
    }

    // Create new user
    const user = new User({
      username: username.trim(),
      email: email.toLowerCase().trim(),
      password,
      preferences: parsedPreferences,
      profileImage: profileImageUrl
    });

    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '7d' }
    );

    res.status(201).json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        profileImage: user.profileImage,
        preferences: user.preferences
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    if (req.file) fs.unlinkSync(req.file.path);
    res.status(500).json({ 
      message: 'Failed to create account', 
      error: error.message 
    });
  }
});

// Login route
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate required fields
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }

    // Find user and check password
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        profileImage: user.profileImage,
        preferences: user.preferences
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Profile update route
router.put('/profile', auth, upload.single('profileImage'), async (req, res) => {
  try {
    console.log('Profile update request received:', req.body);
    const { username, email, currentPassword, newPassword, preferences } = req.body;
    const userId = req.user.id;

    const user = await User.findById(userId);
    if (!user) {
      if (req.file) fs.unlinkSync(req.file.path);
      return res.status(404).json({ message: 'User not found' });
    }

    // Handle file upload to Cloudinary if there's a file
    if (req.file) {
      try {
        const result = await cloudinary.uploader.upload(req.file.path);
        if (user.profileImage) {
          try {
            const publicId = user.profileImage.split('/').pop().split('.')[0];
            await cloudinary.uploader.destroy(publicId);
          } catch (deleteError) {
            console.error('Error deleting old image:', deleteError);
          }
        }
        user.profileImage = result.secure_url;
        fs.unlinkSync(req.file.path);
      } catch (uploadError) {
        console.error('Cloudinary upload error:', uploadError);
        if (req.file) fs.unlinkSync(req.file.path);
        return res.status(500).json({ message: 'Failed to upload image' });
      }
    }

    // Password validation and update
    if (newPassword || currentPassword) {
      if (!currentPassword) {
        return res.status(400).json({ message: 'Current password is required to change password' });
      }

      const isMatch = await user.comparePassword(currentPassword);
      if (!isMatch) {
        return res.status(400).json({ message: 'Current password is incorrect' });
      }

      if (newPassword) {
        user.password = newPassword;
      }
    }

    // Username validation and update
    if (username) {
      const existingUser = await User.findOne({ 
        _id: { $ne: userId }, 
        username: username.toLowerCase() 
      });
      if (existingUser) {
        return res.status(400).json({ message: 'Username already taken' });
      }
      user.username = username.trim();
    }

    // Email validation and update
    if (email) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).json({ message: 'Invalid email format' });
      }

      const existingUser = await User.findOne({ 
        _id: { $ne: userId }, 
        email: email.toLowerCase() 
      });
      if (existingUser) {
        return res.status(400).json({ message: 'Email already registered' });
      }
      user.email = email.toLowerCase().trim();
    }

    // Preferences validation and update
    if (preferences) {
      try {
        const parsedPreferences = JSON.parse(preferences);
        if (!Array.isArray(parsedPreferences)) {
          throw new Error('Preferences must be an array');
        }
        if (parsedPreferences.length < 2) {
          throw new Error('Please select at least 2 preferences');
        }
        user.preferences = parsedPreferences;
      } catch (error) {
        console.error('Error handling preferences:', error);
        return res.status(400).json({ message: error.message });
      }
    }

    await user.save();
    console.log('Profile updated successfully for user:', user._id);

    res.json({
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        profileImage: user.profileImage,
        preferences: user.preferences
      }
    });
  } catch (error) {
    console.error('Profile update error:', error);
    if (req.file) fs.unlinkSync(req.file.path);
    res.status(500).json({ 
      message: 'Failed to update profile', 
      error: error.message 
    });
  }
});

// Delete profile image route
router.delete('/profile/image', auth, async (req, res) => {
  try {
    const userId = req.user.id;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (user.profileImage) {
      try {
        const publicId = user.profileImage.split('/').pop().split('.')[0];
        await cloudinary.uploader.destroy(publicId);
        user.profileImage = '';
        await user.save();
      } catch (error) {
        console.error('Error deleting image from Cloudinary:', error);
        return res.status(500).json({ message: 'Failed to delete image' });
      }
    }

    res.json({
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        profileImage: user.profileImage,
        preferences: user.preferences
      }
    });
  } catch (error) {
    console.error('Profile image deletion error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

module.exports = router;