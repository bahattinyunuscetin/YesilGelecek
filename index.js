require('dotenv').config();
const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

// Models
const User = require('./models/User');
const Course = require('./models/Course');
const Project = require('./models/project');
const Certificate = require('./models/certificate');
const Message = require('./models/Message');
const discussionRoutes = require('./routes/discussions');
const studentsRoutes = require('./routes/students');
const assignmentRoutes = require('./routes/assignments');
const messageRoutes = require('./routes/messages');
const { validateUserRegistration, validateUserLogin, sanitizeInput } = require('./middleware/validation');
const { authenticateToken } = require('./middleware/auth');


// Route modules (add these files as explained earlier)
const courseRoutes = require('./routes/courses');
const projectRoutes = require('./routes/projects');
const certificateRoutes = require('./routes/certificates');
const productRoutes = require('./routes/products');
const orderRoutes = require('./routes/orders');
const PDFDocument = require('pdfkit');
const multer = require('multer');
const fs = require('fs');

const app = express();

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadPath = path.join(__dirname, 'uploads', 'profiles');
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'avatar-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: function (req, file, cb) {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

// Security middleware - Configure helmet properly for static files
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
      connectSrc: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later.'
  }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 auth requests per windowMs
  message: {
    success: false,
    message: 'Too many authentication attempts, please try again later.'
  }
});

app.use(limiter);
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(sanitizeInput);
// Serve static files (HTML, CSS, JS, images) - Configure once
app.use(express.static(path.join(__dirname), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.css')) {
      res.setHeader('Content-Type', 'text/css; charset=utf-8');
    } else if (filePath.endsWith('.js')) {
      res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    } else if (filePath.endsWith('.html')) {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
    }
  }
}));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Specific route for CSS files to ensure proper MIME type
app.get('/css/:filename', (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(__dirname, 'css', filename);

  res.setHeader('Content-Type', 'text/css; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.sendFile(filePath);
});



// MongoDB Connection with retry logic
async function connectToMongoDB() {
  try {
    console.log('🔄 Attempting to connect to MongoDB...');
    await mongoose.connect(process.env.MONGODB_URI, {
      serverSelectionTimeoutMS: 5000, // Timeout after 5s instead of 30s
      socketTimeoutMS: 45000, // Close sockets after 45s of inactivity
    });
    console.log('✅ MongoDB connected successfully');
  } catch (err) {
    console.error('❌ MongoDB connection error:', err.message);
    console.error('🔄 Retrying connection in 5 seconds...');
    setTimeout(connectToMongoDB, 5000);
  }
}

connectToMongoDB();

// JWT Helpers
function generateToken(user) {
  const payload = {
    id: user._id,
    name: user.name,
    email: user.email,
    role: user.role
  };
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });
}



// ---------------- AUTH ROUTES ---------------- //

app.post('/signup', authLimiter, validateUserRegistration, async (req, res) => {
  try {
    const { name, email, password, role, expertise, experience } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ success: false, message: 'Email already registered' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      role,
      expertise: role === 'teacher' ? expertise : null,
      experience: role === 'teacher' ? experience : null,
    });

    await newUser.save();
    const token = generateToken(newUser);
    const { password: _, ...userData } = newUser.toObject();

    res.json({ success: true, user: userData, token });
  } catch (err) {
    console.error('[SIGNUP ERROR]', err);
    res.status(500).json({ success: false, message: 'Signup failed' });
  }
});

app.post('/login', authLimiter, validateUserLogin, async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ success: false, message: 'Invalid credentials' });

    const token = generateToken(user);
    const { password: _, ...userData } = user.toObject();
    res.json({ success: true, user: userData, token });
  } catch (err) {
    console.error('[LOGIN ERROR]', err);
    res.status(500).json({ success: false, message: 'Login failed' });
  }
});

// ---------------- DASHBOARD ROUTE ---------------- //

app.get('/dashboard-data', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    let data = { ...user.toObject() };

    if (user.role === 'student') {
      data.enrolledCourses = await Course.find({ enrolledStudents: user._id }).select('title image _id');
      data.completedProjects = await Project.find({ student: user._id, status: 'approved' });
      data.certificates = await Certificate.find({ student: user._id });
      data.newMessages = await Message.find({ to: user._id, read: false }).populate('from', 'name');
      data.upcomingDeadlines = []; // Optional
    } else if (user.role === 'teacher') {
      // Get teacher's courses with enrolled students
      data.myCourses = await Course.find({ teacher: user._id })
        .populate('enrolledStudents', 'name email')
        .lean();

      // Calculate total students across all courses (unique students)
      const allStudentIds = new Set();
      data.myCourses.forEach(course => {
        course.enrolledStudents?.forEach(student => {
          allStudentIds.add(student._id.toString());
        });
      });
      data.totalStudents = allStudentIds.size;

      // Get all course IDs for this teacher
      const courseIds = data.myCourses.map(course => course._id);

      // Get assignments for teacher's courses
      const Assignment = require('./models/Assignment');
      data.totalAssignments = await Assignment.countDocuments({
        teacher: user._id
      });

      // Get pending assignment reviews
      data.pendingAssignmentReviews = await Assignment.find({
        teacher: user._id,
        'submissions.status': 'submitted'
      })
        .populate('course', 'title')
        .populate('submissions.student', 'name email')
        .sort({ createdAt: -1 })
        .limit(10);

      // Count total pending assignment submissions
      data.pendingAssignmentCount = 0;
      data.pendingAssignmentReviews.forEach(assignment => {
        data.pendingAssignmentCount += assignment.submissions.filter(s => s.status === 'submitted').length;
      });

      // Get pending project reviews for teacher's courses only
      data.pendingReviewsList = await Project.find({
        course: { $in: courseIds },
        status: 'submitted'
      })
        .populate('student', 'name email')
        .populate('course', 'title')
        .sort({ submittedAt: -1 })
        .limit(10); // Show latest 10 pending reviews

      data.pendingReviews = data.pendingReviewsList.length;

      // Get total projects assigned across all courses
      data.totalProjects = await Project.countDocuments({
        course: { $in: courseIds }
      });

      // Get messages from students enrolled in teacher's courses
      const enrolledStudentIds = data.myCourses.reduce((students, course) => {
        return students.concat(course.enrolledStudents?.map(s => s._id) || []);
      }, []);

      data.newMessages = await Message.find({
        to: user._id,
        from: { $in: enrolledStudentIds },
        read: false
      })
        .populate('from', 'name email')
        .sort({ createdAt: -1 })
        .limit(10);

      // Add pending reviews count to each course
      for (let course of data.myCourses) {
        const coursePendingReviews = await Project.countDocuments({
          course: course._id,
          status: 'submitted'
        });
        course.pendingReviews = coursePendingReviews;
      }
    }

    res.json({ success: true, user: data });
  } catch (err) {
    console.error('[DASHBOARD ERROR]', err);
    res.status(500).json({ success: false, message: 'Failed to fetch dashboard data' });
  }
});

// ---------------- PROFILE ROUTES ---------------- //

// Get user profile
app.get('/users/:id', authenticateToken, async (req, res) => {
  try {
    const userId = req.params.id;

    // Check if user is requesting their own profile or is admin
    if (req.user.id !== userId && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Access denied' });
    }

    const user = await User.findById(userId).select('-password');
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({ success: true, user });
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch profile' });
  }
});

// Update user profile
app.put('/users/:id', authenticateToken, async (req, res) => {
  try {
    const userId = req.params.id;
    const { name, email, expertise, experience } = req.body;

    // Check if user is updating their own profile
    if (req.user.id !== userId) {
      return res.status(403).json({ success: false, message: 'Access denied' });
    }

    // Check if email is already taken by another user
    if (email) {
      const existingUser = await User.findOne({ email, _id: { $ne: userId } });
      if (existingUser) {
        return res.status(400).json({ success: false, message: 'Email already in use' });
      }
    }

    const updateData = {};
    if (name) updateData.name = name;
    if (email) updateData.email = email;
    if (expertise !== undefined) updateData.expertise = expertise;
    if (experience !== undefined) updateData.experience = experience;

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      updateData,
      { new: true, runValidators: true }
    ).select('-password');

    if (!updatedUser) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({ success: true, user: updatedUser });
  } catch (error) {
    console.error('Error updating user profile:', error);
    res.status(500).json({ success: false, message: 'Failed to update profile' });
  }
});

// Upload avatar
app.post('/upload-avatar', authenticateToken, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'No file uploaded' });
    }

    const avatarUrl = `/uploads/profiles/${req.file.filename}`;

    // Update user's avatar in database
    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      { profilePicture: avatarUrl },
      { new: true }
    ).select('-password');

    if (!updatedUser) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({
      success: true,
      avatarUrl,
      message: 'Avatar uploaded successfully'
    });
  } catch (error) {
    console.error('Error uploading avatar:', error);
    res.status(500).json({ success: false, message: 'Failed to upload avatar' });
  }
});

// Change password
app.post('/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Current password and new password are required'
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'New password must be at least 6 characters long'
      });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Verify current password
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isCurrentPasswordValid) {
      return res.status(400).json({
        success: false,
        message: 'Current password is incorrect'
      });
    }

    // Hash new password
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    // Update password
    await User.findByIdAndUpdate(req.user.id, { password: hashedNewPassword });

    res.json({ success: true, message: 'Password changed successfully' });
  } catch (error) {
    console.error('Error changing password:', error);
    res.status(500).json({ success: false, message: 'Failed to change password' });
  }
});

// ---------------- MARKETPLACE ROUTES ---------------- //

// Use the new product and order routes
app.use('/api/products', authenticateToken, productRoutes);
app.use('/api/orders', authenticateToken, orderRoutes);

// ---------------- FEATURE ROUTES ---------------- //

app.use('/courses', authenticateToken, courseRoutes);
app.use('/projects', authenticateToken, projectRoutes);
app.use('/certificates', authenticateToken, certificateRoutes);
app.use('/discussions', authenticateToken, discussionRoutes);
app.use('/assignments', assignmentRoutes);
app.use('/messages', messageRoutes);
app.use('/api', courseRoutes); // For backward compatibility
app.use('/students', authenticateToken, studentsRoutes);

// Contact form endpoint
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, subject, message, timestamp } = req.body;

    // Validate required fields
    if (!name || !email || !subject || !message) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required'
      });
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email address'
      });
    }

    // Log the contact form submission (in production, you'd save to database or send email)
    console.log('Contact form submission:', {
      name,
      email,
      subject,
      message,
      timestamp: timestamp || new Date().toISOString(),
      ip: req.ip
    });

    // In a real application, you would:
    // 1. Save to database
    // 2. Send email notification to admin
    // 3. Send confirmation email to user

    res.json({
      success: true,
      message: 'Thank you for your message! We will get back to you soon.'
    });

  } catch (error) {
    console.error('Contact form error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});
// Test route
app.get('/demo/test', (req, res) => {
  res.json({ message: 'Demo routes are working!' });
});

// Demo routes for student management
app.post('/demo/create-student', async (req, res) => {
  try {
    const { name, email, password, isActive, joinedDate, avatar } = req.body;

    // Import Student model
    const Student = require('./models/Student');

    // Check if student already exists
    const existingStudent = await Student.findOne({ email });
    if (existingStudent) {
      return res.status(400).json({ message: 'Student with this email already exists' });
    }

    const student = new Student({
      name,
      email,
      password, // In a real app, this should be hashed
      isActive: isActive !== undefined ? isActive : true,
      joinedDate: joinedDate ? new Date(joinedDate) : new Date(),
      avatar: avatar || 'images/default-avatar.png',
      enrolledCourses: []
    });

    await student.save();

    // Return student without password
    const studentResponse = student.toObject();
    delete studentResponse.password;

    res.status(201).json({
      message: 'Demo student created successfully',
      student: studentResponse
    });
  } catch (error) {
    console.error('Error creating demo student:', error);
    res.status(500).json({ message: 'Error creating demo student' });
  }
});

app.post('/demo/enroll-student', async (req, res) => {
  try {
    const { studentId, courseId, progress } = req.body;

    const Student = require('./models/Student');

    // Find the student
    const student = await Student.findById(studentId);
    if (!student) {
      return res.status(404).json({ message: 'Student not found' });
    }

    // Find the course
    const course = await Course.findById(courseId);
    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    // Check if already enrolled
    const alreadyEnrolled = student.enrolledCourses.some(
      enrollment => enrollment.courseId.toString() === courseId
    );

    if (alreadyEnrolled) {
      return res.status(400).json({ message: 'Student already enrolled in this course' });
    }

    // Add enrollment to student
    student.enrolledCourses.push({
      courseId: courseId,
      progress: progress || 0
    });

    // Add student to course's enrolled students
    if (!course.enrolledStudents.includes(studentId)) {
      course.enrolledStudents.push(studentId);
    }

    await student.save();
    await course.save();

    res.json({
      message: 'Student enrolled successfully',
      enrollment: {
        studentId,
        courseId,
        progress: progress || 0
      }
    });
  } catch (error) {
    console.error('Error enrolling student:', error);
    res.status(500).json({ message: 'Error enrolling student' });
  }
});

app.delete('/demo/clear-students', async (req, res) => {
  try {
    const Student = require('./models/Student');

    // Find all demo students
    const demoStudents = await Student.find({
      email: { $regex: '@demo\.com$' }
    });

    const studentIds = demoStudents.map(student => student._id);

    // Remove these students from all courses
    await Course.updateMany(
      { enrolledStudents: { $in: studentIds } },
      { $pull: { enrolledStudents: { $in: studentIds } } }
    );

    // Delete the demo students
    const result = await Student.deleteMany({
      email: { $regex: '@demo\.com$' }
    });

    res.json({
      message: `Cleared ${result.deletedCount} demo students`,
      deletedCount: result.deletedCount
    });
  } catch (error) {
    console.error('Error clearing demo students:', error);
    res.status(500).json({ message: 'Error clearing demo students' });
  }
});
// Static files already configured above


// ---------------- HEALTH CHECK ---------------- //
app.get('/', (req, res) => {
  res.send('🌿 AgriLearn API is running');
});

// ---------------- START SERVER ---------------- //
const PORT = process.env.PORT || 5000;

console.log('🔧 Starting AgriLearn server...');
console.log('📊 Environment check:');
console.log('  - MongoDB URI:', process.env.MONGODB_URI ? '✅ Set' : '❌ Missing');
console.log('  - JWT Secret:', process.env.JWT_SECRET ? '✅ Set' : '❌ Missing');
console.log('  - Port:', PORT);

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log('🌿 AgriLearn API is ready!');
});