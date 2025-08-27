const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const xlsx = require('xlsx');
require('dotenv').config();
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(express.static('public'));


/*const allowedOrigins = ['https://exc-attendance.vercel.app/'];
app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'The CORS policy for this site does not allow access from the specified origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    }
}));*/
// CORS Configuration
const corsOptions = {
    origin: [ 
        'https://exc-attendance.vercel.app/' // Replace with your actual frontend domain
    ],
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    optionsSuccessStatus: 200
};

// Middleware
app.use(cors());

// Connect to MongoDB Atlas
const mongoURI = process.env.MONGODB_URI;
mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connected to MongoDB Atlas'))
    .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  registrationNumber: String,
  password: String,
  role: { type: String, default: 'user' },
});
const User = mongoose.model('User', userSchema);

// Attendance Schema
const attendanceSchema = new mongoose.Schema({
  eventName: String,
  eventDate: String,
  eventStartTime:String,
  eventEndTime:String,
  records: [{ studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, status: String }],
});
const Attendance = mongoose.model('Attendance', attendanceSchema);

// Login Route
app.post('/login', async (req, res) => {
  const { email, registrationNumber, password } = req.body;
  const user = await User.findOne({ email, registrationNumber });

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.json({ msg: 'Invalid credentials' });
  }

  const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET);
  res.json({ token, role: user.role });
});

// Middleware to Protect Routes
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Get Events and User Attendance Status
app.get('/user/events', authenticateToken, async (req, res) => {
  try {
    // Find all events
    const events = await Attendance.find();

    // Find user attendance for the current user
    const userAttendance = events.map(event => {
      // Find the record for the current user in this event
      const userRecord = event.records.find(
        r => r.studentId.toString() === req.user.userId
      );

      return {
        eventName: event.eventName,
        eventDate: event.eventDate,
        eventStartTime: event.eventStartTime,
        eventEndTime: event.eventEndTime,
        status: userRecord ? userRecord.status : 'Not marked',
      };
    });

    res.json(userAttendance);
  } catch (error) {
    console.error('Error fetching user events:', error);
    res.status(500).json({ message: 'Error fetching events' });
  }
});

// Get Student List (Admin)
app.get('/admin/students', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  const students = await User.find({ role: 'user' }).select('email registrationNumber name');
  res.json(students);
});

// Post Attendance (Admin)
app.post('/admin/post-attendance', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);

  const { eventName, eventDate,eventStartTime,eventEndTime, attendance } = req.body;
  const existingEvent = await Attendance.findOne({ eventName, eventDate,eventStartTime,eventEndTime });
  if (existingEvent) return res.json({ message: 'Event with this date already exists' });

  await Attendance.create({ eventName, eventDate,eventStartTime,eventEndTime, records: attendance });
  res.json({ message: 'Attendance posted successfully' });
});

// View Attendance (Admin)
app.get('/admin/view-attendance', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);

  const { eventName, eventDate, eventStartTime, eventEndTime } = req.query;
  const attendanceData = await Attendance.findOne({ eventName, eventDate, eventStartTime, eventEndTime }).populate({
    path: 'records.studentId',
    select: 'name registrationNumber email _id',
  });

  if (!attendanceData) return res.json({message: "This event does not exist."});

  const response = attendanceData.records.map(record => ({
    _id: record.studentId?._id,
    name: record.studentId?.name || "Name not found",
    registrationNumber: record.studentId?.registrationNumber || "Registration not found",
    email: record.studentId?.email || "Email id not found",
    status: record.status,
  }));
  res.json(response);
});

// Download Attendance as Excel (Admin)
app.get('/admin/download-attendance', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);

  const { eventName, eventDate,eventStartTime,eventEndTime } = req.query;
  const attendanceData = await Attendance.findOne({ eventName, eventDate,eventStartTime,eventEndTime }).populate({
    path: 'records.studentId',
    select: 'name registrationNumber email',
  });

  if (!attendanceData) return res.sendStatus(404);

  const workbook = xlsx.utils.book_new();
  const data = attendanceData.records.map(record => ({
    Name: record.studentId?.name || "Name not found",
    RegistrationNumber: record.studentId?.registrationNumber || "Registration not found",
    Email:record.studentId?.email || "Email id not found",
    Status: record.status,
  }));

  const worksheet = xlsx.utils.json_to_sheet(data);
  xlsx.utils.book_append_sheet(workbook, worksheet, 'Attendance');

  // Set headers for direct download without saving
  res.setHeader('Content-Disposition', `attachment; filename=attendance_${eventName}_${eventDate}_${eventStartTime}_${eventEndTime}.xlsx`);
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');

  // Write workbook directly to response
  const buffer = xlsx.write(workbook, { type: 'buffer', bookType: 'xlsx' });
  res.send(buffer);
});

// Event Summary (Admin)
// Event Summary Route (Admin)
app.get('/admin/event-summary', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);

  try {
    const events = await Attendance.find().populate({
      path: 'records.studentId',
      select: 'role'
    });

    const summary = events.map(event => {
      // Filter and count only user records
      const userRecords = event.records.filter(record => 
        record.studentId && record.studentId.role === 'user'
      );

      const presentCount = userRecords.filter(record => record.status === 'present').length;
      const absentCount = userRecords.filter(record => record.status === 'absent').length;

      return {
        eventName: event.eventName,
        eventDate: event.eventDate,
        eventStartTime: event.eventStartTime,
        eventEndTime: event.eventEndTime,
        presentCount,
        absentCount
      };
    });

    res.json(summary);
  } catch (error) {
    console.error('Error fetching event summary:', error);
    res.status(500).json({ message: 'Error fetching event summary' });
  }
});


// Edit Attendance (Admin)
app.post('/admin/edit-attendance', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);

  try {
    const { 
      studentId, 
      eventName, 
      eventDate, 
      eventStartTime, 
      eventEndTime, 
      newStatus 
    } = req.body;

    // Find the specific event
    const attendanceRecord = await Attendance.findOne({ 
      eventName, 
      eventDate, 
      eventStartTime, 
      eventEndTime 
    });

    if (!attendanceRecord) {
      return res.json({ 
        success: false, 
        message: 'Event not found' 
      });
    }

    // Find and update the specific student's attendance
    const studentRecordIndex = attendanceRecord.records.findIndex(
      record => record.studentId.toString() === studentId
    );

    if (studentRecordIndex === -1) {
      // If not found, log some debugging information
      console.log('Debugging Edit Attendance:');
      console.log('Student ID received:', studentId);
      console.log('Attendance Records:', attendanceRecord.records.map(r => r.studentId.toString()));

      return res.json({ 
        success: false, 
        message: 'Student attendance record not found' 
      });
    }

    // Update the attendance status
    attendanceRecord.records[studentRecordIndex].status = newStatus;

    // Save the updated attendance record
    await attendanceRecord.save();

    res.json({ 
      success: true, 
      message: 'Attendance updated successfully' 
    });

  } catch (error) {
    console.error('Error editing attendance:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

// Delete Event Attendance (Admin)
app.delete('/admin/delete-event', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);

  try {
    const { eventName, eventDate, eventStartTime, eventEndTime } = req.body;

    const result = await Attendance.deleteOne({ 
      eventName, 
      eventDate, 
      eventStartTime, 
      eventEndTime 
    });

    if (result.deletedCount === 0) {
      return res.json({ 
        success: false, 
        message: 'Event not found' 
      });
    }

    res.json({ 
      success: true, 
      message: 'Event attendance deleted successfully' 
    });

  } catch (error) {
    console.error('Error deleting event:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

// Start Server
app.listen(3000, () => console.log('Server running on http://localhost:3000'));
