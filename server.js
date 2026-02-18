require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');
const axios = require('axios');
const { Pool } = require('pg');
const crypto = require('crypto');
const pgSession = require('connect-pg-simple')(session);
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const https = require('https');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.APIPORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';

// Directus API configuration
const url = process.env.DIRECTUS_URL;
const accessToken = process.env.DIRECTUS_TOKEN;

// PostgreSQL connection pool
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: { rejectUnauthorized: false },
});

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.use(session({ secret: 'secret', resave: false, saveUninitialized: true }));
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use(bodyParser.json({ limit: '50mb' }));
app.use(cors({
  origin: ['http://localhost:8081', 'http://localhost:19000', 'exp://localhost:19000', 'http://localhost:3000', 'http://localhost:8055'],
  credentials: true,
}));

app.use(session({
  store: new pgSession({
    pool: pool,
    tableName: 'session',
  }),
  secret: 'sqT_d_qxWqHyXS6Yk7Me8APygz3EjFE8',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
  },
}));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// ============================================
// HELPER FUNCTIONS
// ============================================

/**
 * Query function for Directus API
 */
async function query(path, config) {
    const res = await axios(`${url}${path}`, {
        headers: {
            "Authorization": `Bearer ${accessToken}`,
            "Content-Type": "application/json",
        },
        ...config
    });
    return res;
}

/**
 * Hash password using bcrypt
 */
async function hashPassword(password) {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, salt);
}

/**
 * Verify password
 */
async function verifyPassword(password, hashedPassword) {
  return await bcrypt.compare(password, hashedPassword);
}

/**
 * Generate JWT token
 */
function generateToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

/**
 * Verify JWT token
 */
function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
}

// ============================================
// AUTH MIDDLEWARE
// ============================================

/**
 * Check session middleware (for session-based auth)
 */
const checkSession = (req, res, next) => {
  if (req.session && req.session.user) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized', message: 'Please login to access this resource' });
  }
};

/**
 * Verify JWT token middleware
 */
const verifyTokenMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized', message: 'No token provided' });
  }
  
  const token = authHeader.split(' ')[1];
  const decoded = verifyToken(token);
  
  if (!decoded) {
    return res.status(401).json({ error: 'Unauthorized', message: 'Invalid or expired token' });
  }
  
  req.user = decoded;
  next();
};

// ============================================
// AUTH ROUTES
// ============================================

/**
 * POST /api/register
 * Register a new user
 * Body: { firstName, lastName, phone, password, role?, companyCode? }
 */
async function signUp(userData) {

  const response = await query('/items/users', {
    method: 'POST',
    data: userData,
  });

  return response.data;
}

app.post('/api/register', async (req, res) => {
  try {
    const { firstName, lastName, phone, password, role, companyCode } = req.body;

    // Validate required fields
    if (!firstName || !lastName || !phone || !password) {
      return res.status(400).json({ 
        error: 'Validation Error', 
        message: 'Please fill in all required fields' 
      });
    }

    const hashedPassword = await hashPassword(password);

    // Prepare user data for Directus (Directus handles password hashing)
    const userData = {
      first_name: firstName,
      last_name: lastName,
      phone: phone,
      password: hashedPassword,
      role: role || 'guard',
      invite_code: companyCode || 'null',
      status: 'active',
    };

    // Register user in Directus
    const newUser = await signUp(userData);

    // Return success (without password)
    res.status(201).json({
      message: 'User registered successfully',
      user: newUser
    });
  } catch (error) {
    console.error('Registration Error:', error);
    
    // Handle duplicate entry error
    if (error.message?.includes('UNIQUE')) {
      return res.status(409).json({ 
        error: 'Conflict', 
        message: 'User with this phone number already exists' 
      });
    }
    
    res.status(500).json({ 
      error: 'Internal Server Error', 
      message: 'Failed to register user' 
    });
  }
});

/**
 * GET /api/assignments
 * Get all assignments (admin/supervisor only)
 */
app.get('/api/assignments', verifyTokenMiddleware, async (req, res) => {
  try {
    // Fetch assignments from Directus with guard info
    const response = await query('/items/assignments');
    // console.log(response)
    res.json({
      assignments: response.data.data
    });
  } catch (error) {
    console.error('Error fetching assignments:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to fetch assignments'
    });
  }
});

/**
 * GET /api/my-assignments
 * Get assignments for the logged-in guard
 */
app.get('/api/my-assignments', verifyTokenMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;

    // Fetch assignments for this guard from Directus
    const response = await query(`/items/assignments?filter[user_id][_eq]=${userId}`);

    res.json({
      assignments: response.data.data
    });
  } catch (error) {
    console.error('Error fetching my assignments:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to fetch assignments'
    });
  }
});

/**
 * PUT /api/my-assignments
 * Update assignment for the logged-in guard
 * Body: { location, assigned_areas, start_time, end_time }
 */
app.put('/api/my-assignments', verifyTokenMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { location, assigned_areas, start_time, end_time } = req.body;

    // Validate required fields
    if (!location || !assigned_areas || !start_time || !end_time) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'All fields are required: location, assigned_areas, start_time, end_time'
      });
    }

    // Fetch the assignment for this user
    const response = await query(`/items/assignments?filter[user_id][_eq]=${userId}`);

    if (!response.data.data || response.data.data.length === 0) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'No assignment found for this user'
      });
    }

    const assignment = response.data.data[0]; // Assuming one assignment per user

    // Update the assignment
    const updateData = {
      location,
      assigned_areas,
      start_time,
      end_time,
      date_updated: new Date().toISOString()
    };

    await query(`/items/assignments/${assignment.id}`, {
      method: 'PATCH',
      data: updateData
    });

    res.json({ message: 'Assignment updated successfully' });
  } catch (error) {
    console.error('Error updating assignment:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to update assignment'
    });
  }
});

/**
 * GET /api/locations
 * Get locations for the logged-in user's organization
 */
app.get('/api/locations', verifyTokenMiddleware, async (req, res) => {
  try {
    const inviteCode = req.user.invite_code;

    // Fetch locations where organization.invite_code matches user's invite_code
    const response = await query(`/items/locations?filter[organization][_eq]=${inviteCode}`);

    res.json({
      locations: response.data.data
    });

    // console.log("Locations data",response.data.data)
  } catch (error) {
    console.error('Error fetching locations:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to fetch locations'
    });
  }
});

/**
 * POST /api/login
 * Login with phone and password
 * Body: { phone, password }
 */
app.post('/api/login', async (req, res) => {
  try {
    const { phone, password } = req.body;

    // console.log("Logging in with", phone ,"and", password)

    // Validate input
    if (!phone || !password) {
      return res.status(400).json({ 
        error: 'Validation Error', 
        message: 'Please provide phone number and password' 
      });
    }

    // Find user in Directus by phone
    const queryUrl = `/items/users?filter[phone][_eq]=${encodeURIComponent(phone)}`;
    // console.log("Query URL:", `${url}${queryUrl}`);
    const users = await query(queryUrl);

    // console.log("Full response:", users);
    // console.log("Response data:", users.data);
    // console.log("Found users:", users.data.data);

    if (!users.data.data || users.data.data.length === 0) {
      return res.status(401).json({ 
        error: 'Unauthorized', 
        message: 'Invalid phone number or password' 
      });
    }

    const user = users.data.data[0];

    // Verify password
    const isValidPassword = await verifyPassword(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ 
        error: 'Unauthorized', 
        message: 'Invalid phone number or password' 
      });
    }

    // Fetch assignments for guards
    let assignments = [];
    if (user.role === 'guard') {
      try {
        const assignmentsResponse = await query(`/items/assignments?filter[user_id][_eq]=${user.id}`);
        assignments = assignmentsResponse.data.data || [];
      } catch (assignmentError) {
        console.error('Error fetching guard assignments:', assignmentError);
        assignments = [];
      }
    }

    // Create session
    req.session.user = {
      id: user.id,
      first_name: user.first_name,
      last_name: user.last_name,
      phone: user.phone,
      role: user.role,
      invite_code: user.invite_code,
      assignments: assignments,
    };

    // Generate JWT token with assignments for guards
    const tokenPayload = {
      id: user.id,
      first_name: user.first_name,
      last_name: user.last_name,
      phone: user.phone,
      role: user.role,
      invite_code: user.invite_code,
      assignments: assignments
    };

    // console.log(tokenPayload)

    // Include assignments in token for guards
    if (user.role === 'guard') {
      tokenPayload.assignments = assignments;
    }

    const token = generateToken(tokenPayload);

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        first_name: user.first_name,
        last_name: user.last_name,
        phone: user.phone,
        role: user.role,
        invite_code: user.invite_code,
        assignments: assignments,
      },
      token,
    });
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ 
      error: 'Internal Server Error', 
      message: 'Failed to login' 
    });
  }
});

/**
 * POST /api/logout
 * Logout user and destroy session
 */
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ 
        error: 'Internal Server Error', 
        message: 'Failed to logout' 
      });
    }
    res.clearCookie('connect.sid');
    res.json({ message: 'Logout successful' });
  });
});

/**
 * GET /api/me
 * Get current user session
 */
app.get('/api/me', (req, res) => {
  if (req.session && req.session.user) {
    res.json({ 
      authenticated: true,
      user: req.session.user 
    });
  } else {
    res.status(401).json({ 
      authenticated: false,
      message: 'Not authenticated' 
    });
  }
});

/**
 * GET /api/me (with JWT)
 * Get current user from JWT token
 */
app.get('/api/me', verifyTokenMiddleware, (req, res) => {
  res.json({
    authenticated: true,
    user: req.user,
  });
});

/**
 * POST /api/verify-token
 * Verify JWT token
 * Body: { token }
 */
app.post('/api/verify-token', (req, res) => {
  const { token } = req.body;
  
  if (!token) {
    return res.status(400).json({ 
      valid: false, 
      message: 'No token provided' 
    });
  }
  
  const decoded = verifyToken(token);
  
  if (decoded) {
    res.json({ valid: true, user: decoded });
  } else {
    res.status(401).json({ 
      valid: false, 
      message: 'Invalid or expired token' 
    });
  }
});

// ============================================
// PROTECTED ROUTES EXAMPLE
// ============================================

/**
 * GET /api/admin/dashboard
 * Protected route example - requires authentication
 */
app.get('/api/admin/dashboard', verifyTokenMiddleware, (req, res) => {
  res.json({
    message: 'Welcome to the admin dashboard',
    user: req.user,
    data: {
      totalGuards: 45,
      activeShifts: 12,
      pendingReports: 5,
    }
  });
});


// ============================================
// VIEW ROUTES
// ============================================

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/documentation', (req, res) => {
  res.render('documentation');
});

// ============================================
// ERROR HANDLING
// ============================================
app.use((err, req, res, next) => {
  console.error('Unhandled Error:', err);
  res.status(500).json({ 
    error: 'Internal Server Error', 
    message: 'An unexpected error occurred' 
  });
});

// ============================================
// GET ORGANIZATIONS INVITE CODES
// ============================================
app.get('/api/organizations/invite-codes', verifyTokenMiddleware, async (req, res) => {
  try {
    const response = await query('/items/organizations?fields=invite_code');
    const inviteCodes = response.data.data.map(org => org.invite_code);
    res.json({ inviteCodes });
  } catch (error) {
    console.error('Error fetching invite codes:', error);
    res.status(500).json({ 
      error: 'Internal Server Error', 
      message: 'Failed to fetch invite codes' 
    });
  }
});

// ============================================
// VALIDATE INVITE CODE (PUBLIC)
// ============================================
app.post('/api/organizations/validate-invite-code', async (req, res) => {
  try {
    const { inviteCode } = req.body;

    if (!inviteCode || inviteCode.trim() === '') {
      return res.status(400).json({
        valid: false,
        message: 'Invite code is required'
      });
    }

    // Fetch all invite codes from organizations
    const response = await query('/items/organizations?fields=invite_code');
    const inviteCodes = response.data.data.map(org => org.invite_code);

    // Check if the provided code exists
    if (inviteCodes.includes(inviteCode)) {
      res.json({
        valid: true,
        message: 'Invite code is valid'
      });
    } else {
      res.status(404).json({
        valid: false,
        message: 'The organization is not registered with OmniWatch'
      });
    }
  } catch (error) {
    console.error('Error validating invite code:', error);
    res.status(500).json({
      valid: false,
      message: 'Failed to validate invite code'
    });
  }
});

// ============================================
// PATROLS ROUTES
// ============================================

/**
 * GET /api/patrols
 * Get all patrols for the logged-in guard
 * Query params: limit (optional), sort (optional)
 */
app.get('/api/patrols', verifyTokenMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const limit = req.query.limit || 10;
    const sort = req.query.sort || '-start_time';

    // Fetch patrols for this guard from Directus
    const response = await query(`/items/patrols?filter[user_id][_eq]=${userId}&sort=${sort}&limit=${limit}`);

    res.json({
      patrols: response.data.data
    });
  } catch (error) {
    console.error('Error fetching patrols:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to fetch patrols'
    });
  }
});

/**
 * POST /api/patrols
 * Create a new patrol
 * Body: { start_time, user_id, organization_id }
 */
app.post('/api/patrols', verifyTokenMiddleware, async (req, res) => {
  try {
    const { start_time, user_id, organization_id } = req.body;

    // Validate required fields
    if (!start_time || !user_id) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'start_time and user_id are required'
      });
    }

    // Create patrol in Directus
    const patrolData = {
      start_time,
      user_id,
      organization_id: organization_id || null,
      status: 'active',
    };

    const response = await query('/items/patrols', {
      method: 'POST',
      data: patrolData,
    });

    res.status(201).json({
      message: 'Patrol started successfully',
      data: response.data.data
    });
  } catch (error) {
    console.error('Error creating patrol:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to create patrol'
    });
  }
});

/**
 * PATCH /api/patrols/:id
 * Update a patrol (e.g., end time, location data)
 * Body: { end_time, location_data, status }
 */
app.patch('/api/patrols/:id', verifyTokenMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { end_time, location_data, status } = req.body;

    // Build update data
    const updateData = {};
    
    if (end_time) {
      updateData.end_time = end_time;
    }
    if (location_data) {
      updateData.location_data = location_data;
    }
    if (status) {
      updateData.status = status;
    }

    // If end_time is provided, set status to completed
    if (end_time && !status) {
      updateData.status = 'completed';
    }

    // Update patrol in Directus
    const response = await query(`/items/patrols/${id}`, {
      method: 'PATCH',
      data: updateData,
    });

    res.json({
      message: 'Patrol updated successfully',
      data: response.data.data
    });
  } catch (error) {
    console.error('Error updating patrol:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to update patrol'
    });
  }
});

// ============================================
// START SERVER
// ============================================

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📱 OmniWatch API ready at http://localhost:${PORT}/api`);
  console.log(`📖 API Documentation at http://localhost:${PORT}/documentation`);
});

module.exports = app;