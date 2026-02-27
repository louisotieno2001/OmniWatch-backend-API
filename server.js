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
 * Get current user from session or JWT token
 */
app.get('/api/me', async (req, res) => {
  let currentUser = req.session?.user || null;

  if (!currentUser) {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (token) {
      try {
        currentUser = verifyToken(token);
      } catch (tokenError) {
        console.error('Error verifying token for /api/me:', tokenError?.message || tokenError);
      }
    }
  }

  if (!currentUser) {
    return res.status(401).json({
      authenticated: false,
      message: 'Not authenticated',
    });
  }

  let company = '';
  let organization = null;

  try {
    if (currentUser.invite_code) {
      const orgResponse = await query(
        `/items/organizations?filter[invite_code][_eq]=${encodeURIComponent(currentUser.invite_code)}&fields=*&limit=1`
      );
      const org = (orgResponse.data.data || [])[0] || null;
      organization = org;
      company =
        org?.name ||
        org?.organization ||
        org?.organization_name ||
        org?.company_name ||
        org?.company ||
        org?.title ||
        org?.label ||
        org?.invite_code ||
        currentUser.invite_code ||
        '';
    }
  } catch (orgError) {
    console.error('Error fetching organization for /api/me:', orgError);
  }

  res.json({
    authenticated: true,
    user: {
      ...currentUser,
      company,
      organization,
    },
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

app.get('/api-endpoints', (req, res) => {
  res.render('api_endpoints');
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
 * GET /api/admin/guards
 * Get all guards for the admin's organization
 * Requires authentication and returns guards with matching invite_code
 */
app.get('/api/admin/guards', verifyTokenMiddleware, async (req, res) => {
  try {
    const inviteCode = req.user.invite_code;

    // console.log('Invite code', inviteCode)

    if (!inviteCode) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'No organization invite code found'
      });
    }

    // Fetch users with role='guard' and matching invite_code
    const response = await query(`/items/users?filter[role][_eq]=guard&filter[invite_code][_eq]=${inviteCode}`);
    const guards = response.data.data || [];

    if (!guards.length) {
      return res.json({ guards: [] });
    }

    // Load organization locations once so assignment.location IDs can be resolved to names.
    const locationsResponse = await query(`/items/locations?filter[organization][_eq]=${inviteCode}&fields=id,name`);
    const locations = locationsResponse.data.data || [];
    const locationsById = new Map();
    for (const loc of locations) {
      locationsById.set(loc.id, loc.name);
    }

    // For each guard, get latest assignment by user_id and enrich response fields.
    const enrichedGuards = [];
    for (const guard of guards) {
      let assignment = null;
      let latestPatrol = null;
      try {
        const assignmentsResponse = await query(
          `/items/assignments?filter[user_id][_eq]=${guard.id}&sort=-date_updated&limit=1`
        );
        assignment = (assignmentsResponse.data.data || [])[0] || null;
      } catch (assignmentError) {
        console.error(`Error fetching assignment for guard ${guard.id}:`, assignmentError);
      }

      try {
        const patrolResponse = await query(
          `/items/patrols?filter[user_id][_eq]=${guard.id}&sort=-start_time&limit=1`
        );
        latestPatrol = (patrolResponse.data.data || [])[0] || null;
      } catch (patrolError) {
        console.error(`Error fetching latest patrol for guard ${guard.id}:`, patrolError);
      }

      const locationId = assignment?.location || '';
      const locationName = locationId ? (locationsById.get(locationId) || locationId) : 'Not assigned';
      const isOnActivePatrol = latestPatrol && latestPatrol.status === 'active' && !latestPatrol.end_time;

      let lastSeen = guard.last_access || null;
      let lastSeenDisplay = 'Never';
      if (isOnActivePatrol) {
        lastSeenDisplay = 'Online (Currently on patrol)';
      } else if (latestPatrol?.end_time) {
        lastSeen = latestPatrol.end_time;
        lastSeenDisplay = latestPatrol.end_time;
      } else if (guard.last_access) {
        lastSeenDisplay = guard.last_access;
      }

      enrichedGuards.push({
        ...guard,
        location: locationName,
        location_id: locationId,
        assigned_areas: assignment?.assigned_areas || '',
        operating_hours_start: assignment?.start_time || '',
        operating_hours_end: assignment?.end_time || '',
        last_seen: lastSeen,
        last_seen_display: lastSeenDisplay,
        is_online: Boolean(isOnActivePatrol),
      });
    }

    res.json({
      guards: enrichedGuards
    });
  } catch (error) {
    console.error('Error fetching guards:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to fetch guards'
    });
  }
});

/**
 * POST /api/admin/assignments
 * Create a new assignment for a guard in the admin's organization
 * Body: { user_id, location, assigned_areas, start_time, end_time }
 */
app.post('/api/admin/assignments', verifyTokenMiddleware, async (req, res) => {
  try {
    const inviteCode = req.user.invite_code;
    const { user_id, location, assigned_areas, start_time, end_time } = req.body;

    if (!inviteCode) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'No organization invite code found',
      });
    }

    if (!user_id || !location || !assigned_areas || !start_time || !end_time) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'user_id, location, assigned_areas, start_time, and end_time are required',
      });
    }

    const guardResponse = await query(
      `/items/users?filter[id][_eq]=${encodeURIComponent(user_id)}&filter[role][_eq]=guard&filter[invite_code][_eq]=${encodeURIComponent(inviteCode)}&limit=1`
    );
    const guard = (guardResponse.data.data || [])[0];
    if (!guard) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'Guard not found in your organization',
      });
    }

    const locationResponse = await query(
      `/items/locations?filter[id][_eq]=${encodeURIComponent(location)}&filter[organization][_eq]=${encodeURIComponent(inviteCode)}&limit=1`
    );
    const organizationLocation = (locationResponse.data.data || [])[0];
    if (!organizationLocation) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'Location not found in your organization',
      });
    }

    const assignmentData = {
      user_id: String(user_id).trim(),
      location: String(location).trim(),
      assigned_areas: String(assigned_areas).trim(),
      start_time: String(start_time).trim(),
      end_time: String(end_time).trim(),
      date_updated: new Date().toISOString(),
    };

    const response = await query('/items/assignments', {
      method: 'POST',
      data: assignmentData,
    });

    res.status(201).json({
      message: 'Assignment created successfully',
      assignment: response.data.data,
    });
  } catch (error) {
    console.error('Error creating admin assignment:', error);
    const statusCode = error.response?.status || 500;
    res.status(statusCode).json({
      error: 'Internal Server Error',
      message: 'Failed to create assignment',
      details: error.response?.data || error.message,
    });
  }
});

/**
 * DELETE /api/admin/guards/:id
 * Remove a guard from the admin's organization and cascade-delete related data.
 */
app.delete('/api/admin/guards/:id', verifyTokenMiddleware, async (req, res) => {
  try {
    const inviteCode = req.user.invite_code;
    const { id } = req.params;

    if (!inviteCode) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'No organization invite code found',
      });
    }

    const guardResponse = await query(
      `/items/users?filter[id][_eq]=${encodeURIComponent(id)}&filter[role][_eq]=guard&filter[invite_code][_eq]=${encodeURIComponent(inviteCode)}&limit=1`
    );
    const guard = (guardResponse.data.data || [])[0];
    if (!guard) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'Guard not found in your organization',
      });
    }

    const deleteRelatedRecords = async (collection) => {
      const listResponse = await query(
        `/items/${collection}?filter[user_id][_eq]=${encodeURIComponent(id)}&fields=id&limit=-1`
      );
      const items = listResponse.data.data || [];
      for (const item of items) {
        await query(`/items/${collection}/${encodeURIComponent(item.id)}`, {
          method: 'DELETE',
        });
      }
      return items.length;
    };

    const deletedAssignments = await deleteRelatedRecords('assignments');
    const deletedLogs = await deleteRelatedRecords('logs');
    const deletedPatrols = await deleteRelatedRecords('patrols');

    await query(`/items/users/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });

    res.json({
      message: 'Guard removed successfully',
      deleted: {
        assignments: deletedAssignments,
        logs: deletedLogs,
        patrols: deletedPatrols,
      },
    });
  } catch (error) {
    console.error('Error deleting guard:', error);
    const statusCode = error.response?.status || 500;
    res.status(statusCode).json({
      error: 'Internal Server Error',
      message: 'Failed to remove guard',
      details: error.response?.data || error.message,
    });
  }
});

/**
 * GET /api/admin/patrols
 * Get all patrols for the admin's organization
 * Query params: limit (optional), sort (optional)
 */
app.get('/api/admin/patrols', verifyTokenMiddleware, async (req, res) => {
  try {
    const inviteCode = req.user.invite_code;
    const limit = req.query.limit || 50;
    const sort = req.query.sort || '-start_time';

    // First get all guards for this organization
    const guardsResponse = await query(`/items/users?filter[role][_eq]=guard&filter[invite_code][_eq]=${inviteCode}&fields=id`);
    const guards = guardsResponse.data.data;

    if (!guards || guards.length === 0) {
      return res.json({ patrols: [] });
    }

    // Get guard IDs
    const guardIds = guards.map(g => g.id);

    // Fetch patrols for all guards in the organization
    // Directus doesn't support 'in' filter, so we'll fetch each guard's patrols
    let allPatrols = [];
    for (const guardId of guardIds) {
      try {
        const patrolResponse = await query(`/items/patrols?filter[user_id][_eq]=${guardId}&sort=${sort}&limit=${limit}`);
        if (patrolResponse.data.data) {
          allPatrols = [...allPatrols, ...patrolResponse.data.data];
        }
      } catch (patrolError) {
        console.error(`Error fetching patrols for guard ${guardId}:`, patrolError);
      }
    }

    // Sort combined patrols by start_time
    allPatrols.sort((a, b) => new Date(b.start_time) - new Date(a.start_time));

    // Limit results
    const limitedPatrols = allPatrols.slice(0, parseInt(limit));

    // Build location lookup so assignment location IDs can be resolved to names.
    const locationsById = new Map();
    try {
      const locationsResponse = await query(`/items/locations?filter[organization][_eq]=${inviteCode}&fields=id,name`);
      const locations = locationsResponse.data.data || [];
      for (const location of locations) {
        locationsById.set(location.id, location.name);
      }
    } catch (locationError) {
      console.error('Error fetching locations for patrol enrichment:', locationError);
    }

    // Enrich each patrol using its user_id:
    // 1) fetch user -> guard_name
    // 2) fetch assignment by user_id -> assigned areas and assignment location
    const enrichedPatrols = [];
    for (const patrol of limitedPatrols) {
      const guardId = patrol.user_id;
      let guard = null;
      let assignment = null;

      try {
        const guardResponse = await query(`/items/users/${guardId}?fields=id,first_name,last_name`);
        guard = guardResponse?.data?.data || null;
      } catch (guardError) {
        console.error(`Error fetching guard ${guardId} for patrol ${patrol.id}:`, guardError);
      }

      try {
        const assignmentResponse = await query(
          `/items/assignments?filter[user_id][_eq]=${guardId}&sort=-date_updated&limit=1`
        );
        assignment = (assignmentResponse.data.data || [])[0] || null;
      } catch (assignmentError) {
        console.error(`Error fetching assignment for guard ${guardId}:`, assignmentError);
      }

      const resolvedLocationName = assignment?.location ? (locationsById.get(assignment.location) || assignment.location) : null;
      const guardName = guard ? `${guard.first_name || ''} ${guard.last_name || ''}`.trim() : '';
      const assignmentAreas = assignment?.assigned_areas || '';
      const assignmentCheckpoints = assignmentAreas
        ? assignmentAreas.split(',').map((area) => area.trim()).filter(Boolean)
        : [];

      enrichedPatrols.push({
        ...patrol,
        guard_name: guardName || patrol.guard_name || 'Unknown Guard',
        assigned_areas: assignmentAreas || patrol.assigned_areas || '',
        location: patrol.location || resolvedLocationName || 'Unknown Location',
        checkpoints: assignmentCheckpoints,
      });
    }

    res.json({
      patrols: enrichedPatrols
    });
  } catch (error) {
    console.error('Error fetching admin patrols:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to fetch patrols'
    });
  }
});

/**
 * GET /api/admin/locations
 * Get all locations for the admin's organization
 */
app.get('/api/admin/locations', verifyTokenMiddleware, async (req, res) => {
  try {
    const inviteCode = req.user.invite_code;

    if (!inviteCode) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'No organization invite code found'
      });
    }

    // Fetch locations where organization matches invite_code
    const response = await query(`/items/locations?filter[organization][_eq]=${inviteCode}`);

    res.json({
      locations: response.data.data
    });
  } catch (error) {
    console.error('Error fetching locations:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to fetch locations'
    });
  }
});

/**
 * POST /api/admin/locations
 * Create a location for the admin's organization
 * Body: { name, assigned_areas? }
 */
app.post('/api/admin/locations', verifyTokenMiddleware, async (req, res) => {
  try {
    const inviteCode = req.user.invite_code;
    const { name, assigned_areas } = req.body;

    if (!inviteCode) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'No organization invite code found',
      });
    }

    if (!name || !String(name).trim()) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Location name is required',
      });
    }

    const locationData = {
      name: String(name).trim(),
      assigned_areas: assigned_areas ? String(assigned_areas).trim() : '',
      organization: inviteCode,
    };

    const response = await query('/items/locations', {
      method: 'POST',
      data: locationData,
    });

    res.status(201).json({
      message: 'Location created successfully',
      location: response.data.data,
    });
  } catch (error) {
    console.error('Error creating location:', error);
    const statusCode = error.response?.status || 500;
    res.status(statusCode).json({
      error: 'Internal Server Error',
      message: 'Failed to create location',
      details: error.response?.data || error.message,
    });
  }
});

/**
 * PATCH /api/admin/locations/:id
 * Update a location for the admin's organization
 * Body: { name?, assigned_areas? }
 */
app.patch('/api/admin/locations/:id', verifyTokenMiddleware, async (req, res) => {
  try {
    const inviteCode = req.user.invite_code;
    const { id } = req.params;
    const { name, assigned_areas } = req.body;

    if (!inviteCode) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'No organization invite code found',
      });
    }

    const existingResponse = await query(
      `/items/locations?filter[id][_eq]=${encodeURIComponent(id)}&filter[organization][_eq]=${encodeURIComponent(inviteCode)}&limit=1`
    );
    const existingLocation = (existingResponse.data.data || [])[0];
    if (!existingLocation) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'Location not found',
      });
    }

    const updateData = {};
    if (name !== undefined) {
      if (!String(name).trim()) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Location name cannot be empty',
        });
      }
      updateData.name = String(name).trim();
    }
    if (assigned_areas !== undefined) {
      updateData.assigned_areas = String(assigned_areas).trim();
    }

    if (Object.keys(updateData).length === 0) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'No fields provided to update',
      });
    }

    const response = await query(`/items/locations/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      data: updateData,
    });

    res.json({
      message: 'Location updated successfully',
      location: response.data.data,
    });
  } catch (error) {
    console.error('Error updating location:', error);
    const statusCode = error.response?.status || 500;
    res.status(statusCode).json({
      error: 'Internal Server Error',
      message: 'Failed to update location',
      details: error.response?.data || error.message,
    });
  }
});

/**
 * DELETE /api/admin/locations/:id
 * Delete a location for the admin's organization
 */
app.delete('/api/admin/locations/:id', verifyTokenMiddleware, async (req, res) => {
  try {
    const inviteCode = req.user.invite_code;
    const { id } = req.params;

    if (!inviteCode) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'No organization invite code found',
      });
    }

    const existingResponse = await query(
      `/items/locations?filter[id][_eq]=${encodeURIComponent(id)}&filter[organization][_eq]=${encodeURIComponent(inviteCode)}&limit=1`
    );
    const existingLocation = (existingResponse.data.data || [])[0];
    if (!existingLocation) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'Location not found',
      });
    }

    await query(`/items/locations/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });

    res.json({
      message: 'Location deleted successfully',
      id,
    });
  } catch (error) {
    console.error('Error deleting location:', error);
    const statusCode = error.response?.status || 500;
    res.status(statusCode).json({
      error: 'Internal Server Error',
      message: 'Failed to delete location',
      details: error.response?.data || error.message,
    });
  }
});

/**
 * Shared handler for admin logs endpoint.
 */
const getAdminLogsHandler = async (req, res) => {
  try {
    const inviteCode = req.user.invite_code;
    const limit = req.query.limit || 50;
    const sort = req.query.sort || '-timestamp';

    // First get all guards for this organization
    const guardsResponse = await query(`/items/users?filter[role][_eq]=guard&filter[invite_code][_eq]=${inviteCode}&fields=id`);
    const guards = guardsResponse.data.data;

    if (!guards || guards.length === 0) {
      return res.json({ logs: [] });
    }

    // Get guard IDs
    const guardIds = guards.map(g => g.id);

    // Fetch logs for all guards in the organization
    let allLogs = [];
    for (const guardId of guardIds) {
      try {
        const logResponse = await query(`/items/logs?filter[user_id][_eq]=${guardId}&sort=${sort}&limit=${limit}`);
        if (logResponse.data.data) {
          allLogs = [...allLogs, ...logResponse.data.data];
        }
      } catch (logError) {
        console.error(`Error fetching logs for guard ${guardId}:`, logError);
      }
    }

    // Sort combined logs by timestamp
    allLogs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    // Limit results
    const limitedLogs = allLogs.slice(0, parseInt(limit));

    // Step 3 (minimal): resolve log location from user -> assignment -> location name.
    const locationsById = new Map();
    try {
      const locationsResponse = await query(`/items/locations?filter[organization][_eq]=${inviteCode}&fields=id,name`);
      const locations = locationsResponse.data.data || [];
      for (const location of locations) {
        locationsById.set(location.id, location.name);
      }
    } catch (locationError) {
      console.error('Error fetching locations for admin logs location mapping:', locationError);
    }

    const assignmentByUserId = new Map();
    for (const guardId of guardIds) {
      try {
        const assignmentResponse = await query(
          `/items/assignments?filter[user_id][_eq]=${guardId}&sort=-date_updated&limit=1`
        );
        assignmentByUserId.set(guardId, (assignmentResponse.data.data || [])[0] || null);
      } catch (assignmentError) {
        console.error(`Error fetching assignment for guard ${guardId}:`, assignmentError);
        assignmentByUserId.set(guardId, null);
      }
    }

    const logsWithResolvedLocation = limitedLogs.map((log) => {
      const assignment = assignmentByUserId.get(log.user_id);
      const resolvedLocation = assignment?.location
        ? (locationsById.get(assignment.location) || assignment.location)
        : null;

      return {
        ...log,
        location: log.location || resolvedLocation || 'Unknown Location',
      };
    });

    res.json({
      logs: logsWithResolvedLocation
    });
  } catch (error) {
    console.error('Error fetching admin logs:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to fetch logs'
    });
  }
};

/**
 * GET /api/admin/logs
 * Get all logs for the admin's organization
 * Query params: limit (optional), sort (optional)
 */
app.get('/api/admin/logs', verifyTokenMiddleware, getAdminLogsHandler);

/**
 * Normalize map payloads before persisting.
 * Supports stringified JSON, arrays, and objects.
 */
const normalizeMapValue = (value) => {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value);
  } catch (_error) {
    return null;
  }
};

/**
 * POST /api/patrols
 * Create a new patrol
 * Body: { start_time, user_id, organization_id, duration?, end_time?, map? }
 */
app.post('/api/patrols', verifyTokenMiddleware, async (req, res) => {
  try {
    const { start_time, user_id, organization_id, duration, end_time, map, location_data } = req.body;

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
      duration: typeof duration === 'number' ? duration : null,
      end_time: end_time || null,
      map: normalizeMapValue(map !== undefined ? map : location_data),
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
 * Body: { duration?, start_time?, end_time?, map?, location_data?, status? }
 */
app.patch('/api/patrols/:id', verifyTokenMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    // console.log("Param id:", id)
    const {
      duration,
      end_time,
      map,
      location_data,
      status
    } = req.body;

    // console.log("Data body:", req.body)

    // Build update data - use 'map' field as per Directus collection schema
    const updateData = {};
    
    if (typeof duration === 'number') {
      updateData.duration = duration;
    }
    if (end_time) {
      updateData.end_time = end_time;
    }
    if (map) {
      updateData.map = normalizeMapValue(map);
    } else if (location_data) {
      updateData.map = normalizeMapValue(location_data);
    }
    if (status) {
      updateData.status = status;
    }

    // If end_time is provided, set status to completed
    if (end_time && !status) {
      updateData.status = 'completed';
    }

    // Update patrol in Directus. If duration is rejected by schema/permissions,
    // retry without duration so patrol completion still gets recorded.
    let response;
    try {
      response = await query(`/items/patrols/${id}`, {
        method: 'PATCH',
        data: updateData,
      });
    } catch (updateError) {
      const hasDuration = Object.prototype.hasOwnProperty.call(updateData, 'duration');
      if (!hasDuration) {
        throw updateError;
      }

      const fallbackData = { ...updateData };
      delete fallbackData.duration;

      response = await query(`/items/patrols/${id}`, {
        method: 'PATCH',
        data: fallbackData,
      });

      return res.json({
        message: 'Patrol updated, but duration was not persisted',
        warning: 'duration_not_saved',
        data: response.data.data,
        details: updateError.response?.data || updateError.message,
      });
    }

    res.json({
      message: 'Patrol updated successfully',
      data: response.data.data
    });
  } catch (error) {
    console.error('Error updating patrol:', error);
    const statusCode = error.response?.status || 500;
    res.status(statusCode).json({
      error: 'Internal Server Error',
      message: 'Failed to update patrol',
      details: error.response?.data || error.message
    });
  }
});

/**
 * PATCH /api/patrols/:id/location
 * Update patrol location incrementally (append new points to existing map data)
 * Body: { location_data: [{ latitude, longitude, timestamp }, ...] }
 * This endpoint fetches existing map data, appends new points, and saves back
 */
app.patch('/api/patrols/:id/location', verifyTokenMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { location_data } = req.body;

    if (!location_data || !Array.isArray(location_data)) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'location_data array is required'
      });
    }

    // Fetch existing patrol to get current map data
    const patrolResponse = await query(`/items/patrols/${id}`);
    
    if (!patrolResponse.data.data) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'Patrol not found'
      });
    }

    const existingMapData = patrolResponse.data.data.map;
    let existingLocations = [];

    // Parse existing map data if it exists
    if (existingMapData) {
      if (Array.isArray(existingMapData)) {
        existingLocations = existingMapData;
      } else if (typeof existingMapData === 'string') {
        const trimmedMap = existingMapData.trim();
        if (trimmedMap === '[object Object]') {
          existingLocations = [];
        } else {
          try {
            existingLocations = JSON.parse(existingMapData);
            if (!Array.isArray(existingLocations)) {
              existingLocations = [];
            }
          } catch (parseError) {
            console.error('Error parsing existing map data:', parseError);
            existingLocations = [];
          }
        }
      } else if (typeof existingMapData === 'object') {
        if (Array.isArray(existingMapData.location_data)) {
          existingLocations = existingMapData.location_data;
        } else {
          existingLocations = [existingMapData];
        }
      }
    }

    // Append new location points
    const updatedLocations = [...existingLocations, ...location_data];

    // Update patrol with new map data
    const updateData = {
      map: JSON.stringify(updatedLocations)
    };

    const response = await query(`/items/patrols/${id}`, {
      method: 'PATCH',
      data: updateData
    });

    res.json({
      message: 'Location updated successfully',
      data: response.data.data,
      points_count: updatedLocations.length
    });
  } catch (error) {
    console.error('Error updating patrol location:', error);
    const statusCode = error.response?.status || 500;
    res.status(statusCode).json({
      error: 'Internal Server Error',
      message: 'Failed to update patrol location',
      details: error.response?.data || error.message
    });
  }
});

// ============================================
// LOGS ROUTES
// ============================================

/**
 * GET /api/logs
 * Get all logs for the logged-in guard
 * Query params: limit (optional), sort (optional)
 */
app.get('/api/logs', verifyTokenMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const limit = req.query.limit || 50;
    const sort = req.query.sort || '-timestamp';

    // Fetch logs for this guard from Directus
    const response = await query(`/items/logs?filter[user_id][_eq]=${userId}&sort=${sort}&limit=${limit}`);

    res.json({
      logs: response.data.data
    });
  } catch (error) {
    console.error('Error fetching logs:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to fetch logs'
    });
  }
});

/**
 * POST /api/logs
 * Create a new log entry
 * Body: { title, description, category, images?, patrol_id? }
 */
app.post('/api/logs', verifyTokenMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { title, description, category, images, patrol_id } = req.body;

    // console.log("Body:", req.body)

    // Validate required fields
    if (!title || !description || !category) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'title, description, and category are required'
      });
    }

    // Validate category
    const validCategories = ['activity', 'unusual', 'incident', 'checkpoint', 'other'];
    if (!validCategories.includes(category)) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'category must be one of: activity, unusual, incident, checkpoint, other'
      });
    }

    // Create log in Directus
    const logData = {
      title,
      description,
      category,
      user_id: userId,
      patrol_id: patrol_id || null,
      images: images || null,
      timestamp: new Date().toISOString(),
    };

    const response = await query('/items/logs', {
      method: 'POST',
      data: logData,
    });

    res.status(201).json({
      message: 'Log created successfully',
      data: response.data.data
    });
  } catch (error) {
    console.error('Error creating log:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to create log'
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
