# OmniWatch Backend

Express.js API backend for the OmniWatch guard monitoring mobile application.

## Prerequisites

- Node.js (v18 or higher)
- MongoDB (local or Atlas cloud)

## Setup

1. **Install Dependencies**
   ```bash
   node scripts/generate-package-json.cjs
   npm install
   ```

2. **Configure Environment**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` with your settings:
   ```env
   PORT=5000
   MONGODB_URI=mongodb://localhost:27017/omniwatch
   JWT_SECRET=your_super_secret_jwt_key_change_in_production
   ```

3. **Start MongoDB**
   - Local: Make sure MongoDB is running
   - Cloud: Update `MONGODB_URI` with your Atlas connection string

## Running the Server

**Development mode (auto-restart on changes):**
```bash
npm run dev
```

**Production mode:**
```bash
npm start
```

Server runs at `http://localhost:5000`

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register new user |
| POST | `/api/auth/login` | Login user |
| GET | `/api/auth/me` | Get current user profile |

### Users (Protected)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/users/guards` | Get all guards (supervisor/admin) |
| GET | `/api/users/supervisors` | Get all supervisors (admin) |
| PUT | `/api/users/profile` | Update profile |
| PUT | `/api/users/:id/deactivate` | Deactivate user |
| PUT | `/api/users/:id/activate` | Activate user |

### Patrols
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/patrols` | Start new patrol (guard) |
| POST | `/api/patrols/:id/checkpoint` | Add checkpoint |
| PUT | `/api/patrols/:id/end` | End patrol |
| GET | `/api/patrols/my` | Get my patrols (guard) |
| GET | `/api/patrols` | Get all patrols (supervisor/admin) |
| GET | `/api/patrols/:id` | Get patrol details |

## Project Structure

```
backend/
├── config/
│   └── db.js              # MongoDB connection
├── controllers/
│   ├── authController.js  # Auth logic
│   └── patrolController.js # Patrol logic
├── middleware/
│   └── auth.js            # JWT auth & role middleware
├── models/
│   ├── User.js            # User schema
│   └── Patrol.js          # Patrol schema
├── routes/
│   ├── auth.js            # Auth routes
│   ├── patrols.js         # Patrol routes
│   └── users.js           # User routes
├── .env.example           # Environment template
├── package.cjs
├── scripts/
│   └── generate-package-json.cjs
└── server.js              # Entry point
```

## User Roles

- **guard**: Can manage their own patrols and checkpoints
- **supervisor**: Can view all patrols, manage guards
- **admin**: Full access to all features

## Testing with React Native

Update your API base URL in the app to point to your computer's IP:

```javascript
const API_BASE_URL = 'http://YOUR_IP_ADDRESS:5000/api';
```

For Android emulator, use `http://10.0.2.2:5000/api`
For iOS simulator, use `http://localhost:5000/api`
