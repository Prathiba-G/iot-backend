const express = require("express");
const multer = require("multer");
const cors = require("cors");
const fs = require("fs");
const path = require("path");

const app = express();

// ============================================
// FORCE PORT 5000 - HARDCODED (NO process.env.PORT)
// ============================================
const PORT = 5000;

// ============================================
// STARTUP VALIDATION
// ============================================
console.log("========================================");
console.log("🔍 Starting backend validation...");

// Check required dependencies
const requiredModules = ['express', 'multer', 'cors'];
const missingModules = [];

for (const mod of requiredModules) {
  try {
    require.resolve(mod);
    console.log(`✅ ${mod} installed`);
  } catch (e) {
    missingModules.push(mod);
    console.log(`❌ ${mod} MISSING`);
  }
}

if (missingModules.length > 0) {
  console.error("========================================");
  console.error("❌ FATAL: Missing dependencies!");
  console.error(`   Run: npm install ${missingModules.join(' ')}`);
  console.error("========================================");
  process.exit(1);
}

// ============================================
// REQUEST LOGGING MIDDLEWARE
// ============================================
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  const origin = req.headers.origin || 'no origin';
  console.log(`[${timestamp}] ${req.method} ${req.url} - Origin: ${origin}`);
  next();
});

// ============================================
// CORS CONFIGURATION - LOCALHOST ONLY
// ============================================
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
  'http://localhost:5174',
  'http://localhost:8080',
  'http://localhost:5000',
  'https://localhost:3000',
  'https://localhost:5173',
  'https://localhost:5174',
  'https://localhost:8080',
  'https://localhost:5000',
  'https://neotechembeddedservices.in',
  'https://www.neotechembeddedservices.in'
];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, curl, Postman, etc.)
    if (!origin) {
      console.log(`CORS: Allowing request with no origin (mobile/curl)`);
      return callback(null, true);
    }
    
    // For localhost development, allow any localhost port
    if (origin.match(/^https?:\/\/localhost(:[0-9]+)?$/)) {
      console.log(`CORS: Allowing localhost origin ${origin}`);
      return callback(null, true);
    }
    
    // Check if origin is in allowed list
    if (allowedOrigins.includes(origin)) {
      console.log(`CORS: Allowing origin ${origin}`);
      return callback(null, true);
    }
    
    console.log(`CORS: Blocking origin ${origin}`);
    callback(new Error('CORS policy: Origin not allowed'), false);
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'Origin', 'X-Requested-With', 'Access-Control-Allow-Origin'],
  exposedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  preflightContinue: false,
  optionsSuccessStatus: 204
}));

// Handle preflight requests explicitly
app.options('*', cors());

// ============================================
// BODY PARSING MIDDLEWARE
// ============================================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================
// UPLOADS DIRECTORY SETUP
// ============================================
const uploadsDir = path.join(__dirname, "uploads");

// Create uploads directory if it doesn't exist
try {
  if (!fs.existsSync(uploadsDir)) {
    console.log(`⚠️  Uploads directory missing, creating: ${uploadsDir}`);
    fs.mkdirSync(uploadsDir, { recursive: true });
    console.log(`📁 Created uploads directory: ${uploadsDir}`);
  } else {
    console.log(`📁 Uploads directory exists: ${uploadsDir}`);
  }
} catch (err) {
  console.error(`❌ Failed to create uploads directory: ${err.message}`);
  process.exit(1);
}

// Serve uploaded files statically at /uploads (legacy) and /images (frontend)
app.use("/uploads", express.static(uploadsDir));
app.use("/images", express.static(uploadsDir));


// ============================================
// MULTER CONFIGURATION
// ============================================
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const safeFilename = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
    cb(null, `${uniqueSuffix}-${safeFilename}`);
  },
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    // Accept only image files
    if (file.mimetype && file.mimetype.startsWith("image/")) {
      console.log(`📸 Accepting file: ${file.originalname} (${file.mimetype})`);
      cb(null, true);
    } else {
      console.log(`🚫 Rejecting file: ${file.originalname} (${file.mimetype})`);
      cb(new Error("Only image files are allowed!"), false);
    }
  },
});

// ============================================
// MULTER ERROR HANDLING MIDDLEWARE
// ============================================
const handleMulterError = (err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    console.error(`❌ Multer error: ${err.code} - ${err.message}`);
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({ 
        success: false,
        error: "File too large. Max 10MB allowed." 
      });
    }
    return res.status(400).json({ 
      success: false,
      error: err.message 
    });
  }
  
  if (err) {
    console.error(`❌ Upload error: ${err.message}`);
    return res.status(400).json({ 
      success: false,
      error: err.message 
    });
  }
  
  next();
};

// ============================================
// ROUTES
// ============================================

// ROOT ROUTE - Health Check
app.get("/", (req, res) => {
  console.log("🏥 Health check requested");
  res.json({ 
    status: "alive",
    message: "Backend server is running",
    port: PORT,
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// LOGIN ROUTE
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    
    console.log(`🔐 Login attempt for user: ${username}`);

    if (!username || !password) {
      console.log(`⚠️ Login failed: Missing credentials`);
      return res.status(400).json({ 
        success: false, 
        message: "Username and password required" 
      });
    }

    if (username === "admin" && password === "admin123") {
      console.log(`✅ Login successful for: ${username}`);
      return res.json({ success: true });
    }

    console.log(`❌ Login failed for: ${username} - Invalid credentials`);
    res.status(401).json({ 
      success: false, 
      message: "Invalid credentials" 
    });
  } catch (err) {
    console.error(`❌ Login error: ${err.message}`);
    res.status(500).json({ 
      success: false, 
      message: "Internal server error" 
    });
  }
});

// UPLOAD ROUTE
app.post("/api/upload", upload.single("image"), handleMulterError, (req, res) => {
  console.log(`📤 Upload request received`);
  
  if (!req.file) {
    console.log(`❌ Upload failed: No file in request`);
    return res.status(400).json({ 
      success: false,
      error: "No file uploaded" 
    });
  }

  const filePath = `/uploads/${req.file.filename}`;
  console.log(`✅ Upload successful: ${req.file.originalname} -> ${req.file.filename}`);

  res.json({ 
    success: true,
    message: "File uploaded successfully",
    filename: req.file.filename,
    originalName: req.file.originalname,
    filePath: filePath,
    size: req.file.size
  });
});

// GET IMAGES ROUTE
app.get("/api/images", async (req, res) => {
  try {
    console.log(`📋 Listing images from: ${uploadsDir}`);
    
    const files = await fs.promises.readdir(uploadsDir);
    const imageFiles = files.filter(file => {
      const ext = path.extname(file).toLowerCase();
      return ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp'].includes(ext);
    });
    
    console.log(`📸 Found ${imageFiles.length} images`);
    res.json(imageFiles);
  } catch (err) {
    console.error(`❌ Error reading uploads directory: ${err.message}`);
    res.status(500).json({ 
      success: false,
      error: "Failed to read images directory" 
    });
  }
});

// DELETE IMAGE ROUTE
app.delete("/api/images/:filename", async (req, res) => {
  try {
    const filename = req.params.filename;
    // Security: Prevent directory traversal
    const safeFilename = path.basename(filename);
    const filePath = path.join(uploadsDir, safeFilename);
    
    console.log(`🗑️ Delete request for: ${safeFilename}`);

    // Check if file exists
    try {
      await fs.promises.access(filePath, fs.constants.F_OK);
    } catch {
      console.log(`❌ File not found: ${safeFilename}`);
      return res.status(404).json({ 
        success: false,
        error: "File not found" 
      });
    }

    await fs.promises.unlink(filePath);
    console.log(`✅ Deleted: ${safeFilename}`);
    
    res.json({ 
      success: true,
      message: "File deleted successfully",
      filename: safeFilename
    });
  } catch (err) {
    console.error(`❌ Delete error: ${err.message}`);
    res.status(500).json({ 
      success: false,
      error: "Failed to delete file" 
    });
  }
});

// ============================================
// ERROR HANDLERS
// ============================================

// Global Error Handler
app.use((err, req, res, next) => {
  console.error(`[ERROR] ${req.method} ${req.url}:`, err.message);
  if (err.stack) {
    console.error(err.stack);
  }
  
  // Don't leak error details in production
  const message = err.message || "Internal server error";
  
  res.status(err.status || 500).json({ 
    success: false,
    error: message,
    path: req.url,
    method: req.method
  });
});

// 404 Handler
app.use((req, res) => {
  console.log(`[404] Route not found: ${req.method} ${req.url}`);
  res.status(404).json({ 
    success: false,
    error: "API route not found", 
    path: req.url,
    method: req.method
  });
});

// ============================================
// GLOBAL ERROR HANDLERS
// ============================================

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error("========================================");
  console.error("❌ UNCAUGHT EXCEPTION:");
  console.error(err);
  console.error("========================================");
  // Graceful shutdown
  server.close(() => {
    process.exit(1);
  });
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error("========================================");
  console.error("❌ UNHANDLED REJECTION at:", promise);
  console.error("Reason:", reason);
  console.error("========================================");
});

// ============================================
// START SERVER
// ============================================
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log("========================================");
  console.log(`✅ Backend server STARTED successfully`);
  console.log(`🌐 Server URL: http://localhost:${PORT}`);
  console.log(`📁 Uploads directory: ${uploadsDir}`);
  console.log(`🚀 Health check: http://localhost:${PORT}/`);
  console.log(`📡 API Endpoints:`);
  console.log(`   POST http://localhost:${PORT}/api/login`);
  console.log(`   POST http://localhost:${PORT}/api/upload`);
  console.log(`   GET  http://localhost:${PORT}/api/images`);
  console.log(`   DELETE http://localhost:${PORT}/api/images/:filename`);
  console.log("========================================");
});

// Handle server startup errors
server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error("========================================");
    console.error(`❌ ERROR: Port ${PORT} is already in use!`);
    console.error(`   Another instance of this server may be running.`);
    console.error(`   Run this command to fix: .\\port-fix.ps1`);
    console.error("========================================");
    process.exit(1);
  } else {
    console.error("========================================");
    console.error('❌ Server error:', err);
    console.error("========================================");
    process.exit(1);
  }
});

// Graceful shutdown handlers
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

console.log("⏳ Initializing server...");
