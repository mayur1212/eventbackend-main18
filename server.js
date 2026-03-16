// server.js (full updated file)

require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const http = require("http");
const Event = require("./models/Event"); // Your Mongoose model

const app = express();
const PORT = process.env.PORT || 5000;
const normalizeOrigin = (value) => {
  const raw = String(value || "").trim();
  if (!raw) return "";
  try {
    const parsed = new URL(raw);
    if (!["http:", "https:"].includes(parsed.protocol)) return "";
    return parsed.origin;
  } catch (err) {
    return raw;
  }
};

const ADMIN_EMAILS = [
  "takkemayur456@gmail.com",
  "digambarmarathe.9@gmail.com",
  "digambarmarathe.380@gmail.com",
].map((value) => String(value).toLowerCase());

const ALLOWED_FRONTEND_ORIGINS = Array.from(
  new Set(
    [
      "https://eventfrontend-main.onrender.com",
      "http://localhost:3000",
      "https://artiststation.co.in",
      process.env.CLIENT_URL,
      process.env.FRONTEND_URL,
      ...(process.env.ALLOWED_FRONTEND_ORIGINS || "").split(","),
    ]
      .map((value) => normalizeOrigin(value))
      .filter(Boolean)
  )
);

const PRIMARY_FRONTEND_ORIGIN =
  ALLOWED_FRONTEND_ORIGINS[0] || "http://localhost:3000";
const DEFAULT_GOOGLE_FRONTEND_CALLBACK = `${PRIMARY_FRONTEND_ORIGIN.replace(
  /\/$/,
  ""
)}/auth/google/callback`;

// ======================== Ensure Uploads Folder ========================
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

// ======================== Request logging (debug) ========================
// Place this early so all incoming requests are logged
app.use((req, res, next) => {
  console.log(`⤴️  Incoming -> ${req.method} ${req.originalUrl}`);
  next();
});

// ======================== Middleware ========================
app.use(
  cors({
    origin: ALLOWED_FRONTEND_ORIGINS,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

app.use(express.json({ limit: "10mb" }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use("/uploads", express.static(uploadDir)); // serve images

// ======================== MongoDB Connection ========================
/* mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("✅ MongoDB Connected");
    const server = http.createServer(app);
    server.listen(PORT, () =>
      console.log(`🚀 Server running on port ${PORT} (HTTP/1.1)`)
    );
  })
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));

*/

const MONGO_URI = String(process.env.MONGO_URI || "").trim();

const getMongoServerDiagnostics = (err) => {
  const serverMap = err && err.reason && err.reason.servers;
  if (!serverMap || typeof serverMap.forEach !== "function") return [];

  const diagnostics = [];
  serverMap.forEach((server, address) => {
    const details =
      (server && (server.error || server.lastErrorObject || server.reason)) || null;
    diagnostics.push({
      address,
      type: server && server.type ? server.type : "Unknown",
      error:
        details && details.message
          ? details.message
          : details
          ? String(details)
          : "No detailed error available",
    });
  });

  return diagnostics;
};

const startServer = async () => {
  if (!MONGO_URI) {
    console.error("MongoDB startup error: MONGO_URI is missing in .env");
    process.exit(1);
  }

  try {
    await mongoose.connect(MONGO_URI, {
      serverSelectionTimeoutMS: 15000,
      connectTimeoutMS: 15000,
    });

    console.log("MongoDB connected");
    const server = http.createServer(app);
    server.listen(PORT, () => {
      console.log(`Server running on port ${PORT} (HTTP/1.1)`);
    });
  } catch (err) {
    console.error("MongoDB connection error:", err && err.message ? err.message : err);
    const diagnostics = getMongoServerDiagnostics(err);
    if (diagnostics.length) {
      console.error("MongoDB server diagnostics:");
      diagnostics.forEach((item) => {
        console.error(`- ${item.address} [${item.type}]: ${item.error}`);
      });
    }
    process.exit(1);
  }
};

startServer();

// ======================== JWT Middleware ========================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader)
    return res.status(401).json({ message: "Authorization header missing" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Token missing" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Invalid or expired token" });
    req.user = decoded;
    next();
  });
};

// ======================== Multer Config ========================
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) =>
    cb(null, `${Date.now()}-${file.originalname.replace(/\s+/g, "-")}`),
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif/;
    allowedTypes.test(file.mimetype)
      ? cb(null, true)
      : cb(new Error("Only image files allowed."));
  },
});

const SEND_OTP_ROUTE_PATHS = [
  "/forgot-password",
  "/forgot-password-otp",
  "/send-reset-otp",
];

const RESET_OTP_ROUTE_PATHS = [
  "/reset-password-with-otp",
  "/reset-password/otp",
  "/reset-password",
];

const OTP_EXPIRY_MS = 10 * 60 * 1000;

const mailTransporter =
  process.env.EMAIL_USER && process.env.EMAIL_PASS
    ? nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS.replace(/\s+/g, ""),
        },
      })
    : null;

const generateOtp = () =>
  String(Math.floor(100000 + Math.random() * 900000));

const normalizeEmail = (value) => String(value || "").trim().toLowerCase();

const getRoleForEmail = (email) =>
  ADMIN_EMAILS.includes(normalizeEmail(email)) ? "admin" : "user";

const isHttpUrl = (value) => /^https?:\/\//i.test(String(value || ""));

const getServerBaseUrl = (req) =>
  process.env.BASE_URL || `${req.protocol}://${req.get("host")}`;

const getPublicProfileImg = (profileImg, req) => {
  const value = String(profileImg || "").trim();
  if (!value) return "";
  if (isHttpUrl(value)) return value;
  const baseUrl = getServerBaseUrl(req);
  return `${baseUrl}${value.startsWith("/") ? value : `/${value}`}`;
};

const toClientUser = (user, token, req) => ({
  id: String(user._id),
  _id: String(user._id),
  name: user.clientName || "User",
  clientName: user.clientName || "User",
  email: normalizeEmail(user.email),
  contactNumber: user.contactNumber || "",
  role: user.role || getRoleForEmail(user.email),
  profileImg: getPublicProfileImg(user.profileImg, req),
  token: token || "",
});

const resolveFrontendRedirect = (rawRedirect) => {
  if (!rawRedirect) return DEFAULT_GOOGLE_FRONTEND_CALLBACK;
  try {
    const parsed = new URL(String(rawRedirect), PRIMARY_FRONTEND_ORIGIN);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return DEFAULT_GOOGLE_FRONTEND_CALLBACK;
    }
    if (!ALLOWED_FRONTEND_ORIGINS.includes(parsed.origin)) {
      return DEFAULT_GOOGLE_FRONTEND_CALLBACK;
    }
    return parsed.toString();
  } catch (err) {
    return DEFAULT_GOOGLE_FRONTEND_CALLBACK;
  }
};

const appendQueryParamsToUrl = (baseUrl, params = {}) => {
  const targetUrl = new URL(baseUrl);
  Object.entries(params).forEach(([key, value]) => {
    if (value != null && String(value).trim() !== "") {
      targetUrl.searchParams.set(key, String(value));
    }
  });
  return targetUrl.toString();
};

const getGoogleOAuthConfig = () => {
  const config = {
    clientId: String(process.env.GOOGLE_CLIENT_ID || "").trim(),
    clientSecret: String(process.env.GOOGLE_CLIENT_SECRET || "").trim(),
    redirectUri: String(process.env.GOOGLE_REDIRECT_URI || "").trim(),
  };

  if (!config.clientId || !config.clientSecret || !config.redirectUri) {
    throw new Error(
      "Google OAuth env is incomplete. Required: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI."
    );
  }

  return config;
};

const createOAuthState = (frontendRedirect) =>
  jwt.sign(
    {
      frontendRedirect,
      nonce: crypto.randomBytes(12).toString("hex"),
    },
    process.env.JWT_SECRET,
    { expiresIn: "10m" }
  );

const parseOAuthState = (state) => {
  if (!state) return null;
  try {
    return jwt.verify(String(state), process.env.JWT_SECRET);
  } catch (err) {
    return null;
  }
};

const exchangeGoogleCodeForToken = async ({ code, clientId, clientSecret, redirectUri }) => {
  const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code: String(code),
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
    }),
  });

  if (!tokenResponse.ok) {
    const details = await tokenResponse.text();
    throw new Error(`Google token exchange failed (${tokenResponse.status}). ${details}`);
  }

  const tokenData = await tokenResponse.json();
  if (!tokenData.access_token) {
    throw new Error("Google token response missing access token.");
  }

  return tokenData;
};

const fetchGoogleProfile = async (accessToken) => {
  const userInfoResponse = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!userInfoResponse.ok) {
    const details = await userInfoResponse.text();
    throw new Error(`Google user profile request failed (${userInfoResponse.status}). ${details}`);
  }

  return userInfoResponse.json();
};

// =============================================================
// ======================== API ROUTES ==========================
// =============================================================

// ------------------------ Debug/Health ------------------------
app.get("/api/ping", (req, res) => {
  console.log("🟢 GET /api/ping");
  res.json({ ok: true, env: process.env.NODE_ENV || "unknown" });
});

app.get("/api/auth/google", (req, res) => {
  try {
    const { clientId, redirectUri } = getGoogleOAuthConfig();
    const frontendRedirect = resolveFrontendRedirect(
      req.query.redirect || req.query.redirect_uri
    );
    const state = createOAuthState(frontendRedirect);

    const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    authUrl.searchParams.set("client_id", clientId);
    authUrl.searchParams.set("redirect_uri", redirectUri);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("scope", "openid email profile");
    authUrl.searchParams.set("state", state);
    authUrl.searchParams.set("access_type", "offline");
    authUrl.searchParams.set("prompt", "select_account");

    return res.redirect(authUrl.toString());
  } catch (err) {
    console.error("Google auth start error:", err);
    return res.status(500).json({
      message: err.message || "Google auth is not configured correctly.",
    });
  }
});

app.get("/api/auth/google/callback", async (req, res) => {
  const fallbackRedirect = resolveFrontendRedirect(
    req.query.redirect || req.query.redirect_uri
  );
  const statePayload = parseOAuthState(req.query.state);
  const frontendRedirect = resolveFrontendRedirect(
    statePayload?.frontendRedirect || fallbackRedirect
  );

  const redirectWithPayload = (payload) =>
    res.redirect(appendQueryParamsToUrl(frontendRedirect, payload));

  if (req.query.error) {
    return redirectWithPayload({
      error: req.query.error_description || req.query.error,
    });
  }

  if (!statePayload) {
    return redirectWithPayload({ error: "Invalid or expired OAuth state." });
  }

  if (!req.query.code) {
    return redirectWithPayload({ error: "Google callback missing authorization code." });
  }

  try {
    const { clientId, clientSecret, redirectUri } = getGoogleOAuthConfig();
    const tokenData = await exchangeGoogleCodeForToken({
      code: req.query.code,
      clientId,
      clientSecret,
      redirectUri,
    });

    const googleProfile = await fetchGoogleProfile(tokenData.access_token);
    const email = normalizeEmail(googleProfile.email);
    if (!email) throw new Error("Google account did not provide an email address.");

    let user = await Event.findOne({ email });
    if (!user) {
      const randomPassword = crypto.randomBytes(24).toString("hex");
      const now = new Date();

      user = await Event.create({
        eventName: `Google Signup (${email})`,
        clientName: googleProfile.name || "Google User",
        contactNumber: "0000000000",
        email,
        password: await bcrypt.hash(randomPassword, 10),
        venue: "Google OAuth",
        city: "N/A",
        startDate: now,
        endDate: now,
        profileImg: googleProfile.picture || "",
        role: getRoleForEmail(email),
      });
    } else {
      let shouldSave = false;
      const resolvedRole = getRoleForEmail(email);
      if (user.role !== resolvedRole) {
        user.role = resolvedRole;
        shouldSave = true;
      }
      if (googleProfile.picture && user.profileImg !== googleProfile.picture) {
        user.profileImg = googleProfile.picture;
        shouldSave = true;
      }
      if (!user.clientName && googleProfile.name) {
        user.clientName = googleProfile.name;
        shouldSave = true;
      }
      if (shouldSave) await user.save();
    }

    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    const safeUser = toClientUser(user, token, req);
    return redirectWithPayload({
      token,
      user: JSON.stringify(safeUser),
    });
  } catch (err) {
    console.error("Google auth callback error:", err);
    return redirectWithPayload({
      error: err.message || "Google sign-in failed.",
    });
  }
});

// TEMP: debug route to test multer/form-data without auth
// REMOVE or protect this route after you finish debugging.
app.post("/api/update-profile-debug", upload.single("profileImg"), async (req, res) => {
  console.log("🔧 Hit /api/update-profile-debug", {
    body: req.body,
    file: req.file && req.file.filename,
  });
  res.json({ success: true, message: "debug ok", body: req.body, file: req.file ? req.file.filename : null });
});

const handleForgotPasswordOtp = async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    if (!email) return res.status(400).json({ message: "Email is required" });

    const user = await Event.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    if (!mailTransporter) {
      return res
        .status(500)
        .json({ message: "Email service not configured on server" });
    }

    const otp = generateOtp();
    user.resetToken = await bcrypt.hash(otp, 10);
    user.resetTokenExpiry = new Date(Date.now() + OTP_EXPIRY_MS);
    await user.save();

    await mailTransporter.sendMail({
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: "OTP for Password Reset",
      text: `Your OTP for password reset is ${otp}. It expires in 10 minutes.`,
    });

    return res.json({ message: "OTP sent successfully" });
  } catch (err) {
    console.error("Forgot password OTP error:", err);
    return res.status(500).json({ message: "Unable to send OTP" });
  }
};

const handleResetPasswordWithOtp = async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const otp = String(req.body?.otp || "").trim();
    const newPassword = String(
      req.body?.newPassword || req.body?.password || ""
    ).trim();
    const confirmPassword = req.body?.confirmPassword;

    if (!email || !otp || !newPassword) {
      return res
        .status(400)
        .json({ message: "Email, OTP and new password are required" });
    }
    if (!/^\d{4,8}$/.test(otp)) {
      return res.status(400).json({ message: "OTP must be 4 to 8 digits" });
    }
    if (newPassword.length < 6) {
      return res
        .status(400)
        .json({ message: "Password must be at least 6 characters" });
    }
    if (confirmPassword != null && newPassword !== String(confirmPassword)) {
      return res.status(400).json({ message: "Passwords do not match" });
    }

    const user = await Event.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    if (!user.resetToken || !user.resetTokenExpiry) {
      return res.status(400).json({ message: "OTP not requested" });
    }

    if (new Date(user.resetTokenExpiry).getTime() < Date.now()) {
      user.resetToken = null;
      user.resetTokenExpiry = null;
      await user.save();
      return res.status(400).json({ message: "OTP expired. Please resend OTP." });
    }

    const isOtpValid = await bcrypt.compare(otp, user.resetToken);
    if (!isOtpValid) return res.status(400).json({ message: "Invalid OTP" });

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetToken = null;
    user.resetTokenExpiry = null;
    await user.save();

    return res.json({ message: "Password reset successful" });
  } catch (err) {
    console.error("Reset password OTP error:", err);
    return res.status(500).json({ message: "Unable to reset password" });
  }
};

SEND_OTP_ROUTE_PATHS.forEach((routePath) => {
  app.post(routePath, handleForgotPasswordOtp);
  app.post(`/api${routePath}`, handleForgotPasswordOtp);
});

RESET_OTP_ROUTE_PATHS.forEach((routePath) => {
  app.post(routePath, handleResetPasswordWithOtp);
  app.post(`/api${routePath}`, handleResetPasswordWithOtp);
});

// ======================== REGISTER ========================
app.post("/api/register", async (req, res) => {
  try {
    const {
      eventName,
      clientName,
      contactNumber,
      email,
      password,
      venue,
      city,
      startDate,
      endDate,
    } = req.body;

    const normalizedEmail = normalizeEmail(email);
    const existing = await Event.findOne({ email: normalizedEmail });
    if (existing) return res.status(400).json({ message: "Email already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newEvent = new Event({
      eventName,
      clientName,
      contactNumber,
      email: normalizedEmail,
      password: hashedPassword,
      venue,
      city,
      startDate,
      endDate,
    });

    await newEvent.save();

    let message = "Registration successful!";
    if (mailTransporter) {
      try {
        await mailTransporter.sendMail({
          from: process.env.EMAIL_USER,
          to: newEvent.email,
          subject: "Registration Successful",
          text: `Hello ${newEvent.clientName}, your registration for ${newEvent.eventName} is successful.`,
        });
      } catch (mailErr) {
        console.error("Registration confirmation email error:", mailErr);
        message = "Registration successful, but confirmation email could not be sent.";
      }
    } else {
      message = "Registration successful, but email service is not configured.";
    }

    res.status(201).json({ message });
  } catch (err) {
    console.error("Register Error:", err);
    res.status(500).json({ message: "Server error during registration" });
  }
});

// ======================== LOGIN ========================
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await Event.findOne({ email: normalizeEmail(email) });
    if (!user) return res.status(400).json({ message: "User not found" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ message: "Login successful!", token });
  } catch (err) {
    res.status(500).json({ message: "Server error during login" });
  }
});

// ======================== FETCH CURRENT USER ========================
app.get("/api/me", authenticateToken, async (req, res) => {
  try {
    const user = await Event.findById(req.user.id).select("-password -__v");
    if (!user) return res.status(404).json({ message: "User not found" });

    const userObj = user.toObject();
    userObj.profileImg = getPublicProfileImg(userObj.profileImg, req);

    res.json({ success: true, user: userObj });
  } catch (err) {
    res.status(500).json({ message: "Error fetching user data" });
  }
});

// ======================== UPDATE PROFILE (with image) ========================
app.post(
  "/api/update-profile",
  authenticateToken,
  upload.single("profileImg"),
  async (req, res) => {
    console.log("🔹 Hit /api/update-profile");

    try {
      const { clientName, contactNumber, email } = req.body;
      const user = await Event.findById(req.user.id);

      if (!user)
        return res.status(404).json({ success: false, message: "User not found" });

      // Delete old image if new uploaded
      if (req.file && user.profileImg && !isHttpUrl(user.profileImg)) {
        const oldPath = path.join(uploadDir, path.basename(user.profileImg));
        if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
      }

      user.clientName = clientName || user.clientName;
      user.contactNumber = contactNumber || user.contactNumber;
      user.email = email || user.email;

      if (req.file) {
        user.profileImg = `/uploads/${req.file.filename}`;
      }

      await user.save();

      return res.json({
        success: true,
        message: "Profile updated successfully",
        user: {
          clientName: user.clientName,
          email: user.email,
          contactNumber: user.contactNumber,
          profileImg: getPublicProfileImg(user.profileImg, req) || null,
        },
      });
    } catch (err) {
      console.error("Update profile error:", err);
      res.status(500).json({
        success: false,
        message: "Server error while updating profile",
      });
    }
  }
);

// ======================== REMOVE PROFILE IMAGE ========================
app.delete("/api/remove-profile-image", authenticateToken, async (req, res) => {
  try {
    const user = await Event.findById(req.user.id);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    if (user.profileImg && !isHttpUrl(user.profileImg)) {
      const imgPath = path.join(uploadDir, path.basename(user.profileImg));
      if (fs.existsSync(imgPath)) fs.unlinkSync(imgPath);
    }

    user.profileImg = undefined;
    await user.save();

    res.status(200).json({
      success: true,
      message: "Profile image removed successfully",
      user: { ...user.toObject(), profileImg: null },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error removing image" });
  }
});

// =============================================================
// ======================== EVENTS CRUD =========================
// =============================================================
app.get("/api/events", async (req, res) => {
  try {
    const events = await Event.find({}, { password: 0, __v: 0 });
    res.json(events);
  } catch (err) {
    res.status(500).json({ message: "Error fetching events" });
  }
});

app.get("/api/events/:id", async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    if (!event) return res.status(404).json({ message: "Event not found" });
    res.json(event);
  } catch (err) {
    res.status(500).json({ message: "Error fetching event" });
  }
});

app.post("/api/events", async (req, res) => {
  try {
    const {
      eventName,
      clientName,
      contactNumber,
      email,
      password,
      venue,
      city,
      startDate,
      endDate,
    } = req.body;

    const existing = await Event.findOne({ email });
    if (existing) return res.status(400).json({ message: "Email already exists for another event." });

    const hashedPassword = password ? await bcrypt.hash(password, 10) : null;
    const newEvent = new Event({
      eventName,
      clientName,
      contactNumber,
      email,
      password: hashedPassword,
      venue,
      city,
      startDate,
      endDate,
    });

    await newEvent.save();
    res.status(201).json(newEvent);
  } catch (err) {
    res.status(500).json({ message: "Error creating event" });
  }
});

app.put("/api/events/:id", async (req, res) => {
  try {
    const {
      eventName,
      clientName,
      contactNumber,
      email,
      password,
      venue,
      city,
      startDate,
      endDate,
    } = req.body;

    const event = await Event.findById(req.params.id);
    if (!event) return res.status(404).json({ message: "Event not found" });

    event.eventName = eventName ?? event.eventName;
    event.clientName = clientName ?? event.clientName;
    event.contactNumber = contactNumber ?? event.contactNumber;
    event.email = email ?? event.email;
    event.password = password ? await bcrypt.hash(password, 10) : event.password;
    event.venue = venue ?? event.venue;
    event.city = city ?? event.city;
    event.startDate = startDate ?? event.startDate;
    event.endDate = endDate ?? event.endDate;

    await event.save();
    res.json({ message: "Event updated successfully", event });
  } catch (err) {
    res.status(500).json({ message: "Error updating event" });
  }
});

app.delete("/api/events/:id", async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    if (!event) return res.status(404).json({ message: "Event not found" });

    await event.deleteOne();
    res.json({ message: "Event deleted successfully" });
  } catch (err) {
    res.status(500).json({ message: "Error deleting event" });
  }
});

// ======================== Root route ========================
app.get("/", (req, res) => {
  res.send("🎉 Event Backend API is running successfully!");
});

// ======================== React Build Serve (Optional) ========================
const reactBuildPath = path.join(__dirname, "client/build");
if (fs.existsSync(reactBuildPath)) {
  app.use(express.static(reactBuildPath));
  app.get("/*", (req, res) => {
    res.sendFile(path.join(reactBuildPath, "index.html"));
  });
} else {
  console.warn("⚠️ React build folder not found. Run `npm run build`.");
}

// ======================== Global error handler ========================
app.use((err, req, res, next) => {
  console.error("🔥 Uncaught error:", err && err.stack ? err.stack : err);
  if (res.headersSent) return next(err);
  res.status(err.status || 500).json({ success: false, message: err.message || "Server error" });
});

// ======================== 404 Fallback ========================
app.use((req, res) => {
  if (req.originalUrl.startsWith("/api")) return res.status(404).json({ message: "API route not found" });
  res.status(404).send("Not Found");
});
