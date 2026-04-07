// ================= IMPORTS =================

// basic server
import express from "express";

// database connection
import mongoose from "mongoose";

// read .env variables
import dotenv from "dotenv";

// allow frontend to talk to backend
import cors from "cors";

// password hashing
import bcrypt from "bcryptjs";

// login token (JWT)
import jwt from "jsonwebtoken";

// read cookies from browser
import cookieParser from "cookie-parser";

// user database model
import User from "./models/User.js";

dotenv.config();

const app = express();


// ================= MIDDLEWARE =================

// allow ONLY your frontend to access backend
app.use(cors({
    origin: "https://trendfluence-billing-invoice.vercel.app",
    credentials: true // allow cookies
}));

// fix browser preflight (important for login requests)

app.options(/.*/, cors());


// allow JSON data from frontend
app.use(express.json());

// allow reading cookies
app.use(cookieParser());


// ================= DATABASE =================

// connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ MongoDB Connected"))
    .catch(err => {
        console.log("❌ DB Error:", err);
        process.exit(1); // stop server if DB fails
    });


// ================= TEST ROUTE =================

// just to check server is running
app.get("/", (req, res) => {
    res.send("API Running");
});


// ================= LOGIN =================

app.post("/auth/login", async (req, res) => {
    try {
        // get email & password from frontend
        const { email, password } = req.body;

        // check if user exists
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ msg: "Invalid email" });
        }

        // check password (compare with hashed one)
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ msg: "Wrong password" });
        }

        // create login token
        const token = jwt.sign(
            { id: user._id },          // store user id inside token
            process.env.JWT_SECRET,    // secret key
            { expiresIn: "1d" }        // token valid for 1 day
        );

        // send token in cookie (secure way)
        res.cookie("token", token, {
            httpOnly: true,   // cannot be accessed by JS (safe)
            secure: true,     // required for HTTPS (Render + Vercel)
            sameSite: "None", // allow cross-site cookies
            maxAge: 24 * 60 * 60 * 1000 // 1 day
        });


        // success response
        res.status(200).json({ msg: "Login success" });

    } catch (err) {
        console.error("LOGIN ERROR:", err);
        res.status(500).json({ msg: "Server error" });
    }
});


// ================= AUTH MIDDLEWARE =================

// this protects routes (like dashboard)
const auth = (req, res, next) => {

    // get token from cookie
    const token = req.cookies.token;

    // if no token → not logged in
    if (!token) {
        return res.status(401).json({ msg: "Not logged in" });
    }

    try {
        // verify token
        jwt.verify(token, process.env.JWT_SECRET);

        next(); // allow access

    } catch {
        res.status(401).json({ msg: "Invalid token" });
    }
};


// ================= DASHBOARD =================

// protected route (only logged-in users)
app.get("/dashboard", auth, (req, res) => {
    res.json({ msg: "Welcome to Dashboard" });
});


// ================= LOGOUT =================

app.post("/auth/logout", (req, res) => {

    // remove cookie
    res.clearCookie("token", {
        httpOnly: true,
        secure: true,
        sameSite: "None"
    });

    res.json({ msg: "Logged out" });
});


// ================= START SERVER =================

const PORT = process.env.PORT || 5000;

// start server
app.listen(PORT, () => {
    console.log("🚀 Server running on port " + PORT);
});