import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";

dotenv.config();

await mongoose.connect(process.env.MONGO_URI);

// create hash
const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASS, 10);

// define schema quickly
const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

const User = mongoose.model("User", userSchema);

// save admin
await User.create({
    email: process.env.ADMIN_EMAIL,
    password: hashedPassword
});

console.log("✅ Admin Created");
process.exit();