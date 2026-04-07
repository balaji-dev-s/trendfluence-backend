import mongoose from "mongoose";

const customerSchema = new mongoose.Schema({
    name: { type: String, required: true },
    phone: { type: String, required: true },
    address: String
}, { timestamps: true });

export default mongoose.model("Customer", customerSchema);