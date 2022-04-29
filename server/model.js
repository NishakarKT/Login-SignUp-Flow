import mongoose from "mongoose";

const userSchema = mongoose.Schema({
    userId: {
        type: String,
        required: true
    },
    firstName: {
        type: String,
        required: true
    },
    lastName: {
        type: String,
        required: true
    },
    firstName: {
        type: String,
        required: true
    },
    city: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: [true, "Email already exists."]
    },
    password: {
        type: String,
        required: true
    }
});

const User = new mongoose.model("task5_user", userSchema);

export default User;