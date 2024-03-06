const mongoose = require('mongoose');
const validator = require('validator');

const userSchema = new mongoose.Schema({
    firstName: {
        type: String,
        required: [true, 'Please Enter your first name!'],
    },
    lastName: {
        type: String,
        required: [true, 'Please Enter your last name!'],
    },
    userName: {
        type: String,
        required: [true, 'Please Enter a unique user name!'],
        unique: true,
    },
    email: {
        type: String,
        required: [true, 'Please Provide your email address!'],
        unique: true,
        validate: [validator.isEmail, 'Please Provide a valid email address!'],
    },
    password: {
        type: String,
        required: [true, 'Please Provide your password!'],
        unique: true,
        minlength: 8,
        select: false,
    },
    phoneNumber: {
        type: String,
        required: [true, 'Please Provide your phone number!'],
    },
    age: {
        type: String,
        required: [true, 'Please Provide your DOB!'],
    },
    role: {
        type: String,
        default: 'user',
    },
    isVerfied: {
        type: Boolean,
        default: false,
    },
    isDeleted: {
        type: Boolean,
        default: false,
    },
});

const User = mongoose.model('User', userSchema);
module.exports = User;
