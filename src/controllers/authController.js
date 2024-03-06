const User = require('../models/userModel');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

exports.signup = async (req, res) => {
    try {
        // CHECK IF USER REGISTERED BEFORE
        const { email, password } = req.body;
        const foundedUser = await User.findOne({ email });
        if (foundedUser)
            return res.status(400).json({
                status: 'failed',
                message: 'User already registered',
            });
        // HASHING PASSWORD, THEN SAVE IT IN DB
        const hashedPassword = await bcrypt.hash(password, Number(process.env.BCRYPT_SALT));
        const newUser = await User.create({ ...req.body, password: hashedPassword });
        // VERIFY USER REGISTRATION THROUGH EMAIL
        // let link = `https://shop-easy-backend.onrender.com/auth/verify/${token}`;
        // sendeEmailFun(verifyTemplate, email, link, userName);
        res.status(201).json({
            status: 'success',
            data: {
                newUser,
            },
        });
    } catch (err) {
        res.status(500).json({
            status: 'failed',
            message: err.message,
        });
    }
};
exports.login = async (req, res) => {
    try {
        // 1-) check if user has registered before
        const { email, password } = req.body;
        const registeredUser = await User.findOne({ email }).select('+password');
        if (!registeredUser)
            return res.status(401).json({
                status: 'failed',
                message: 'Invalid email address, You  should register first',
            });
        // 2-) check if user verifies email address
        if (!registeredUser.isVerfied)
            return res
                .status(400)
                .json({ status: 'failed', message: 'You should verify your account before logging!' });
        // 3-) check if user account is deactivated
        if (registeredUser.isDeleted)
            return res.status(401).json({ status: 'failed', message: 'Your account is Deleted temporarly!' });
        // 4-) check if provided password is correct
        const passwordMatch = bcrypt.compareSync(password, registeredUser.password);
        if (!passwordMatch)
            return res.status(401).json({
                status: 'failed',
                message: 'You entered wrong password!',
            });
        // 5-) send token to user if logged successfully
        const token = jwt.sign({ id: registeredUser._id }, process.env.JWT_SECRET, {
            expiresIn: process.env.JWT_EXPIRES_IN,
        });
        res.status(201).json({
            status: 'success',
            token,
            data: {
                registeredUser,
            },
        });
    } catch (err) {
        res.status(500).json({
            status: 'failed',
            message: err.message,
        });
    }
};

exports.forgetPassword = async (req, res) => {
    try {
        const oldUser = await userModel.findOne({ email: req.body.email });
        if (!oldUser) {
            return res.status(401).json({
                status: 'failed',
                message: "User with given email doesn't exist",
            });
        }
        const token = jwt.sign({ userId: oldUser._id, email: oldUser.email }, process.env.RESET_SECRET, {
            expiresIn: '10m',
        });
        const resetLink = `https://shop-easy-backend.onrender.com/auth/reset/${token}`;
        sendeEmailFun(resetTemplate, oldUser.email, resetLink, oldUser.userName);
        res.status(201).json({ status: 'success', message: 'Check your mail to reset your password!' });
    } catch (err) {
        res.status(500).json({
            status: 'failed',
            message: err.message,
        });
    }
};
exports.resetPassword = async (req, res) => {
    try {
        const { token } = req.params;
        const { userId } = jwt.verify(token, process.env.RESET_SECRET);
        const oldUser = await userModel.findById(userId);
        if (!oldUser) return res.status(404).json({ message: 'User not exist' });
        const verify = jwt.verify(token, process.env.RESET_SECRET);
        if (!verify) return res.status(400).json({ status: 'failed', message: 'Invalid link' });
        res.status(200).json({ status: 'success', message: 'Verified' });
    } catch (err) {
        res.status(500).json({
            status: 'failed',
            err: err.message,
        });
    }
};

exports.createNewPassword = async (req, res) => {
    try {
        const { userId } = jwt.verify(req.params.token, process.env.RESET_SECRET);
        console.log(userId);
        const { password } = req.body;
        const oldUser = await userModel.findById(userId);
        if (!oldUser || !userId) return res.status(404).json({ status: 'failed', message: 'Invalid link' });
        const hashedPassword = bcrypt.hashSync(password, Number(process.env.BCRYPT_SALT));
        oldUser.password = hashedPassword;
        await oldUser.save();
        res.status(201).json({ status: 'success', message: 'Password updated successfully' });
    } catch (err) {
        res.status(500).json({
            status: 'failed',
            err: err.message,
        });
    }
};

exports.verifyUser = async (req, res) => {
    try {
        const { token } = req.params;
        const { userId } = jwt.verify(token, process.env.JWT_SECRET);
        const foundedUser = await userModel.findById(userId);
        if (!foundedUser) return res.status(404).json({ status: 'failed', message: 'User not found!' });
        foundedUser.isVerfied = true;
        await foundedUser.save();
        res.status(200).json({
            status: 'success',
            message: 'User verified successfully',
        });
    } catch (err) {
        res.status(500).json({
            status: 'failed',
            err: err.message,
        });
    }
};

exports.getDashboard = async (req, res) => {
    try {
        if (req.role != 'admin') return res.status(403).json({ status: 'failed', message: 'You are not authorized!' });
        const users = await userModel.find();
        res.status(200).json({
            status: 'success',
            message: 'hello from admin',
            data: {
                users,
            },
        });
    } catch (err) {
        res.status(500).json({
            status: 'failed',
            err: err.message,
        });
    }
};
