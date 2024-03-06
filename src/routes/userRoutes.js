const express = require('express');
const { signup } = require('../controllers/authController');
const isAuthenticated = require('../middleware/isAuthenticated');
const userRouter = express.Router();

userRouter.post('/signup', signup);

module.exports = userRouter;
