require('dotenv').config();
const express = require('express');
const userRouter = require('./src/routes/userRoutes');
const app = express();

app.use(express.json());
app.use('/user', userRouter);

module.exports = app;
