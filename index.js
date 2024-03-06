require('dotenv').config();
const express = require('express');
const categoryRouter = require('./src/routes/category.routes');

const app = express();

app.use('/category',categoryRouter);

module.exports = app;
