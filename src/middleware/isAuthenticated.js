const jwt = require('jsonwebtoken');

const isAuthenticated = (req, res, next) => {
    const headAuthorization = req.headers.authorization;
    if (!headAuthorization) return res.status(401).json({ status: 'failed', message: 'Missing authorized Token!' });
    const token = headAuthorization.split(' ')[1];
    const { userId, role } = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = userId;
    req.role = role;
    next();
};

module.exports = isAuthenticated;
