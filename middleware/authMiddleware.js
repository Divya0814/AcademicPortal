//authMiddleware.js
const jwt = require("jsonwebtoken");
const SECRET_KEY = "YOUR_SECRET_KEY"; // or use your .env

module.exports = function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "No token provided" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    // Attach roll_no and name from token
    req.user = {
      roll_no: decoded.roll_no,
      name: decoded.name
    };
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
};
