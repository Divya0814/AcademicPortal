// utils/mailer.js
const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "saidivya096@gmail.com",
    pass: "grwjscitjrcacjjx" // 16-char App Password
  }
});

async function sendMail(to, subject, text) {
  return transporter.sendMail({
    from: '"College Portal" <saidivya096@gmail.com>',
    to,
    subject,
    text
  });
}

module.exports = sendMail;

