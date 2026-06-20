const express = require("express");
const router = express.Router();
const db = require("../utils/db"); // correct path

// -----------------------------
// GET ATTENDANCE DIRECT FROM DB
// -----------------------------
router.get("/:year/:branch/:roll_no", (req, res) => {
  const { year, branch, roll_no } = req.params;

  const sql = `
    SELECT 
        subject_name AS subject,
        COUNT(*) AS held,
        SUM(status = 'present') AS attended
    FROM attendance
    WHERE roll_no = ?
      AND subject_name IN (
          SELECT subject_name 
          FROM subjects 
          WHERE branch = ? AND year = ?
      )
    GROUP BY subject_name;
  `;

  db.query(sql, [roll_no, branch, year], (err, result) => {
    if (err) {
      return res.status(500).json({ error: "Database error", details: err });
    }

    res.json(result);
  });
});

module.exports = router;
