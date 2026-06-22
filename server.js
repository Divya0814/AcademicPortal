// server.js
// ------------------- IMPORTS -------------------
const http = require("http"); //Used to create a raw HTTP server
const { Server } = require("socket.io");
const express = require("express");
const bcrypt = require("bcrypt");
const router = express.Router();
const cors = require("cors");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2");
const multer = require("multer");//file uploads
const path = require("path");
const fs = require("fs");
//const db = require("./utils/db");
const { db, dbPromise } = require("./utils/db");
const sendMail = require("./utils/mailer");
const nodemailer = require('nodemailer');//library for sending mails
const axios = require("axios");

const FP_SERVER =
"https://foldable-ailene-overfavorably.ngrok-free.dev";
//const { spawn, exec } = require("child_process");
// ------------------- APP SETUP -------------------
//const app = express();
//creating actual server with http
require("dotenv").config();
const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: "*" } 
}); 
const PORT = 5000;

const SECRET_KEY = process.env.SECRET_KEY;
//app.use(cors());
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads'));
app.use(express.static('uploads'));
app.use(express.static("frontend"));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

io.on("connection", (socket) => {
  console.log("Student connected");

  db.query("SELECT * FROM notifications ORDER BY id DESC LIMIT 20", (err, rows) => {
    socket.emit("allNotifications", rows || []);
  });
});


// ------------------- LOGIN ROUTES -------------------
// ------------------- STUDENT LOGIN (PLAIN-TEXT) -------------------
app.post("/api/student/login", (req, res) => {
  const { username, password } = req.body;
  console.log("Login attempt:", username);

  const query = "SELECT * FROM student_logins WHERE student_username = ?";
  db.query(query, [username], (err, results) => {
    if (err) {
      console.error("DB query error:", err);
      return res.status(500).json({ error: "Server error" });
    }

    if (results.length === 0) {
      console.log("User not found:", username);
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const user = results[0];
    console.log("User found:", user.student_username);

    // Plain-text password comparison
    if (password !== user.student_password) {
      console.log("Password mismatch");
      return res.status(401).json({ error: "Invalid username or password" });
    }

    // Extract roll number from username
    const roll_no_match = username.toUpperCase().match(/\b\d{4}[A-Z]{2,3}\d{3}\b|\b[A-Z]{2,3}\d{5}\b/);
    if (!roll_no_match) {
      console.log("Roll number regex failed");
      return res.status(400).json({ error: "Invalid username format" });
    }

    const roll_no = roll_no_match[0];

    // Fetch student data
    db.query("SELECT * FROM students WHERE roll_no = ?", [roll_no], (err2, studentResults) => {
      if (err2) {
        console.error("DB query error:", err2);
        return res.status(500).json({ error: "Server error" });
      }

      if (studentResults.length === 0) {
        console.log("Student data not found for roll_no:", roll_no);
        return res.status(404).json({ error: "Student data not found" });
      }

      const studentData = studentResults[0];
      const token = jwt.sign({ roll_no: studentData.roll_no, name: studentData.first_name }, SECRET_KEY, { expiresIn: "2h" });

      console.log("Login successful for:", roll_no);
      res.json({ token, studentData });
    });
  });
});


// --------------------------------------
// CHANGE PASSWORD (Student / Faculty / Admin)
// --------------------------------------
app.post("/api/change-password", (req, res) => {
  const { username, oldPassword, newPassword } = req.body;

  if (!username || !oldPassword) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  // ----------------- STUDENT -----------------
  db.query(
    "SELECT student_password FROM student_logins WHERE student_username = ?",
    [username],
    (err, results) => {
      if (err) return res.status(500).json({ message: "Server error" });

      if (results.length > 0) {
        if (results[0].student_password !== oldPassword)
          return res.status(401).json({ message: "Incorrect current password" });

        db.query(
          "UPDATE student_logins SET student_password = ? WHERE student_username = ?",
          [newPassword, username],
          (err2) => {
            if (err2) return res.status(500).json({ message: "Server error" });
            return res.json({ message: "Student password updated successfully" });
          }
        );
      } else {
        // ----------------- FACULTY -----------------
        db.query(
          "SELECT faculty_password FROM faculty_logins WHERE faculty_username = ?",
          [username],
          (err3, results3) => {
            if (err3) return res.status(500).json({ message: "Server error" });

            if (results3.length > 0) {
              if (results3[0].faculty_password !== oldPassword)
                return res.status(401).json({ message: "Incorrect current password" });

              db.query(
                "UPDATE faculty_logins SET faculty_password = ? WHERE faculty_username = ?",
                [newPassword, username],
                (err4) => {
                  if (err4) return res.status(500).json({ message: "Server error" });
                  return res.json({ message: "Faculty password updated successfully" });
                }
              );
            } else {
              // ----------------- ADMIN -----------------
              db.query(
                "SELECT password FROM admin WHERE username = ?",
                [username],
                (err5, results5) => {
                  if (err5) return res.status(500).json({ message: "Server error" });

                  if (results5.length > 0) {
                    if (results5[0].password !== oldPassword)
                      return res.status(401).json({ message: "Incorrect current password" });

                    db.query(
                      "UPDATE admin SET password = ? WHERE username = ?",
                      [newPassword, username],
                      (err6) => {
                        if (err6) return res.status(500).json({ message: "Server error" });
                        return res.json({ message: "Admin password updated successfully" });
                      }
                    );
                  } else {
                    return res.status(404).json({ message: "User not found" });
                  }
                }
              );
            }
          }
        );
      }
    }
  );
});


// FACULTY LOGIN
app.post("/api/faculty/login", (req, res) => {
  const { username, password } = req.body;
  const query = "SELECT * FROM faculty_logins WHERE faculty_username = ? AND faculty_password = ?";
  db.query(query, [username, password], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(401).json({ error: "Invalid username or password" });

    db.query("SELECT * FROM faculty WHERE faculty_username = ?", [username], (err2, facultyResults) => {
      if (err2) return res.status(500).json({ error: err2.message });
      if (facultyResults.length === 0) return res.status(404).json({ error: "Faculty data not found" });

      const facultyData = facultyResults[0];
      const token = jwt.sign({ faculty_id: facultyData.faculty_id, name: facultyData.faculty_name }, SECRET_KEY, { expiresIn: "2h" });
      res.json({ token, facultyData });
    });
  });
});

// ADMIN LOGIN
app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body;
  const query = "SELECT * FROM admin WHERE username = ? AND password = ?";
  db.query(query, [username, password], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(401).json({ error: "Invalid username or password" });

    const adminData = results[0];
    const token = jwt.sign({ admin_id: adminData.admin_id, name: adminData.admin_name }, SECRET_KEY, { expiresIn: "2h" });
    res.json({ token, adminData });
  });
});

// ------------------- STUDENT PROFILE -------------------
app.get("/api/student/profile", (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Unauthorized" });
  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const roll_no = decoded.roll_no;
    db.query("SELECT * FROM students WHERE roll_no = ?", [roll_no], (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      if (results.length === 0) return res.status(404).json({ error: "Student not found" });
      res.json(results[0]);
    });
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });//401 = Unauthorized
  }
});

// ------------------- MULTER FILE UPLOAD -------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = "./uploads";
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "_" + file.originalname);
  },
});
const upload = multer({ storage });

// ------------------- TIMETABLE UPLOAD / FETCH FOR STUDENT-------------------
app.post("/api/timetable/upload", upload.single("timetableFile"), (req, res) => {
  let { department, year } = req.body;

  if (!req.file) return res.status(400).json({ message: "No file uploaded" });

  // Force CSE instead of CS
  if (department.toUpperCase() === "CS") {
    department = "CSE";
  }

  const filepath = "uploads/" + req.file.filename;

  const sql = "INSERT INTO timetables (department, year, filepath) VALUES (?, ?, ?)";
  db.query(sql, [department, year, filepath], (err, result) => {
    if (err) return res.status(500).json({ error: err });
    res.json({ message: "Timetable uploaded successfully", filepath });
  });
});

app.get("/api/timetable/:department/:year", (req, res) => {
  let { department, year } = req.params;

  // Treat CS as CSE
  if (department.toUpperCase() === "CS") department = "CSE";

  const sql = "SELECT filepath FROM timetables WHERE department = ? AND year = ? ORDER BY id DESC LIMIT 1";
  db.query(sql, [department, year], (err, results) => {
    if (err) return res.status(500).json({ error: err });
    if (results.length === 0) return res.status(404).json({ message: "No timetable found" });
    res.json(results[0]);
  });
});

// ----------------- ADMIN VIEW ALL TIMETABLES -----------------
app.get("/api/admin/timetables", (req, res) => {
  const sql = `
    SELECT t.*, f.faculty_name
    FROM timetable t
    JOIN faculty f ON t.faculty_id = f.faculty_id
    ORDER BY t.faculty_id, t.uploaded_at DESC
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error(err);
      return res.json({ success: false });
    }

    res.json({ success: true, data: results });
  });
});
// ---------- ADMIN UPLOAD FOR FACULTY ----------

// ----------------- Get Faculty List -----------------
app.get("/api/admin/faculty", async (req, res) => {
  const sql = `SELECT faculty_id, faculty_name FROM faculty ORDER BY faculty_name`;
  try {
    const [results] = await dbPromise.query(sql);
    res.json(results);
  } catch (err) {
    console.error(err);
    res.status(500).json([]);
  }
});

// ----------------- Upload Timetable -----------------
// ----------------- Upload Timetable (MAX 3 FILES) -----------------
app.post("/api/admin/assign/upload", upload.array("files"), (req, res) => {
  const faculty_id = req.body.faculty_id;
  const files = req.files;

  if (!files || files.length === 0) {
    return res.status(400).json({ success: false, message: "No files uploaded" });
  }

  // ✅ Step 1: Check existing count
  const countQuery = "SELECT COUNT(*) AS total FROM timetable WHERE faculty_id = ?";

  db.query(countQuery, [faculty_id], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "DB error" });
    }

    const existingCount = result[0].total;
    const newFilesCount = files.length;

    // ❌ Block if exceeds 3
    if (existingCount + newFilesCount > 3) {
      return res.status(400).json({
        success: false,
        message: `Only 3 files allowed. Already uploaded: ${existingCount}`
      });
    }

    // ✅ Insert files
    const sql = `INSERT INTO timetable (faculty_id, file_path) VALUES (?, ?)`;

    files.forEach(file => {
      db.query(sql, [faculty_id, file.filename], err => {
        if (err) console.error(err);
      });
    });

    res.json({
      success: true,
      message: `${files.length} file(s) uploaded successfully`
    });
  });
});
app.delete("/api/admin/timetable/:id", (req, res) => {
  const id = req.params.id;

  const sql = "DELETE FROM timetable WHERE id = ?";

  db.query(sql, [id], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "DB error" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Not found" });
    }

    res.json({ message: "Deleted successfully" });
  });
});

// faculty timetable route
app.get("/api/faculty/timetable/:faculty_id", async (req, res) => {
  try {
    const faculty_id = parseInt(req.params.faculty_id);
    console.log("Fetching timetable for faculty:", faculty_id);

    const sql = "SELECT * FROM timetable WHERE faculty_id=? ORDER BY uploaded_at DESC";
    const [results] = await dbPromise.query(sql, [faculty_id]); // note await

    res.json({ success: true, data: results });
  } catch (err) {
    console.error("DB Error:", err);
    res.status(500).json({ success: false, message: "DB error" });
  }
});


// ------------------- FEE ROUTES -------------------

// -------------------
// GET STUDENT BY ROLL (case-insensitive)
// -------------------
app.get("/api/student/:roll_no", (req, res) => {
  const roll_no = req.params.roll_no;

  const sql = "SELECT * FROM students WHERE UPPER(roll_no) = UPPER(?) LIMIT 1";
  db.query(sql, [roll_no], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(404).json({ error: "Student not found" });
    res.json(results[0]);
  });
});

// -------------------
// UPDATE STUDENT FEE (SAVE CURRENT PAYMENT & TOTAL PAID)
// -------------------
/*app.post("/update-fee", (req, res) => {

  const { roll_no, fee_type, paid_amount, payment_mode } = req.body;

  if (!roll_no || !fee_type || !paid_amount) {
    return res.status(400).json({
      error: "roll_no, fee_type and paid_amount required"
    });
  }

  const amount = Number(paid_amount);

  if (isNaN(amount) || amount <= 0) {
    return res.status(400).json({
      error: "Invalid amount"
    });
  }

  const mode = payment_mode || "Cash";


  // Decide column values
  let tuition = 0;
  let transport = 0;
  let university = 0;

  if (fee_type === "tuition_paid")
    tuition = amount;

  else if (fee_type === "transport_paid")
    transport = amount;

  else if (fee_type === "university_paid")
    university = amount;

  else
    return res.status(400).json({
      error: "Invalid fee type"
    });


  // INSERT payment
  const insertQuery = `
    INSERT INTO fee_payments
    (
      roll_no,
      tuition_paid,
      transport_paid,
      university_paid,
      payment_mode,
      paid_on
    )
    VALUES (?, ?, ?, ?, ?, NOW())
  `;

  db.query(
    insertQuery,
    [
      roll_no.toUpperCase(),
      tuition,
      transport,
      university,
      mode
    ],
    (err, result) => {

      if (err) {

        console.error(err);

        return res.status(500).json({
          error: "Database insert failed"
        });

      }


      // NOW update students table
      const updateStudentQuery = `
        UPDATE students
        SET paid_amount =
          COALESCE(paid_amount, 0) + ?
        WHERE UPPER(roll_no) =
          UPPER(?)
      `;


      db.query(
        updateStudentQuery,
        [amount, roll_no],
        (err2, result2) => {

          if (err2) {

            console.error(err2);

            return res.status(500).json({
              error: "Student update failed"
            });

          }

          res.json({
            success: true,
            message: "Payment saved and student updated",
            added_amount: amount
          });

        }
      );

    }
  );

});
*/app.post("/update-fee", (req, res) => {

  const { roll_no, fee_type, paid_amount, payment_mode } = req.body;

  if (!roll_no || !fee_type || !paid_amount) {
    return res.status(400).json({
      error: "roll_no, fee_type and paid_amount required"
    });
  }

  const amount = Number(paid_amount);
  const mode = payment_mode || "Cash";

  let tuition = 0;
  let transport = 0;
  let university = 0;

  if (fee_type === "tuition_paid")
    tuition = amount;
  else if (fee_type === "transport_paid")
    transport = amount;
  else if (fee_type === "university_paid")
    university = amount;
  else
    return res.status(400).json({ error: "Invalid fee type" });

  // Get student year first
  const getYearQuery = `
    SELECT year
    FROM students
    WHERE UPPER(roll_no)=UPPER(?)
    LIMIT 1
  `;

  db.query(getYearQuery, [roll_no], (err, student) => {

    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (student.length === 0) {
      return res.status(404).json({ error: "Student not found" });
    }

    const currentYear = student[0].year;

    const insertQuery = `
      INSERT INTO fee_payments
      (
        roll_no,
        tuition_paid,
        transport_paid,
        university_paid,
        payment_mode,
        paid_on,
        year
      )
      VALUES (?, ?, ?, ?, ?, NOW(), ?)
    `;

    db.query(
      insertQuery,
      [
        roll_no.toUpperCase(),
        tuition,
        transport,
        university,
        mode,
        currentYear
      ],
      (err2) => {

        if (err2) {
          console.error(err2);
          return res.status(500).json({
            error: "Database insert failed"
          });
        }

        const updateStudentQuery = `
          UPDATE students
          SET paid_amount =
            COALESCE(paid_amount,0) + ?
          WHERE UPPER(roll_no)=UPPER(?)
        `;

        db.query(
          updateStudentQuery,
          [amount, roll_no],
          (err3) => {

            if (err3) {
              return res.status(500).json({
                error: "Student update failed"
              });
            }

            res.json({
              success: true,
              year: currentYear,
              message: "Payment saved successfully"
            });

          }
        );

      }
    );

  });

});
// ------------------ GET STUDENT FEES + ALL PAYMENTS ------------------
app.get("/student-fee/:roll_no", (req, res) => {
  const roll_no = req.params.roll_no;

  if (!roll_no) {
    return res.status(400).json({ error: "roll_no is required" });
  }

  // 1️⃣ STUDENT TOTAL FEES
  const studentQuery = `
    SELECT total_fee, transport_fee, univ_fee
    FROM students
    WHERE UPPER(roll_no) = UPPER(?)
    LIMIT 1
  `;

  db.query(studentQuery, [roll_no], (err, studentResults) => {
    if (err) {
      console.error("STUDENT QUERY ERROR:", err);
      return res.status(500).json({ error: "Database error (students)" });
    }

    if (studentResults.length === 0) {
      return res.json({
        total_fee: 0,
        transport_fee: 0,
        univ_fee: 0,
        payments: []
      });
    }

    const studentFee = studentResults[0];

    // 2️⃣ ALL PAYMENTS (NOT LATEST)
    const paymentQuery = `
      SELECT
        tuition_paid,
        transport_paid,
        university_paid,
        paid_on
      FROM fee_payments
      WHERE UPPER(roll_no) = UPPER(?)
      ORDER BY paid_on ASC
    `;

    db.query(paymentQuery, [roll_no], (err2, paymentResults) => {
      if (err2) {
        console.error("PAYMENT QUERY ERROR:", err2);
        return res.status(500).json({ error: "Database error (fee_payments)" });
      }

      res.json({
        total_fee: Number(studentFee.total_fee || 0),
        transport_fee: Number(studentFee.transport_fee || 0),
        univ_fee: Number(studentFee.univ_fee || 0),
        payments: paymentResults || []
      });
    });
  });
});


// ------------------- FACULTY SUBJECTS & STUDENTS TO GIVE ATTENDANCE -------------------
// ------------------- FACULTY ATTENDANCE (FIXED ROUTES) -------------------

// Subjects allotted to faculty
// ---------------- GET FACULTY SUBJECTS ----------------
app.get("/api/faculty/subjects", (req, res) => {
  console.log("➡️ /api/faculty/subjects HIT");

  const facultyId = req.query.faculty_id;
  console.log("Faculty ID:", facultyId);

  if (!facultyId) {
    return res.json({
      success: false,
      message: "faculty_id missing"
    });
  }

  const sql = `
    SELECT DISTINCT
      s.subject_id,
      s.subject_name,
      s.branch,
      s.year,
      s.semester
    FROM faculty_subjects fs
    JOIN subjects s
      ON fs.subject_name = s.subject_name
    WHERE fs.faculty_id = ?
  `;

  db.query(sql, [facultyId], (err, rows) => {
    if (err) {
      console.error("❌ SQL ERROR:", err);
      return res.json({ success: false });
    }

    console.log("✅ Subjects:", rows);

    res.json({
      success: true,
      subjects: rows
    });
  });
});

// -----------------
// GET STUDENTS FOR A SUBJECT
// -----------------
// GET STUDENTS FOR FACULTY & SUBJECT

app.get("/api/students/:facultyId/:subjectName", (req, res) => {
  const { facultyId, subjectName } = req.params;

  const query = `
        SELECT DISTINCT
            st.roll_no,
            st.first_name,
            st.last_name,
            st.branch,
            s.subject_name,
            s.year,
            s.semester
        FROM students st
        JOIN student_subjects ss 
            ON st.roll_no = ss.roll_no
        JOIN subjects s 
            ON ss.subject_name = s.subject_name
        JOIN faculty_subjects fs 
            ON fs.subject_name = s.subject_name
        WHERE 
            fs.faculty_id = ?
            AND s.subject_name = ?
            AND st.branch = s.branch
    `;

  db.query(query, [facultyId, subjectName], (err, results) => {
    if (err) {
      console.error("MYSQL ERROR:", err);
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

// ------------------ SUBMIT ATTENDANCE ------------------
app.post("/api/attendance/submit", (req, res) => {
  const { subject_name, attendance } = req.body;

  if (!subject_name || !attendance || attendance.length === 0) {
    return res.status(400).json({ message: "Invalid data" });
  }

  const today = new Date().toISOString().split("T")[0];

  // ✅ CHECK if already submitted
  const checkQuery = `
    SELECT 1 FROM attendance 
    WHERE subject_name = ? AND date = ? 
    LIMIT 1
  `;

  db.query(checkQuery, [subject_name, today], (checkErr, result) => {
    if (checkErr) {
      console.error(checkErr);
      return res.status(500).json({ message: "Check failed" });
    }

    // ❌ BLOCK if already submitted
    if (result.length > 0) {
      return res.status(400).json({
        message: "Attendance already submitted for today 🔒"
      });
    }

    // ✅ Insert attendance
    const values = attendance.map(s => [
      s.roll_no,
      subject_name,
      today,
      s.status
    ]);

    const insertQuery =
      "INSERT INTO attendance (roll_no, subject_name, date, status) VALUES ?";

    db.query(insertQuery, [values], (insErr) => {
      if (insErr) {
        console.error(insErr);
        return res.status(500).json({ message: "Insert failed" });
      }

      res.json({ message: "Attendance submitted successfully ✅" });
    });
  });
});
///////////////////////////////////
app.get("/api/attendance/status", (req, res) => {
  const { subject_name } = req.query;

  const today = new Date().toISOString().split("T")[0];

  const query = `
    SELECT 1 FROM attendance 
    WHERE subject_name = ? AND date = ? 
    LIMIT 1
  `;

  db.query(query, [subject_name, today], (err, result) => {
    if (err) return res.status(500).json({ error: err });

    res.json({ submitted: result.length > 0 });
  });
});


// GET student's subjects & attendance filtered by semester
/*app.get("/api/student/attendance/:rollNo", (req, res) => {
  const { rollNo } = req.params;

  // Step 1: Get student's branch, year, semester
  const studentQuery = "SELECT branch, year, semester FROM students WHERE roll_no = ?";
  db.query(studentQuery, [rollNo], (err, studentResults) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (studentResults.length === 0) return res.status(404).json({ error: "Student not found" });

    const { branch, year, semester } = studentResults[0];

    // Step 2: Get subjects for this student in their semester
    const query = `
     SELECT 
        s.subject_name,
        s.semester,
        IFNULL(a.classes_held, 0) AS classes_held,
        IFNULL(a.classes_attended, 0) AS classes_attended,
        IFNULL(a.percentage, 0) AS percentage
      FROM subjects s
      LEFT JOIN (
        SELECT 
          subject_name,
          COUNT(*) AS classes_held,
          SUM(CASE WHEN LOWER(status)='present' THEN 1 ELSE 0 END) AS classes_attended,
          ROUND(
            CASE WHEN COUNT(*) = 0 THEN 0
                 ELSE SUM(CASE WHEN LOWER(status)='present' THEN 1 ELSE 0 END)/COUNT(*)*100
            END, 2
          ) AS percentage
        FROM attendance
        WHERE roll_no = ?
        GROUP BY subject_name
      ) a ON s.subject_name = a.subject_name
      WHERE s.branch = ? AND s.year = ? AND s.semester = ?
      ORDER BY s.subject_name
    `;

    db.query(query, [rollNo, branch, year, semester], (err2, results) => {
      if (err2) return res.status(500).json({ error: "Database error" });
      res.json(results);
    });
  });
});
*/app.get("/api/student/attendance/:rollNo", (req, res) => {
  const { rollNo } = req.params;

  // 1️⃣ Get student details
  const studentQuery = `
    SELECT branch, year, semester 
    FROM students 
    WHERE roll_no = ?
  `;

  db.query(studentQuery, [rollNo], (err, studentResults) => {
    if (err) return res.status(500).json({ error: "Database error" });

    if (studentResults.length === 0) {
      return res.status(404).json({ error: "Student not found" });
    }

    const { branch, year, semester } = studentResults[0];

    // 2️⃣ Main attendance query (FIXED)
    const query = `
      SELECT 
        s.subject_name,

        -- ✅ TOTAL CLASSES HELD (ALL STUDENTS)
        IFNULL(ch.total_classes, 0) AS classes_held,

        -- ✅ STUDENT ATTENDED
        IFNULL(sa.attended, 0) AS classes_attended,

        -- ✅ PERCENTAGE
        IFNULL(
          ROUND(
            (IFNULL(sa.attended,0) / NULLIF(ch.total_classes,0)) * 100,
            2
          ),
          0
        ) AS percentage

      FROM subjects s

      -- 🔥 TOTAL CLASSES PER SUBJECT
      LEFT JOIN (
        SELECT subject_name, COUNT(DISTINCT date) AS total_classes
        FROM attendance
        GROUP BY subject_name
      ) ch ON s.subject_name = ch.subject_name

      -- 🔥 STUDENT ATTENDANCE
      LEFT JOIN (
        SELECT subject_name, COUNT(*) AS attended
        FROM attendance
        WHERE roll_no = ? AND status = 'Present'
        GROUP BY subject_name
      ) sa ON s.subject_name = sa.subject_name

      WHERE s.branch = ? 
        AND s.year = ? 
        AND s.semester = ?

      ORDER BY s.subject_name
    `;

    db.query(query, [rollNo, branch, year, semester], (err2, results) => {
      if (err2) {
        console.error(err2);
        return res.status(500).json({ error: "Database error" });
      }

      res.json(results);
    });
  });
});
// ------------------- ADMIN: YEAR + DEPARTMENT ATTENDANCE SUMMARY -------------------
// -------------------
// ADMIN: ATTENDANCE MATRIX
// -------------------
app.get("/api/admin/attendance-matrix", (req, res) => {
  const { department, year, semester } = req.query;

  const query = `
    SELECT
      st.roll_no,
      CONCAT(st.first_name,' ',st.last_name) AS student_name,
      st.branch,
      st.year,
      st.semester,
      s.subject_name,

      IFNULL(ch.total_classes,0) AS classes_held,

      IFNULL(sa.attended,0) AS attended,

      IFNULL(
        ROUND(
          (IFNULL(sa.attended,0) /
          NULLIF(ch.total_classes,0))*100,
          2
        ),
        0
      ) AS percentage

    FROM students st

    JOIN subjects s
      ON s.branch = st.branch
     AND s.year = st.year
     AND s.semester = st.semester

    LEFT JOIN (
      SELECT
        subject_name,
        COUNT(DISTINCT date) AS total_classes
      FROM attendance
      GROUP BY subject_name
    ) ch
      ON s.subject_name = ch.subject_name

    LEFT JOIN (
      SELECT
        roll_no,
        subject_name,
        COUNT(*) AS attended
      FROM attendance
      WHERE status='Present'
      GROUP BY roll_no, subject_name
    ) sa
      ON sa.roll_no = st.roll_no
     AND sa.subject_name = s.subject_name

    WHERE st.branch = ?
      AND st.year = ?
      AND st.semester = ?

    ORDER BY st.roll_no, s.subject_name
  `;

  db.query(
    query,
    [department, year, semester],
    (err, rows) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "DB Error" });
      }

      res.json(rows);
    }
  );
});
/*app.get("/api/admin/attendance-matrix", (req, res) => {
  const { department, year } = req.query;

  const query = `
    SELECT
      st.roll_no,
      st.branch,
      st.year,
      s.subject_name,
      COUNT(a.id) AS classes_held,
      SUM(CASE WHEN a.status='Present' THEN 1 ELSE 0 END) AS attended,
      IFNULL(
        ROUND(
          SUM(CASE WHEN a.status='Present' THEN 1 ELSE 0 END) /
          NULLIF(COUNT(a.id),0) * 100, 2
        ),
        0
      ) AS percentage
    FROM students st
    JOIN subjects s
      ON s.branch = st.branch AND s.year = st.year
    LEFT JOIN attendance a
      ON a.roll_no = st.roll_no
     AND a.subject_name = s.subject_name
    WHERE st.branch = ? AND st.year = ?
    GROUP BY st.roll_no, s.subject_name
    ORDER BY st.roll_no, s.subject_name;
  `;

  db.query(query, [department, year], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "DB error" });
    }
    res.json(rows);
  });
});
*/

// marks for students
app.get("/api/student/marks/:roll_no", (req, res) => {
  const roll = req.params.roll_no;

  const sql = `
    SELECT 
      sub.subject_name,
      CASE 
        WHEN im.mid1 IS NULL OR im.mid1 = 0 THEN '-' 
        ELSE im.mid1 
      END AS mid1,

      CASE 
        WHEN im.mid2 IS NULL OR im.mid2 = 0 THEN '-' 
        ELSE im.mid2 
      END AS mid2

    FROM students s
    JOIN subjects sub 
      ON s.semester = sub.semester 
     AND s.branch = sub.branch

    LEFT JOIN internal_marks im 
      ON s.roll_no = im.roll_no 
     AND sub.subject_name = im.subject_name

    WHERE s.roll_no = ?
    ORDER BY sub.subject_name
  `;

  db.query(sql, [roll], (err, result) => {
    if (err) {
      console.error("Marks Fetch Error:", err);
      return res.json([]);
    }
    res.json(result);
  });
});

app.post("/api/exam/upload-and-sms", upload.any(), (req, res) => {
  try {
    const { branch, year, semester, examType, sendSMS } = req.body;
    const file = req.files && req.files.length ? req.files[0] : null;

    if (!file) {
      return res.status(400).json({ message: "No file uploaded" });
    }

    const filepath = "uploads/" + file.filename;

    db.query(
      `INSERT INTO exam_timetables (branch, year, semester, exam_type, filepath)
       VALUES (?, ?, ?, ?, ?)`,
      [branch, year, semester, examType, filepath],
      (err, result) => {
        if (err) {
          console.error("DB Error:", err);
          return res.status(500).json({ message: "Database insert failed" });
        }

        io.emit("newNotification", {
          message: `New ${examType} exam schedule uploaded for ${branch} - Year ${year} Sem ${semester}`,
          created_at: new Date()
        });

        res.json({ message: "Exam uploaded successfully" });
      }
    );

  } catch (err) {
    console.error("Upload Error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ------------------- GET LATEST EXAM SCHEDULE -------------------
app.get("/api/exam/schedule/:branch/:year/:semester", (req, res) => {
  let { branch, year, semester } = req.params;
  branch = branch.toUpperCase() === "CS" ? "CSE" : branch.toUpperCase();

  db.query(

    `SELECT filepath, exam_type FROM exam_timetables
     WHERE branch=? AND year=? AND semester=? 
     ORDER BY uploaded_at DESC LIMIT 1`,
    [branch, year, semester],
    (err, rows) => {
      if (err) return res.status(500).json({ message: "Server error" });
      if (rows.length === 0) return res.status(404).json({ message: "No exam schedule found" });

      const cleanPath = rows[0].filepath.replace(/\\/g, "/");
      res.json({ filepath: cleanPath, exam_type: rows[0].exam_type });
    }
  );
});

app.post("/api/admin/notification", (req, res) => {
  const { message } = req.body;

  db.query("INSERT INTO notifications (message) VALUES (?)", [message], (err, result) => {
    if (err) return res.status(500).json({ error: "DB error" });

    const notice = {
      id: result.insertId,
      message,
      created_at: new Date()
    };

    io.emit("newNotification", notice);
    res.json({ success: true });
  });
});

// ------------------- ADMIN POST NOTIFICATION -------------------
// POST notification
app.post("/api/admin/notifications", async (req, res) => {
  try {
    const { message, type } = req.body;

    if (!message)
      return res.status(400).json({ success: false, message: "Message required" });

    const [result] = await dbPromise.query(
      "INSERT INTO notifications (message, type) VALUES (?, ?)",
      [message, type]
    );

    const notice = {
      id: result.insertId,
      message,
      type,
      created_at: new Date()
    };

    // Emit to all connected sockets
    io.emit("newNotification", notice);

    res.json({ success: true, notice });
  } catch (err) {
    console.error("DB Error:", err);
    res.status(500).json({ success: false, message: "DB error" });
  }
});

// GET notifications
app.get("/api/admin/notifications", async (req, res) => {
  try {
    const [rows] = await dbPromise.query(
      "SELECT * FROM notifications ORDER BY created_at DESC"
    );
    res.json({ success: true, notifications: rows });
  } catch (err) {
    console.error("DB Error:", err);
    res.status(500).json({ success: false, message: "DB error" });
  }
});

// DELETE notification
app.delete("/api/admin/notifications/:id", async (req, res) => {
  try {
    const { id } = req.params;

    await dbPromise.query("DELETE FROM notifications WHERE id = ?", [id]);

    res.json({ success: true, message: "Notification deleted" });
  } catch (err) {
    console.error("DB Error:", err);
    res.status(500).json({ success: false, message: "Delete failed" });
  }
});

app.get("/test", (req, res) => {
  res.send("API IS WORKING");
});


// -------------------------------------
// SUBMIT MID-1
// -------------------------------------
/*app.post("/api/marks/mid1", (req, res) => {

  const { subject_name, marks } = req.body;

  if (!subject_name || !marks || marks.length === 0) {
    return res.json({
      success: false,
      message: "Invalid data"
    });
  }

  // CHECK IF ALREADY SUBMITTED
  const checkSql = `
    SELECT COUNT(*) AS count
    FROM internal_marks
    WHERE subject_name = ?
      AND mid1 IS NOT NULL
  `;

  db.query(checkSql, [subject_name], (err, result) => {

    if (err) {
      console.error(err);
      return res.json({
        success: false,
        message: "DB error"
      });
    }

    // ALREADY EXISTS
    if (result[0].count > 0) {
      return res.json({
        success: false,
        message: "MID-1 already submitted 🔒"
      });
    }

    // INSERT ONLY ONCE
    const values = marks.map(m => [
      m.roll_no,
      subject_name,
      m.mid1
    ]);

    const sql = `
      INSERT INTO internal_marks
      (roll_no, subject_name, mid1)
      VALUES ?
    `;

    db.query(sql, [values], (err) => {

      if (err) {
        console.error(err);
        return res.json({
          success: false,
          message: "Database error"
        });
      }

      res.json({
        success: true,
        message: "MID-1 submitted successfully ✅"
      });

    });

  });

}); */
app.post("/api/marks/mid1", (req, res) => {

  const { subject_name, marks } = req.body;

  if (!subject_name || !marks || marks.length === 0) {
    return res.json({
      success: false,
      message: "Invalid data"
    });
  }

  const values = marks.map(m => [
    m.roll_no,
    subject_name,
    m.mid1
  ]);

  const sql = `
    INSERT INTO internal_marks
    (roll_no, subject_name, mid1)
    VALUES ?
    ON DUPLICATE KEY UPDATE
      mid1 = VALUES(mid1)
  `;

  db.query(sql, [values], (err) => {

    if (err) {
      console.error(err);
      return res.json({
        success: false,
        message: "Database error"
      });
    }

    res.json({
      success: true,
      message: "MID-1 submitted successfully ✅"
    });

  });

});

app.post("/api/marks/mid2", (req, res) => {

  const { subject_name, marks } = req.body;

  if (!subject_name || !marks || marks.length === 0) {
    return res.json({
      success: false,
      message: "Invalid data"
    });
  }

  const values = marks.map(m => [
    m.roll_no,
    subject_name,
    m.mid2
  ]);

  const sql = `
    INSERT INTO internal_marks
    (roll_no, subject_name, mid2)
    VALUES ?
    ON DUPLICATE KEY UPDATE
      mid2 = VALUES(mid2)
  `;

  db.query(sql, [values], (err) => {

    if (err) {
      console.error(err);
      return res.json({
        success: false,
        message: "Database error"
      });
    }

    res.json({
      success: true,
      message: "MID-2 submitted successfully ✅"
    });

  });

});
app.get("/api/marks/status", (req, res) => {
  const { subject_name } = req.query;

  const query = `
    SELECT 
      MAX(mid1 IS NOT NULL) AS mid1_done,
      MAX(mid2 IS NOT NULL) AS mid2_done
    FROM internal_marks
    WHERE subject_name = ?
  `;

  db.query(query, [subject_name], (err, result) => {
    if (err) return res.json({ error: err });

    res.json({
      mid1: result[0].mid1_done === 1,
      mid2: result[0].mid2_done === 1
    });
  });
});
/*app.post("/api/marks/mid2", (req, res) => {

  const { subject_name, marks } = req.body;

  if (!subject_name || !marks || marks.length === 0) {
    return res.json({
      success: false,
      message: "Invalid data"
    });
  }

  // CHECK IF ALREADY SUBMITTED
  const checkSql = `
    SELECT COUNT(*) AS count
    FROM internal_marks
    WHERE subject_name = ?
      AND mid2 IS NOT NULL
  `;

  db.query(checkSql, [subject_name], (err, result) => {

    if (err) {
      console.error(err);
      return res.json({
        success: false,
        message: "DB error"
      });
    }

    // ALREADY SUBMITTED
    if (result[0].count > 0) {
      return res.json({
        success: false,
        message: "MID-2 already submitted 🔒"
      });
    }

    const values = marks.map(m => [
      m.roll_no,
      subject_name,
      m.mid2
    ]);

    const sql = `
      INSERT INTO internal_marks
      (roll_no, subject_name, mid2)
      VALUES ?
    `;

    db.query(sql, [values], (err) => {

      if (err) {
        console.error(err);
        return res.json({
          success: false,
          message: "Database error"
        });
      }

      res.json({
        success: true,
        message: "MID-2 submitted successfully ✅"
      });

    });

  });

}); */
// GET student payment summary
// ----------------------------
// FEE SUMMARY API
// ----------------------------
// GET FEE SUMMARY FOR ONE STUDENT
app.get("/api/fee-summary/:roll", (req, res) => {

  const roll = req.params.roll;

  const sql = `
    SELECT 
      IFNULL(SUM(tuition_paid),0) AS tuition_paid,
      IFNULL(SUM(transport_paid),0) AS transport_paid,
      IFNULL(SUM(university_paid),0) AS university_paid,
      IFNULL(SUM(tuition_paid + transport_paid + university_paid),0) AS total_paid
    FROM fee_payments
    WHERE roll_no = ?
  `;

  db.query(sql, [roll], (err, rows) => {

    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Database error" });
    }

    res.json({
      success: true,
      summary: rows[0]
    });

  });

});

app.get("/api/admin/dashboard-count", (req, res) => {

  const result = {
    students: 0,
    faculty: 0,
    pendingFees: 0
  };

  // Total Students
  db.query(
    "SELECT COUNT(*) AS totalStudents FROM students",
    (err, studentRows) => {

      if (err) {
        console.error(err);
        return res.status(500).json({ error: err.message });
      }

      result.students = studentRows[0].totalStudents;

      // Total Faculty
      db.query(
        "SELECT COUNT(*) AS totalFaculty FROM faculty",
        (err, facultyRows) => {

          if (err) {
            console.error(err);
            return res.status(500).json({ error: err.message });
          }

          result.faculty = facultyRows[0].totalFaculty;

          // Total Pending Fees
          db.query(
            `
            SELECT 
              SUM(
                (total_fee + transport_fee + univ_fee) 
                - COALESCE(paid_amount,0)
              ) AS pendingFees
            FROM students
            `,
            (err, feeRows) => {

              if (err) {
                console.error(err);
                return res.status(500).json({ error: err.message });
              }

              result.pendingFees =
                feeRows[0].pendingFees || 0;

              res.json(result);

            }
          );

        }
      );

    }
  );

});
/////////////////////////
app.get("/api/admin/students", (req, res) => {
  db.query(
    `
    SELECT
      roll_no,
      CONCAT(first_name,' ',last_name) AS name,
      branch,
      year
    FROM students
    ORDER BY branch, year, roll_no
    `,
    (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json([]);
      }
      res.json(result);
    }
  );
});

// Dashboard Faculty List API
app.get("/api/dashboard/faculty", async (req, res) => {
  const sql = `
    SELECT 
      faculty_id,
      faculty_name,
      department
    FROM faculty
    ORDER BY department, faculty_id
  `;

  try {
    const [results] = await dbPromise.query(sql);
    res.json(results);
  } catch (err) {
    console.error("Dashboard Faculty Fetch Error:", err);
    res.status(500).json([]);
  }
});

app.get("/api/admin/pending-fees", (req, res) => {

  const query = `
    SELECT 
      roll_no,
      CONCAT(first_name, ' ', last_name) AS name,
      (
        (total_fee + transport_fee + univ_fee)
        - COALESCE(paid_amount,0)
      ) AS balance
    FROM students
    WHERE 
      (
        (total_fee + transport_fee + univ_fee)
        - COALESCE(paid_amount,0)
      ) > 0
    ORDER BY balance DESC
  `;

  db.query(query, (err, rows) => {

    if (err) {
      console.error(err);
      return res.status(500).json({ error: err.message });
    }

    res.json(rows);

  });

});

// -------------------
// ADMIN: MARKS MATRIX (Based on Student Semester)
// -------------------
app.get("/api/admin/marks-matrix", async (req, res) => {
  try {
    const { department, year } = req.query;

    if (!department || !year) {
      return res.status(400).json({
        error: "Department and Year are required"
      });
    }

    // 1️⃣ Get students with their semester
    const [students] = await dbPromise.query(
      `SELECT roll_no,
              CONCAT(first_name, ' ', last_name) AS name,
              semester
       FROM students
       WHERE branch = ?
         AND year = ?
       ORDER BY roll_no`,
      [department, year]
    );

    if (students.length === 0) {
      return res.json({ subjects: [], data: [] });
    }

    // Assume all students of same year have same semester
    const semester = students[0].semester;

    // 2️⃣ Get subjects based on branch + year + semester
    const [subjects] = await dbPromise.query(
      `SELECT subject_name
       FROM subjects
       WHERE branch = ?
         AND year = ?
         AND semester = ?
       ORDER BY subject_name`,
      [department, year, semester]
    );

    if (subjects.length === 0) {
      return res.json({ subjects: [], data: [] });
    }

    const subjectNames = subjects.map(s => s.subject_name);

    // 3️⃣ Get marks only for those students + subjects
    const rollNumbers = students.map(s => s.roll_no);

    const [marks] = await dbPromise.query(
      `SELECT roll_no, subject_name, mid1, mid2
       FROM internal_marks
       WHERE roll_no IN (?)
         AND subject_name IN (?)`,
      [rollNumbers, subjectNames]
    );

    // 4️⃣ Convert marks to lookup map
    const marksMap = {};

    marks.forEach(m => {
      if (!marksMap[m.roll_no]) {
        marksMap[m.roll_no] = {};
      }

      marksMap[m.roll_no][m.subject_name] = {
        mid1: m.mid1 ?? "-",
        mid2: m.mid2 ?? "-"
      };
    });

    // 5️⃣ Build final table data
    const finalData = students.map(student => {
      const row = {
        roll_no: student.roll_no,
        name: student.name
      };

      subjects.forEach(sub => {
        const subName = sub.subject_name;

        const studentMark =
          marksMap[student.roll_no] &&
          marksMap[student.roll_no][subName];

        row[subName + "_mid1"] = studentMark
          ? studentMark.mid1
          : "-";

        row[subName + "_mid2"] = studentMark
          ? studentMark.mid2
          : "-";
      });

      return row;
    });

    res.json({
      subjects: subjectNames,
      data: finalData
    });

  } catch (error) {
    console.error("Marks Matrix Error:", error);
    res.status(500).json({
      error: "Database error"
    });
  }
});


// ------------------- SEND OTP EMAIL -------------------
// ------------------- OTP ROUTES -------------------
// In-memory OTP store
const otpStore = {}; // { username: { otp, expiresAt } }
// SEND OTP
app.post("/send-otp", async (req, res) => {
  const { username, email } = req.body;

  const otp = Math.floor(100000 + Math.random() * 900000);
  const expiresAt = Date.now() + 5 * 60 * 1000;

  otpStore[username] = { otp, email, expiresAt };

  console.log("OTP Saved:", otpStore[username]);

  // ---- SEND EMAIL ----

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});
  const mailOptions = {
    from: "saidivya096@gmail.com",
    to: email,
    subject: "OTP for Password Reset",
    text: `Your OTP is ${otp}`
  };

  try {
    await transporter.sendMail(mailOptions);
    res.json({ success: true, message: "OTP sent successfully" });
  } catch (err) {
    console.log(err);
    return res.status(500).json({ success: false, message: "Failed to send OTP" });
  }
});
// VERIFY OTP
app.post("/verify-otp", (req, res) => {
  const { username, otp } = req.body;

  if (!otpStore[username]) {
    return res.json({ success: false, message: "Invalid or expired OTP" });
  }

  const { otp: storedOtp, expiresAt } = otpStore[username];

  if (Date.now() > expiresAt) {
    delete otpStore[username];
    return res.json({ success: false, message: "OTP expired" });
  }

  if (otp != storedOtp) {
    return res.json({ success: false, message: "Incorrect OTP" });
  }

  delete otpStore[username];

  res.json({ success: true, message: "OTP verified" });
});
//RESET PASSWORD
app.post("/reset-password", (req, res) => {

  const { username, password, role } = req.body;
  console.log(username, password, role);
  let sql;

  if (role === "admin") {
    sql = "UPDATE admin SET password=? WHERE username=?";
  }

  else if (role === "faculty") {
    sql = "UPDATE faculty_logins SET faculty_password=? WHERE faculty_username=?";
  }

  else if (role === "student") {
    sql = "UPDATE student_logins SET student_password=? WHERE student_username=?";
  }

  db.query(sql, [password, username], (err, result) => {

    if (err) {
      console.log(err);
      return res.status(500).json({ message: "Database error" });
    }

    if (result.affectedRows === 0) {
      return res.json({ message: "User not found" });
    }

    res.json({ message: "Password updated successfully" });

  });

});

// ------------------- START SERVER -------------------
/*app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); */

// ============================
// FINGERPRINT SYSTEM (ALL IN ONE)
// ============================
// GET students by department + year (FOR FINGERPRINT ENROLL)
app.get("/api/admin/students-filter", (req, res) => {
  const { department, year } = req.query;

  if (!department || !year) {
    return res.status(400).json({ error: "Missing department/year" });
  }

  const sql = `
    SELECT roll_no, first_name, last_name
    FROM students
    WHERE branch = ? AND year = ?
    ORDER BY roll_no
  `;

  db.query(sql, [department, year], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json([]);
    }

    res.json(result);
  });
});

app.post("/api/fingerprint/scan", async (req, res) => {

  try {

    console.log("Calling fingerprint server...");

    const response = await axios.post(
      `${FP_SERVER}/scan`,
      req.body
    );

    console.log("Response from fingerprint server:");
    console.log(response.data);

    return res.json(response.data);

  } catch (err) {

    console.log("AXIOS ERROR:");

    if (err.response) {
      console.log(err.response.status);
      console.log(err.response.data);
    }

    console.log(err.message);

    return res.status(500).json({
      success: false,
      message: err.message
    });

  }

});



app.get("/api/fingerprint/status", (req, res) => {

  const sql = "SELECT roll_no, status FROM fingerprints";

  db.query(sql, (err, results) => {

    if (err) {
      return res.status(500).json({
        success: false,
        error: "DB error"
      });
    }

    const clean = results.map(r => ({
      roll_no: r.roll_no,
      status: r.status ? r.status.toUpperCase() : "NOT_ENROLLED"
    }));

    res.json(clean);

  });

});
app.post("/api/fingerprint/start-session", async (req, res) => {

  try {

    const response = await axios.post(
      `${FP_SERVER}/start-session`,
      req.body
    );

    res.json(response.data);

  } catch (err) {

    console.error(err);

    res.status(500).json({
      message: "Fingerprint server offline"
    });

  }

});
// =====================
// LIVE ATTENDANCE API
// =====================
app.get("/api/fingerprint/attendance-live", async (req, res) => {

    try {

        const response = await axios.get(
            `${FP_SERVER}/attendance-live`
        );

        const present = response.data.present;

      const { subject_name } = req.query;

const allQuery = `
SELECT st.roll_no
FROM students st
JOIN student_subjects ss
ON st.roll_no = ss.roll_no
WHERE ss.subject_name = ?
`;

     db.query(allQuery, [subject_name], (err, rows) => {

            if (err) {
                return res.status(500).json({
                    message: "DB error"
                });
            }

            const allStudents = rows.map(r => r.roll_no);

            const absent = allStudents.filter(
                r => !present.includes(r)
            );

            res.json({
                present,
                absent
            });

        });

    } catch (err) {

        console.error(err);

        res.status(500).json({
            message: "Fingerprint server offline"
        });

    }

});

app.post("/api/fingerprint/stop-session", async (req, res) => {

  try {

    const response = await axios.post(
      `${FP_SERVER}/stop-session`
    );

    res.json(response.data);

  } catch (err) {

    console.error(err);

    res.status(500).json({
      message: "Fingerprint server offline"
    });

  }

});


////////////////////////////////
app.get("/api/admin/student-attendance/:rollNo", (req, res) => {

  const rollNo = req.params.rollNo;

  const sql = `
    SELECT
      s.semester,
      s.subject_name,

      IFNULL(ch.total_classes,0) AS classes_held,

      IFNULL(sa.attended,0) AS attended,

      IFNULL(
        ROUND(
          (IFNULL(sa.attended,0) /
          NULLIF(ch.total_classes,0))*100,2
        ),
        0
      ) AS percentage

    FROM subjects s

    LEFT JOIN (
      SELECT
        subject_name,
        COUNT(DISTINCT date) total_classes
      FROM attendance
      GROUP BY subject_name
    ) ch
      ON s.subject_name=ch.subject_name

    LEFT JOIN (
      SELECT
        subject_name,
        COUNT(*) attended
      FROM attendance
      WHERE roll_no=?
      AND status='Present'
      GROUP BY subject_name
    ) sa
      ON s.subject_name=sa.subject_name

    JOIN students st
      ON st.roll_no=?

    WHERE s.branch=st.branch

    ORDER BY s.semester,s.subject_name
  `;

  db.query(sql,[rollNo,rollNo],(err,result)=>{
    if(err) return res.status(500).json(err);

    res.json(result);
  });

});

app.get("/api/admin/student-marks/:rollNo",(req,res)=>{

  const rollNo=req.params.rollNo;

  const sql=`
  SELECT
    sub.semester,
    im.subject_name,
    im.mid1,
    im.mid2
  FROM internal_marks im
  LEFT JOIN subjects sub
    ON im.subject_name = sub.subject_name
  WHERE im.roll_no=?
  ORDER BY sub.semester, im.subject_name
  `;

  db.query(sql,[rollNo],(err,result)=>{
    if(err) return res.status(500).json(err);
    res.json(result);
  });

});

// ==========================
// STUDENT FEE REPORT
// ==========================
app.get("/api/admin/student-fees/:rollNo", (req, res) => {
  const { rollNo } = req.params;

  const sql = `
    SELECT
      year,
      SUM(tuition_paid) AS tuition_paid,
      SUM(transport_paid) AS transport_paid,
      SUM(university_paid) AS university_paid
    FROM fee_payments
    WHERE roll_no = ?
    GROUP BY year
    ORDER BY year
  `;

  db.query(sql, [rollNo], (err, results) => {
    if (err) {
      console.log(err);
      return res.status(500).json({ error: err.message });
    }

    db.query(
      `SELECT total_fee, transport_fee, univ_fee
       FROM students
       WHERE roll_no = ?`,
      [rollNo],
      (err2, student) => {
        if (err2) {
          return res.status(500).json({ error: err2.message });
        }

        res.json({
          fees: results,
          totals: student[0]
        });
      }
    );
  });
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
