const mysql = require("mysql2");

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "saidivya",
    database: "college_db"
});

db.connect((err) => {
    if (err) {
        console.error("❌ Database connection failed:", err);
    } else {
        console.log("✅ MySQL Connected");
    }
});
// Export both versions
module.exports = {
    db,             // callback-style queries
    dbPromise: db.promise()  // promise-based queries for async/await
};
//module.exports = db;
//module.exports = db.promise();   // IMPORTANT
