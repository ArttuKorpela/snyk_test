// app.js - A purposely vulnerable Node.js project for testing vulnerability analyzers

const express = require('express');
const app = express();
const child_process = require('child_process');
const sqlite3 = require('sqlite3').verbose();

app.use(express.json());

// Vulnerability 1: Arbitrary Code Execution via eval()
// The code below directly evaluates user input without validation,
// allowing an attacker to execute arbitrary JavaScript.
app.post('/eval', (req, res) => {
  let userInput = req.body.code;
  try {
    let result = eval(userInput); // ⚠️ Dangerous use of eval
    res.send({ result });
  } catch (err) {
    res.status(500).send(err.toString());
  }
});

// Setup in-memory SQLite database for demonstration purposes.
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run("CREATE TABLE users (id INT, name TEXT)");
  db.run("INSERT INTO users (id, name) VALUES (1, 'Alice')");
});

// Vulnerability 2: SQL Injection
// The SQL query below directly concatenates user input into the query string.
// This makes it vulnerable to SQL injection attacks.
app.get('/user', (req, res) => {
  let id = req.query.id;
  let query = "SELECT * FROM users WHERE id = " + id; // ⚠️ Unsanitized input used in SQL query
  db.all(query, (err, rows) => {
    if (err) {
      res.status(500).send(err.toString());
    } else {
      res.json(rows);
    }
  });
});

// Vulnerability 3: Command Injection
// This route executes shell commands using unsanitized user input,
// allowing attackers to inject arbitrary shell commands.
app.get('/exec', (req, res) => {
  let command = req.query.cmd;
  child_process.exec(command, (err, stdout, stderr) => {
    if (err) {
      res.status(500).send(err.toString());
    } else {
      res.send(stdout);
    }
  });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
