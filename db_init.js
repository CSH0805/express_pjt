const sqlite3 = require('sqlite3').verbose();

// SQLite DB 연결
const db = new sqlite3.Database('./database.db');

// 테이블 준비 함수
function initDB() {
  // articles 테이블 생성
  db.run(`
    CREATE TABLE IF NOT EXISTS articles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      content TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err) {
      console.error("테이블 생성 에러:", err);
    } else {
      console.log("테이블 준비 완료(articles)");
    }
  });

  // comments 테이블 생성
  db.run(`
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      content TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      article_id INTEGER,
      FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE CASCADE
    )
  `, (err) => {
    if (err) {
      console.error("테이블 생성 에러:", err);
    } else {
      console.log("테이블 준비 완료(comments)");
    }
  });

  // users 테이블 생성
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err) {
      console.error("테이블 생성 에러:", err);
    } else {
      console.log("테이블 준비 완료(users)");
    }
  });
}

// function initDB() {
//   db.run(`
//     CREATE TABLE IF NOT EXISTS users (
//       id INTEGER PRIMARY KEY AUTOINCREMENT,
//       email TEXT NOT NULL UNIQUE,
//       password TEXT NOT NULL,
//       created_at DATETIME DEFAULT CURRENT_TIMESTAMP
//     )
//   `, (err) => {
//     if (err) {
//       console.error("테이블 생성 에러:", err);
//     } else {
//       console.log("테이블 준비 완료(users)");
//     }
//   });
// }

// 데이터베이스 초기화 함수 실행
initDB();
