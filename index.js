const express = require('express');
const app = express();

const cors = require('cors');
app.use(cors())

app.use(express.static('public'));


// json으로 된 post의 바디를 읽기 위해 필요요
app.use(express.json())

const PORT = 3000;

//db 연결
const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('./database.db');

app.listen(PORT, () => {
    console.log(`서버가 http://localhost:${PORT} 에서 실행 중입니다.`);
  });

app.post("/articles", (req, res)=>{
    let {title, content} = req.body
    
    db.run(`INSERT INTO articles (title, content) VALUES (?, ?)`,
        [title, content],
        function(err) {
          if (err) {
            return res.status(500).json({error: err.message});
          }
          res.json({id: this.lastID, title, content});
        });
})

// 전체 아티클 리스트
app.get("/articles", (req, res) => {
    db.all("SELECT * FROM articles", [], (err, rows) => {
        if (err) {
            return res.status(500).json({error: err.message});
        }
        res.json(rows);  // 조회된 모든 게시글을 JSON 형태로 반환
    });
});


// 개별 아이티클 주는 api를 만들자
// get : /articles/:id
app.get('/articles/:id', (req,res)=>{

    let id = req.params.id

    db.all("SELECT * FROM articles", [], (err, rows) => {
        if (err) {
            return res.status(500).json({error: err.message});
        }
        res.json(rows);  // 조회된 모든 게시글을 JSON 형태로 반환
    });
})