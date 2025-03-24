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

    let id = req.params.id;

    db.get("SELECT * FROM articles WHERE id = ?", [id], (err, row) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (!row) {
            return res.status(404).json({ error: "Article not found" });
        }
        res.json(row);  // 조회된 단일 게시글을 JSON 형태로 반환
    });
    
})


app.delete('/articles/:id', (req, res) => {

    const deleteArticle = (id) => {
    const sql = `DELETE FROM articles WHERE id = ?`;

    db.run(sql, [id], function (err) {
        if (err) {
            console.error('Error deleting article:', err.message);
            return;
        }
        console.log(`Article with ID ${id} deleted successfully.`);
    });
    };

// 사용 예시
    const id = req.params.id; // 삭제하려는 아티클의 ID
    deleteArticle(id);

    res.send("okeydokey")

  })



app.put('/articles/:id', (req, res) => {
    const { title, content } = req.body;
    const id = req.params.id;

    if (!title || !content) {
        return res.status(400).json({ error: "Title and content are required" });
    }

    const sql = `UPDATE articles SET title = ?, content = ? WHERE id = ?`;
    const params = [title, content, id];

    db.run(sql, params, function (err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: "Article not found" });
        }
        res.json({ message: "Article updated successfully", id });
    });
});


app.post("/articles/:id/comments", (req, res) => {
    let articleId = req.params.id;
    let content = req.body.content;

    if (!content) {
        return res.status(400).json({ error: "Content is required" });
    }

    let query = "INSERT INTO comments (content, created_at, article_id) VALUES (?, datetime('now'), ?)";
    db.run(query, [content, articleId], function (err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(201).json({ id: this.lastID, content, created_at: new Date().toISOString(), article_id: articleId });
    });
});


app.get("/articles/:id/comments", (req, res) => {
    let articleId = req.params.id;
    let query = "SELECT * FROM comments WHERE article_id = ? ORDER BY created_at DESC";
    
    db.all(query, [articleId], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});