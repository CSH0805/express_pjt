const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const secretKey = process.env.SECRET_KEY;

const cors = require('cors');
app.use(cors())

app.use(express.static('public'));


// json으로 된 post의 바디를 읽기 위해 필요요
app.use(express.json())

const PORT = 3000;




function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
  
    if (!authHeader) {
      return res.status(401).send('인증 헤더 없음');
    }
  
    const token = authHeader.split(' ')[1];
  
    jwt.verify(token, secretKey, (err, decoded) => {
      if (err) {
        return res.status(401).send('토큰 검증 실패');
      }
  
      // 인증 성공 시 decoded 안에 있는 사용자 정보 req에 저장
      req.user = decoded;
      next(); // 다음 미들웨어 or 라우터로
    });
  }
  
  

module.exports = authMiddleware;

//db 연결
const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('./database.db');

app.listen(PORT, () => {
    console.log(`서버가 http://localhost:${PORT} 에서 실행 중입니다.`);
  });

  app.post("articles")

// 전체 아티클 리스트



// 개별 아이티클 주는 api를 만들자
// get : /articles/:id
//로그인 필요
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

// 로그인 필요
// 게시글이 본인인지 확인하는 것도 필요(추후 제작)
//로그인 필요
// 로그인 필요 + 본인 게시글인지 확인 필요
app.delete('/articles/:id', authMiddleware, (req, res) => {
    const articleId = req.params.id;
    const userId = req.user.id; // JWT에서 추출한 사용자 ID

    // 1️⃣ 삭제하려는 게시글이 존재하는지 확인 + 본인 게시글인지 확인
    const sql = `SELECT * FROM articles WHERE id = ?`;
    db.get(sql, [articleId], (err, article) => {
        if (err) {
            console.error('Error finding article:', err.message);
            return res.status(500).send('서버 오류');
        }

        if (!article) {
            return res.status(404).send('게시글을 찾을 수 없음');
        }

        if (article.user_id !== userId) {  // 🛑 본인 게시글인지 체크
            return res.status(403).send('삭제 권한이 없음');
        }

        // 2️⃣ 게시글 삭제
        const deleteSql = `DELETE FROM articles WHERE id = ?`;
        db.run(deleteSql, [articleId], function (err) {
            if (err) {
                console.error('Error deleting article:', err.message);
                return res.status(500).send('삭제 실패');
            }
            console.log(`Article with ID ${articleId} deleted successfully.`);
            res.send('삭제 완료');
        });
    });
});



// 로그인 필요
// 게시글이 본인인지 확인하는 것도 필요(추후 제작)
app.put('/articles/:id', authMiddleware, (req, res) => {
    const { title, content } = req.body;
    const articleId = req.params.id;
    const userId = req.user.id; // JWT에서 추출한 사용자 ID

    // 1️⃣ 수정하려는 게시글이 존재하는지 확인 + 본인 게시글인지 확인
    if (!title || !content) {
        return res.status(400).json({ error: "Title and content are required" });
    }

    const sql = `SELECT * FROM articles WHERE id = ?`;
    db.get(sql, [articleId], (err, article) => {
        if (err) {
            console.error('Error finding article:', err.message);
            return res.status(500).send('서버 오류');
        }

        if (!article) {
            return res.status(404).send('게시글을 찾을 수 없음');
        }

        // 본인 게시글인지 체크
        if (article.user_id !== userId) {
            return res.status(403).send('수정 권한이 없음');
        }

        // 2️⃣ 게시글 수정
        const updateSql = `UPDATE articles SET title = ?, content = ? WHERE id = ?`;
        const params = [title, content, articleId];

        db.run(updateSql, params, function (err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: "Article not found" });
            }
            res.json({ message: "Article updated successfully", id: articleId });
        });
    });
});


app.post("/articles/:id/comments", authMiddleware,(req, res) => {
    let articleId = req.params.id;
    let content = req.body.content;
    let usrId = req.user.userId

    if (!content) {
        return res.status(400).json({ error: "Content is required" });
    }

    let query = "INSERT INTO comments (content, created_at, article_id, user_id) VALUES (?, datetime('now'), ?, ?)";
    db.run(query, [content, articleId, usrId], function (err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(201).json({ id: this.lastID, content, created_at: new Date().toISOString(), article_id: articleId, user_id: usrId });
    });
});

// 로그인 필요

app.get("/articles/:id/comments", (req, res) => {
    let articleId = req.params.id;
    // 댓글과 사용자 이메일을 함께 조회하는 쿼리
    let query = `
        SELECT comments.id, comments.content, comments.created_at, users.email AS user_email
        FROM comments
        JOIN users ON comments.user_id = users.id
        WHERE comments.article_id = ?
        ORDER BY comments.created_at DESC
    `;
    
    db.all(query, [articleId], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);  // 댓글과 사용자 이메일을 포함하여 반환
    });
});

  

  app.post('/user', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "이메일과 비밀번호를 입력하세요." });
    }

    try {
        // 🔹 이메일 중복 체크
        db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, row) => {
            if (err) {
                console.log(err)
                return res.status(500).json({ error: "데이터베이스 오류" });
            }
            if (row) {
                return res.status(400).json({ error: "이미 존재하는 이메일입니다." });
            }

            // 🔹 비밀번호 해싱 후 삽입
            const hashedPassword = await bcrypt.hash(password, 10);
            db.run(`INSERT INTO users (email, password) VALUES (?, ?)`, [email, hashedPassword], function (err) {
                if (err) {
                    return res.status(500).json({ error: "회원가입 실패." });
                }
                res.status(201).json({ message: "회원가입 성공", userId: this.lastID });
            });
        });

    } catch (error) {
        res.status(500).json({ error: "서버 오류 발생" });
    }
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
  
    // 이메일과 비밀번호가 모두 제공되었는지 확인
    if (!email || !password) {
      return res.status(400).json({ error: '이메일과 비밀번호를 모두 입력해주세요.' });
    }
  
    // 이메일로 사용자 찾기
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) {
        return res.status(500).json({ error: '로그인 중 오류가 발생했습니다.' });
      }
  
      if (!user) {
        return res.status(400).json({ error: '이메일 또는 비밀번호가 잘못되었습니다.' });
      }
  
      try {
        // 비밀번호 비교
        const isMatch = await bcrypt.compare(password, user.password);
  
        if (isMatch) {
          // JWT 토큰 생성
          const token = jwt.sign(
            { userId: user.id, email: user.email }, // payload
            secretKey, // 비밀 키 (환경변수로 관리하는 것이 좋습니다)
            { expiresIn: '1h' } // 토큰 만료 시간 설정
          );
  
          res.status(200).json({
            message: '로그인 성공',
            userId: user.id,
            email: user.email,
            token: token // JWT 토큰 반환
          });
        } else {
          res.status(400).json({ error: '이메일 또는 비밀번호가 잘못되었습니다.' });
        }
      } catch (error) {
        console.error(error);
        res.status(500).json({ error: '비밀번호 비교 중 오류가 발생했습니다.' });
      }
    });
  });

  
app.get('/logintest', (req, res)=>{
    console.log(req.headers.authorization.split(' ')[1])
    let token = req.headers.authorization.split(' ')[1]

    jwt.verify(token, secretKey, (err, decoded)=>{
        if(err){
            return res.send("에러러")
        }
        
        return res.send('로그인 성공!')
    })

})


// JWT 토큰 인증 미들웨어
// JWT 인증 미들웨어
function authenticateToken(req, res, next) {
    
    const token = req.headers['authorization']?.split(' ')[1];  // 'Bearer <token>' 형태에서 토큰만 추출

    if (!token) {
        return res.status(401).json({ error: '로그인이 필요합니다.' });
    }

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            // 유효하지 않은 토큰일 경우
            return res.status(403).json({ error: '유효하지 않은 토큰입니다.' });  // 여기에 메시지를 추가
        }

        // JWT에서 userId를 추출하여 요청 객체에 추가
        req.user = decoded;
        next();  // 다음 미들웨어로 진행
    });
}

// 게시글 작성 API (로그인한 사용자만 작성 가능)
// 게시글 작성 API
app.post("/articles", authenticateToken, (req, res) => {
    const { title, content } = req.body;
    const userId = req.user.userId;  // authenticateToken 미들웨어에서 유저 정보를 가져옴

    console.log('User ID:', userId);  // userId 확인용 로그

    if (!title || !content) {
        return res.status(400).json({ error: '제목과 내용은 필수입니다.' });
    }

    db.run(`INSERT INTO articles (title, content, user_id) VALUES (?, ?, ?)`,
        [title, content, userId],
        function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json({ id: this.lastID, title, content });
        });
});



async function loginUser() {
    const email = "user@example.com";
    const password = "yourpassword";

    try {
        const response = await fetch('http://localhost:3000/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });

        const result = await response.json();

        if (response.ok) {
            localStorage.setItem('token', result.token);  // 로그인 후 받은 JWT 토큰을 로컬스토리지에 저장
            console.log('로그인 성공', result);
        } else {
            console.log('로그인 실패', result.error);
        }
    } catch (error) {
        console.error('로그인 오류:', error);
    }
}

async function createArticle() {
    const token = localStorage.getItem('token');  // 로컬스토리지에서 JWT 토큰 가져오기
    const title = "새로운 게시글";
    const content = "게시글 내용입니다.";

    if (!token) {
        alert("로그인이 필요합니다.");
        return;
    }

    try {
        const response = await fetch('http://localhost:3000/articles', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`  // JWT 토큰을 Authorization 헤더에 포함
            },
            body: JSON.stringify({ title, content })
        });

        const result = await response.json();

        if (response.ok) {
            console.log('게시글 작성 성공:', result);
        } else {
            console.log('게시글 작성 실패:', result.error);
        }
    } catch (error) {
        console.error('게시글 작성 오류:', error);
    }
}

// 커밋 한번해주세요

// 전체 아티클 리스트 주는 api를 만들어주세요
// GET : /articles
// 로그인 안필요
app.get('/articles', (req, res) => {
    const query = `
      SELECT 
        articles.*, 
        users.email 
      FROM articles 
      JOIN users ON articles.user_id = users.id
    `;
  
    db.all(query, [], (err, rows) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(rows);  // returns the list of articles with user emails
    });
  });
  







