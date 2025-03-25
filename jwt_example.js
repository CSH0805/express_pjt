// jwt_example.js
const jwt = require('jsonwebtoken');

const secretKey = 'mysecretkey'; // JWT 서명에 사용할 비밀키

const payload = { username: '파스칼', role: '케이스스' };

// JWT 생성 (1시간 후 만료)
const token = jwt.sign(payload, secretKey, { expiresIn: '1h' });
console.log('생성된 JWT:', token);

// 토큰의 내부 내용을 확인 (헤더, 페이로드, 서명)
const decoded = jwt.decode(token, { complete: true });
console.log('디코딩한 JWT:', decoded);
