let jwt = require('jsonwebtoken')
let userController = require('../controllers/users')
const fs = require('fs');
const path = require('path');

// 1. Đọc file Public Key (dùng để verify token)
// Giả định file public.pem bạn vừa tạo nằm ở thư mục ngoài cùng của dự án (cùng cấp với thư mục utils)
const publicKeyPath = path.join(__dirname, '../public.pem');
const publicKey = fs.readFileSync(publicKeyPath, 'utf8');

module.exports = {
    checkLogin: async function (req, res, next) {
        let token = req.headers.authorization;
        if (!token || !token.startsWith("Bearer ")) {
            return res.status(403).send("ban chua dang nhap"); 
        }
        
        token = token.split(" ")[1];
        
        try {
            // 2. Chuyển từ "secret" sang publicKey và ép buộc dùng thuật toán RS256
            let result = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
            
            let user = await userController.FindById(result.id);
            if (!user) {
                return res.status(403).send("ban chua dang nhap");
            } else {
                req.user = user;
                next();
            }
        } catch (error) {
            console.error("Lỗi xác thực token:", error.message);
            res.status(403).send("Token không hợp lệ hoặc đã hết hạn");
        }
    }
}