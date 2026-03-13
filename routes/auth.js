var express = require('express');
var router = express.Router();
let userController = require('../controllers/users')
let { RegisterValidator, handleResultValidator } = require('../utils/validatorHandler')
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
let { checkLogin } = require('../utils/authHandler')

// THÊM 2 THƯ VIỆN ĐỂ ĐỌC FILE
const fs = require('fs');
const path = require('path');

// 1. ĐỌC FILE PRIVATE KEY TỪ THƯ MỤC GỐC ĐỂ KÝ TOKEN
const privateKeyPath = path.join(__dirname, '../private.pem');
const privateKey = fs.readFileSync(privateKeyPath, 'utf8');

/* GET home page. */
router.post('/register', RegisterValidator, handleResultValidator, async function (req, res, next) {
    let newUser = userController.CreateAnUser(
        req.body.username,
        req.body.password,
        req.body.email,
        "69aa8360450df994c1ce6c4c"
    );
    await newUser.save()
    res.send({
        message: "dang ki thanh cong"
    })
});

router.post('/login', async function (req, res, next) {
    let { username, password } = req.body;
    let getUser = await userController.FindByUsername(username);
    if (!getUser) {
        res.status(403).send("tai khoan khong ton tai")
    } else {
        if (getUser.lockTime && getUser.lockTime > Date.now()) {
            res.status(403).send("tai khoan dang bi ban");
            return;
        }
        if (bcrypt.compareSync(password, getUser.password)) {
            await userController.SuccessLogin(getUser);
            
            // 2. CHUYỂN SANG DÙNG PRIVATE KEY VÀ THUẬT TOÁN RS256
            let token = jwt.sign({
                id: getUser._id
            }, privateKey, {
                algorithm: 'RS256', // Khai báo rõ thuật toán mã hoá bất đối xứng
                expiresIn: '30d'
            })
            
            res.send(token)
        } else {
            await userController.FailLogin(getUser);
            res.status(403).send("thong tin dang nhap khong dung")
        }
    }

});

// (Phần API /me này của bạn viết rất gọn gàng và đúng chuẩn rồi!)
router.get('/me', checkLogin, function(req, res, next){
    res.send(req.user)
})

module.exports = router;