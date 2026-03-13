var express = require("express");
var router = express.Router();
let { checkLogin } = require('../utils/authHandler');
let { userCreateValidator, userUpdateValidator, handleResultValidator } = require('../utils/validatorHandler');
let userController = require("../controllers/users");

// 1. THÊM 2 THƯ VIỆN NÀY ĐỂ KẾT NỐI DB VÀ MÃ HOÁ MẬT KHẨU
const userModel = require('../schemas/users'); 
const bcrypt = require('bcrypt'); 

router.get("/", checkLogin, async function (req, res, next) {
    let users = await userController.GetAllUser();
    res.send(users);
});

// ==========================================
// 2. CHỨC NĂNG /me (PHẢI NẰM TRÊN GET /:id)
// ==========================================
router.get("/me", checkLogin, async function (req, res, next) {
    try {
        // req.user có được từ middleware checkLogin giải mã Token
        let userId = req.user._id || req.user.id; 
        
        let user = await userModel.findOne({ _id: userId, isDeleted: false });
        if (user) {
            res.send(user);
        } else {
            res.status(404).send({ message: "Không tìm thấy thông tin user" });
        }
    } catch (error) {
        res.status(500).send({ message: "Lỗi server", error: error.message });
    }
});

// ==========================================
// 3. CHỨC NĂNG ĐỔI MẬT KHẨU (BÀI TẬP YÊU CẦU)
// ==========================================
router.put("/change-password", checkLogin, async function (req, res, next) {
    try {
        let { oldpassword, newpassword } = req.body;
        let userId = req.user._id || req.user.id;

        // Validate newpassword (ví dụ: yêu cầu ít nhất 6 ký tự)
        if (!newpassword || newpassword.length < 6) {
            return res.status(400).send({ message: "Mật khẩu mới phải có ít nhất 6 ký tự" });
        }

        let user = await userModel.findById(userId);
        if (!user) {
            return res.status(404).send({ message: "Không tìm thấy người dùng" });
        }

        // So sánh mật khẩu cũ (Giả định mật khẩu trong DB đã được mã hoá bằng bcrypt)
        const isMatch = await bcrypt.compare(oldpassword, user.password);
        if (!isMatch) {
            return res.status(400).send({ message: "Mật khẩu cũ không chính xác" });
        }

        // Mã hoá mật khẩu mới và lưu vào DB
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newpassword, salt);
        await user.save();

        res.send({ message: "Đổi mật khẩu thành công" });
    } catch (error) {
        res.status(500).send({ message: "Lỗi server", error: error.message });
    }
});


// ==========================================
// CÁC ROUTE CŨ CỦA BẠN (GIỮ NGUYÊN, CHỈ ĐẨY XUỐNG DƯỚI)
// ==========================================
router.get("/:id", async function (req, res, next) {
    try {
        let result = await userModel
            .find({ _id: req.params.id, isDeleted: false })
        if (result.length > 0) {
            res.send(result);
        }
        else {
            res.status(404).send({ message: "id not found" });
        }
    } catch (error) {
        res.status(404).send({ message: "id not found" });
    }
});

router.post("/", userCreateValidator, handleResultValidator,
    async function (req, res, next) {
        try {
            let newItem = userController.CreateAnUser(
                req.body.username,
                req.body.password, req.body.email, req.body.fullName,
                req.body.avatarUrl, req.body.role, req.body.status, req.body.loginCount
            )
            await newItem.save();

            let saved = await userModel
                .findById(newItem._id)
            res.send(saved);
        } catch (err) {
            res.status(400).send({ message: err.message });
        }
    });

router.put("/:id", userUpdateValidator, handleResultValidator, async function (req, res, next) {
    try {
        let id = req.params.id;
        let updatedItem = await userModel.findByIdAndUpdate(id, req.body, { new: true });

        if (!updatedItem)
            return res.status(404).send({ message: "id not found" });
        
        let populated = await userModel
            .findById(updatedItem._id)
        res.send(populated);
    } catch (err) {
        res.status(400).send({ message: err.message });
    }
});

router.delete("/:id", async function (req, res, next) {
    try {
        let id = req.params.id;
        let updatedItem = await userModel.findByIdAndUpdate(
            id,
            { isDeleted: true },
            { new: true }
        );
        if (!updatedItem) {
            return res.status(404).send({ message: "id not found" });
        }
        res.send(updatedItem);
    } catch (err) {
        res.status(400).send({ message: err.message });
    }
});

module.exports = router;