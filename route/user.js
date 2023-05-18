const express = require('express')
const { getAllUser, addUser, signIn, resetPassword, sendEmailOTP, confirmOTP, changePassword } = require('../controller/user')
const { verifyToken } = require('../middleware/Auth')
const userRouter = express.Router()

userRouter.get('/getAllUser', getAllUser)

userRouter.post('/signUp', addUser)

userRouter.post('/signIn', signIn)

userRouter.post('/resetPassword/:id', verifyToken, resetPassword)

userRouter.post('/forgotPassword', sendEmailOTP)

userRouter.post('/confirmOtp/:id', confirmOTP)

userRouter.post('/confirmPass/:id', changePassword)

module.exports = userRouter