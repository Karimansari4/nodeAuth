const User = require('../model/User')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const validator = require('email-validator')
const nodemailer = require('nodemailer')
const dotenv = require('dotenv')
const generateOTP = require('../config/otpUtill')
dotenv.config()

const salt = process.env.SALT
const secret = process.env.SECRET

const createToken = (result) => {
    return jwt.sign({result}, secret, {expiresIn: '7d'})
}


exports.getAllUser = async(req, res) => {
    try {
        const result = await User.find()
        if(result){
            return res.status(200).json({result, success: true})
        }else{
            return res.status(404).json({msg: 'Data NOt Found?', success: false})
        }
    } catch (error) {
        console.log("error on getAllUser: ", error);
        return res.status(500).json({err: error.message, success: false, error})
    }
}

exports.addUser = async(req, res) => {
    const name = req.body.name
    const email = req.body.email
    const password = req.body.password

    try {
        if(!name){
            return res.status(400).json({msg: 'Please enter name?', success: false})
        }else if(!isNaN(name)){
            return res.status(400).json({msg: 'Please enter valide name?', success: false})
        }else if(!email){
            return res.status(400).json({msg: 'Please enter email?', success: false})
        }else if(!validator.validate(email)){
            return res.status(400).json({msg: 'Please enter a valid email?', success: false})
        }else if(!password){
            return res.status(400).json({msg: 'Please enter password?', success: false})
        }else if(password.length < 5){
            return res.status(400).json({msg: 'Password should be more than 5 words?', success: false})
        }else{
            const findUser = await User.findOne({email: email})
            if(findUser){
                return res.status(400).json({msg: 'Emali is already register?', success: false})
            }else{
                const hashedPass = await bcrypt.hash(password, parseInt(salt))
                if(hashedPass){
                    const users = new User({name: name, email: email, password: hashedPass})
                    const result = await users.save()
                    if(result){
                        const token = createToken({_id: result._id, name: result.name, email: result.email})
                        if(token){
                            return res.status(200).json({msg: 'ok', token, success:true})
                        }else{
                            return res.status(400).json({msg: 'Failed to create token', success:false })
                        }
                    }else{
                        return res.status(400).json({msg: 'Something went wrong?', success: false})
                    }
                }else{
                    return res.status(400).json({msg: 'Failed to hash password?', success: false})
                }
            }
        }
    } catch (error) {
        console.log("error on addUser: ", error);
        return res.status(500).json({err: error.message, success: false, error})
    }
}


exports.signIn = async(req, res) => {
    const email = req.body.email
    const password = req.body.password

    try {
        if(!email){
            return res.status(400).json({msg: 'Please enter email?', success: false})
        }else if(!validator.validate(email)){
            return res.status(400).json({msg: 'Enter valide email?', success: false})
        }else if(!password){
            return res.status(400).json({msg: 'Please enter password', success: false})
        }else{
            const findUser = await User.findOne({email: email})
            if(findUser){
                const matchPass = await bcrypt.compare(password, findUser.password)
                if(matchPass){
                    const token = createToken({_id: findUser._id, name: findUser.name, email: findUser.email})
                    return res.status(200).json({token, success: true})
                }else{
                    return res.status(400).json({msg: 'Email or Password are not matched?', success: false})
                }
            }else{
                return res.status(404).json({msg: 'Email or Password are not matched?', success: false})
            }
        }
    } catch (error) {
        console.log("error on signIn: ", error);
        return res.status(500).json({err: error.message, success: false, error})
    }
}

exports.resetPassword = async(req, res) => {
    const id = req.params.id
    const oldPass = req.body.oldPass
    const newPass = req.body.newPass


    try {

        const findUser = await User.findById(id)
        
        if(findUser){
            if(!oldPass){
                return res.status(400).json({msg: 'Please enter password?', success: false})
            }if(!newPass){
                return res.status(400).json({msg: 'Please enter old password?', success: false})
            }else if(password.length < 5){
                return res.status(400).json({msg: 'Password should be more than 5 words?', success: false})
            }else{

                const matchedPass = await bcrypt.compare(oldPass, findUser.password)
                
                if(matchedPass){
                    const hashedPass = await bcrypt.hash(newPass, parseInt(salt))
                    const result = await User.findByIdAndUpdate({_id: id}, {password: hashedPass})
                    
                    if(result){
                        return res.status(200).json({msg: 'Password reset successfully.', success: true})
                    }else{
                        return res.status(400).json({msg: 'Opps! Something failed to reset password?', success: false})
                    }
                }else{
                    return res.status(400).json({msg: 'Password incorrect!', success: false})
                }
            }
        }else{
            return res.status(404).json({msg: 'User not found?', success: false})
        }
    } catch (error) {
        console.log("error on resetPassword: ", error);
        return res.status(500).json({err: error.message, success: false, error})
    }
}

exports.sendEmailOTP = async(req, res) => {
    const email = req.body.email
    // console.log("email: ", req.body);
    try {
        if(!email){
            return res.status(400).json({msg: 'Please enter email?', success: false})
        }else if(!validator.validate(email)){
            return res.status(400).json({msg: 'Enter valid email?', success: false})
        }else{
            const findUser = await User.findOne({email: email})
            if(findUser){
                const genOtp = parseInt(generateOTP())
                let transporter = nodemailer.createTransport({
                    service: 'gmail',
                    host: "smtp.gmail.com",
                    port: 587,
                    secure: false,
                    auth: {
                        user: "goprahul545@gmail.com",
                        pass: "zdoqxecvhrdhdybv",
                    },
                    tls: {
                      
                      rejectUnauthorized: false,
                    },
                })

                let info = await transporter.sendMail({
                    from: 'goprahul545@gmail.com',
                    to: email,
                    subject: "Forgot password in Auth",
                    text: `Hi ${findUser.name}`,
                    html: `Hi ${findUser.name} </br> you have requested for reseting your password by using forgot password option <br/> if you have not sent plese contact us. <br/> Your OTP is ${genOtp}`,
                })  
                if(info.accepted){
                    console.log("info: ", info);
                    const result = await User.findOneAndUpdate({email: email}, {otp: genOtp})
                    if(result){
                        return res.status(200).json({msg: `OTP sent to your ${result.email}! Please check email`, success: true, id: result._id})
                    }else{
                        return res.status(400).json({msg: 'Failed to sent OTP?', success: false})
                    }
                }else{
                    return res.status(400).json({msg: 'Failed to sent OTP?', success: false})
                }
            }else{
                return res.status(404).json({msg: "Sorry! we could not find any email?", success: false})
            }
        }
    } catch (error) {
        console.log("error on sendEmailOTP: ", error);
        return res.status(500).json({err: error.message, success: false, error})
    }
}

exports.confirmOTP = async(req, res) => {
    const id = req.params.id
    const otp = req.body.otp

    // console.log("req.body: ", req.body);
    try {
        if(!id){
            return res.status(400).json({msg: 'Access denied?', success: false})
        }else if(!otp){
            return res.status(400).json({msg: 'Please enter OTP?', success: false})
        }else if(otp.length != 4){
            return res.status(400).json({msg: 'Enter valid OTP?', success: false})
        }else{
            const findUser = await User.findById(id)
            if(findUser){
                if(findUser.otp == otp){
                    // const result = await User.findByIdAndUpdate({_id: id}, {otp: ''})
                    return res.status(200).json({msg: 'Now you can change your password.', success: true})
                }else{
                    return res.status(400).json({msg: 'Please enter correct OTP?', success: false})
                }
            }else{
                return res.status(400).json({msg: 'Invalid Access!', success: false})
            }
        }
    } catch (error) {
        console.log("error on confirmOTP: ", error);
        return res.status(500).json({err: error.message, success: false, error})
    }
}

exports.changePassword = async(req, res) => {
    const id = req.params.id
    const otp = req.body.otp
    const password = req.body.pass.conPass

    // console.log("req.body: ", req.body);
    // return res.status(200).json({msg: 'ok', success: true})
    try {
        if(!id){
            return res.status(400).json({msg: 'Access denied?', success: false})
        }else if(!otp){
            return res.status(400).json({msg: 'Please enter OTP?', success: false})
        }else if(!otp.length == 4){
            return res.status(400).json({msg: 'Enter valid OTP?', success: false})
        }else if(!password){
            return res.status(400).json({msg: 'Please enter password', success: false})
        }else if(password.length < 5){
            return res.status(400).json({msg: 'Password should be more than 5 words?', success: false})
        }else{
            const findUser = await User.findById(id)
            if(findUser){
                if(findUser.otp == otp){
                    const hashedPass = await bcrypt.hash(password, parseInt(salt))
                    if(hashedPass){
                        const result = await User.findByIdAndUpdate({_id: id}, {password: hashedPass})
                        if(result){
                            return res.status(200).json({msg: 'Password Reset Successfully.', success: true})
                        }else{
                            return res.status(400).json({msg: 'Failed to reset password! Please enter again?', success: false})
                        }
                    }else{
                        return res.status(400).json({msg: 'Opps! Something went wrong?', success: false})
                    }
                }else{
                    return res.status(400).json({msg: 'Please send OTP again?', success: false})
                }
            }else{
                return res.status(400).json({msg: 'Credentials are not matched?', success: false})
            }
        }
    } catch (error) {
        console.log("error on changePassword: ", error);
        return res.status(500).json({err: error.message, success: false, error})
    }
}