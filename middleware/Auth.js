const jwt = require('jsonwebtoken')
const dotenv = require('dotenv')
dotenv.config()
const secret = process.env.SECRET


exports.verifyToken = async(req, res, next) => {
    const authHeader = req.headers['authorization']
    // console.log("token: ", authHeader);
    try {
        if(!authHeader){
            return res.status(400).json({msg: 'Access denied!', success: false})
        }else{
            const bearerToken = authHeader.split(' ')
            const token = bearerToken[1]

            jwt.verify(token, secret, (err, payload) => {
                if(err){
                    return res.status(400).json({msg: 'Access denied?', success: false})
                }else{
                    req.payload = payload
                    next()
                }
            })
        }
    } catch (error) {
        console.log("error on verify token: ", error);
        return res.status(500).json({err: error.message, error, success: false})
    }
}