const jwt = require('jsonwebtoken');
const User = require('../model/schema');

const auth = async(req,res,next)=>{
    try {
        const token=req.cookies.jwt;
        const verifyuser=jwt.verify(token,process.env.SECRET_KEY);

        const user=await User.findOne({_id:verifyuser._id});
        req.token=token;
        req.user=user;
        // console.log(user);
        next();
    } catch (error) {
        res.status(401).send(error);
    }
}

module.exports=auth;