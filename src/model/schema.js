const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');


const userschema = new mongoose.Schema({
   firstName:{
    type:String,
    required:true
   },
   lastName:{
    type:String,
    required:true
   },
   email:{
     type:String,
     required:true,
    //  unique:true
   },
   password:{
    type:String,
    required:true
   },
   tokens:[{
    token:{
    type:String,
    required:true
    }
   }]
})
//generating token
userschema.methods.createtoken = async function() {
    try {
        const token = jwt.sign({_id:this._id.toString()},process.env.SECRET_KEY);
        console.log(token);
        this.tokens=this.tokens.concat({token:token})
        await this.save()
        return token;
    } catch (error) {
        console.log("the error part"+error);
    }
}

userschema.pre("save", async function(next){
    if(this.isModified("password")){
        this.password= await bcrypt.hash(this.password,10);
    }
    next();
})

const User = new mongoose.model("user",userschema);
module.exports = User;

