const mongoose = require('mongoose');

mongoose.connect('mongodb://localhost:27017/regestration')
.then(()=>{
    console.log("connection successfully");
}).catch(()=>{
    console.log("connection error");
})