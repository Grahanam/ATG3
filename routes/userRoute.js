const express=require('express')
const bcrypt=require('bcrypt')
const jwt=require('jsonwebtoken')
const nodemailer=require('nodemailer')
const handlebars=require('handlebars')
const fs=require('fs')
const path=require('path')
const crypto = require("crypto");
const clientURL=process.env.clientURL


const router=express.Router()

const userModel=require('../models/userModel')
const tokenModel=require('../models/tokenModel')

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: 465,
  auth: {
    user: process.env.EMAIL_USERNAME,
    pass: process.env.EMAIL_PASSWORD, // naturally, replace both with your real credentials or an application-specific password
  },
});

router.post('/signup',async(req,res)=>{
    try{

      const {username,email,password}=req.body
      if(!username||!email||!password){
        return res.status(400).send({message:"username / email / password -field missing?"})
      }
      const existingUser=await userModel.findOne({username:username})
      const existingEmail=await userModel.findOne({email:email})
      if(existingUser||existingEmail){
        if(existingUser)return res.status(400).send({message:"Username already exists"})
        else if(existingEmail)return res.status(400).send({message:"Email already exists"})
      }else{
          const hashedpass=await bcrypt.hash(password,10)
          if(hashedpass){
            const user=new userModel({
                username,
                email,
                password:hashedpass,
            })

            const saveuser=await user.save()
            if(saveuser){
                res.status(200).send({message:`${saveuser.username} created`,user:saveuser})
            }else{
                res.status(500).send({message:"user saving error"})
            }
          }else{
            res.status(500).send({message:"Password not hashed correctly"})
          }
      }
    
    }catch(err){
        console.log(err)
        res.status(500).send('Internal Server Error')
    }
})

router.post('/login',async(req,res)=>{
    try{
        const {username,password}=req.body
        if(!username||!password){
            return res.status(400).send({message:"username / password -field missing?"})
        }
        const founduser=await userModel.findOne({username})
        if(founduser){
            const checkpass=await bcrypt.compare(password,founduser.password)
            if(checkpass){
                const token=await jwt.sign({
                    userId:founduser._id,
                    username:founduser.username,
                },
                process.env.secretkey,
                    {expiresIn:"24h"}
                );
            res.status(200).send({message:"Login successful",token,user:founduser.username,userId:founduser._id})    

            }else{
                res.status(500).send({message:"Password does not match"})
            }

        }else{
            res.status(400).send({message:'User not found'})
        }

    }catch(err){
        console.log(err)
        res.status(500).json({message:"Internal Server error"})
    }
})

router.post('/forgotpass',async(req,res)=>{
    try{
        const {email}=req.body
        if(!email)return res.status(400).send({message:"Provide email field"})

        const findUser=await userModel.findOne({email:email})
      if(!findUser){
        res.status(400).send({message:"User with this email does not exist"})
      }else{
        
        let token = await tokenModel.findOne({ userId: findUser._id });
        if (token) await token.deleteOne();

        let resetToken = crypto.randomBytes(32).toString("hex");
        const hash = await bcrypt.hash(resetToken,10);

        await new tokenModel({
          userId: findUser._id,
          token: hash,
          createdAt: Date.now(),
        }).save();

        const link =`${clientURL}/resetpassword?token=${resetToken}&id=${findUser._id}`;

        
        const source = fs.readFileSync(path.join(__dirname, './email_template/resetpassword.handlebars'), "utf8");
        const compiledTemplate = handlebars.compile(source);
        const options = () => {
          return {
            from: process.env.EMAIL_USERNAME,
            to: email,
            subject: "Password Reset Request",
            html: compiledTemplate({name:findUser.username,link:link}),
          };
        }


    // Send email
    transporter.sendMail(options(), (error, info) => {
      if (error) {
        console.log(error)
        return res.status(400).json({
            message: 'Error sending mail',
          });
      } else {
        return res.status(200).json({
          success: true,message:'Recovery email sent successfully!'
        });
      }
    })
    
  }

    }catch(err){
        console.log(err)
        res.status(500).json({message:"Internal Server error"})
    } 
})


router.post('/resetpassword',async(req,res)=>{
  try{
      const {password,id,token}=req.body
  
      let passwordResetToken = await tokenModel.findOne({userId:id});
      if (!passwordResetToken) {
        return res.status(400).send({message:"Invalid or expired password reset token"})
      }
      const isValid = await bcrypt.compare(token, passwordResetToken.token);
      
      if (!isValid) {
        return res.status(400).send({message:"Invalid or expired password reset token"})
      }
      const hash = await bcrypt.hash(password, Number(10));
      await userModel.updateOne(
        { _id: id },
        { $set: { password: hash } },
        { new: true }
      );

      const user = await userModel.findById({ _id: id });
  
      const source = fs.readFileSync(path.join(__dirname, './email_template/resetpasswordsuccess.handlebars'), "utf8");
        const compiledTemplate = handlebars.compile(source);
        const options = () => {
          return {
            from: process.env.EMAIL_USERNAME,
            to: user.email,
            subject: "Password Reset Successful",
            html: compiledTemplate({name:user.username}),
          };
        }
        await passwordResetToken.deleteOne();

    // Send email
    transporter.sendMail(options(), (error, info) => {
      if (error) {
        console.log(error)
        return res.status(400).json({
            message: 'Error sending mail',
          });
        } else { 
          return res.status(200).send({success:true,message:'Password Reset Successfull!'})
      }
    })
    

  }catch(err){
    res.status(500).send({message:"Internal Server Error"})
  }
})

module.exports=router



