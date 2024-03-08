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

//configure email sender
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: 465,
  auth: {
    user: process.env.EMAIL_USERNAME,
    pass: process.env.EMAIL_PASSWORD, 
  },
});

router.post('/signup',async(req,res)=>{
    try{

      const {username,email,password}=req.body

      // check form field
      if(!username||!email||!password){
        return res.status(400).send({message:"username / email / password -field missing?"})
      }
      //check if username or email already exist.
      const existingUser=await userModel.findOne({username:username})
      const existingEmail=await userModel.findOne({email:email})
      if(existingUser||existingEmail){
        if(existingUser)return res.status(400).send({message:"Username already exists"})
        else if(existingEmail)return res.status(400).send({message:"Email already exists"})
      }else{
          //At this moment password can be further validated : length-8;(characters/symbol/number) present or not.
          //But for this simple example i skipped this part

          // hash password
          const hashedpass=await bcrypt.hash(password,10)
          if(hashedpass){
            //if hash is success
            const user=new userModel({
                username,
                email,
                password:hashedpass,
            })

            //save User
            const saveuser=await user.save()
            if(saveuser){
                //Success message 
                res.status(200).send({message:`${saveuser.username} created`,user:saveuser})
            }else{
                res.status(500).send({message:"user saving error"})
            }
          }else{
            //if hash fails
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
        //checking field
        if(!username||!password){
            return res.status(400).send({message:"username / password -field missing?"})
        }

        const founduser=await userModel.findOne({username})
        if(founduser){
            //if user found
            const checkpass=await bcrypt.compare(password,founduser.password)
            if(checkpass){
                //if password is correct

                //create token
                const token=await jwt.sign({
                    userId:founduser._id,
                    username:founduser.username,
                },
                process.env.secretkey,
                    {expiresIn:"24h"}
                );
              
            
              res.status(200).send({message:"Login successful",token,user:founduser.username,userId:founduser._id})    

            }else{
              //if password is wrong
                res.status(500).send({message:"Password does not match"})
            }

        }else{
          //if user not found
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
        //check form fields
        
        //check email in database
        const findUser=await userModel.findOne({email:email})
        if(!findUser){
          res.status(400).send({message:"User with this email does not exist"})
        }else{
        //if email present create token and save to database with userid

        let token = await tokenModel.findOne({ userId: findUser._id });
        if (token) await token.deleteOne();

        let resetToken = crypto.randomBytes(32).toString("hex");
        const hash = await bcrypt.hash(resetToken,10);

        await new tokenModel({
          userId: findUser._id,
          token: hash,
          createdAt: Date.now(),
        }).save();
        
        //recovery link send with email 
        const link =`${clientURL}/resetpassword?token=${resetToken}&id=${findUser._id}`;

        //email template
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


    // Send recovery email
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
      if(!password||!id||token)return res.status(400).send({message:"password/id/token-field missing?"})
        //check form fields
      
      //check token in database
      let passwordResetToken = await tokenModel.findOne({userId:id});

      if (!passwordResetToken) {
        return res.status(400).send({message:"Invalid or expired password reset token"})
      }
      //compare database token from token provided through form
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
     
      //email template
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

    // Send success email
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



