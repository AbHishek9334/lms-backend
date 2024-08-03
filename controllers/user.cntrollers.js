import User from "../models/user.model.js"
import AppError from "../utils/appError.js"
import cloudinary from "cloudinary"
import fs from "fs/promises"
import crypto from 'crypto';
import sendEmail from "../utils/sendEmail.js"
const cookieOptions={
    secure:process.env.NODE_ENV==="production"?true:false,
    maxAge:7*24*60*60*1000,
    httpOnly:true
}

export const registerUser=async(req,res,next)=>{
    const {fullName,email,password}=req.body
    if(!fullName || !email || !password){
        return next (new AppError("All fields are required",400))
    }
    const userExists=await User.findOne({email})
    if(userExists){
        return next(new AppError("Email already exists,409"))
    }
    const user=await User.create({
        fullName,
        email,
        password,
        avatar:{
            public_id:"",
            secure_url:""
        },
        role:"ADMIN"
        
        
        
    })
    if(!user){
        return next(
            new AppError("User registration failed,please try again later",400)
        )
    }
    //run only if user sends a file
    if (req.file) {
        try {
          const result = await cloudinary.v2.uploader.upload(req.file.path, {
            folder: 'lms', // Save files in a folder named lms
            width: 250,
            height: 250,
            gravity: 'faces', // This option tells cloudinary to center the image around detected faces (if any) after cropping or resizing the original image
            crop: 'fill',
          });
    
          // If success
          if (result) {
            // Set the public_id and secure_url in DB
            user.avatar.public_id = result.public_id;
            user.avatar.secure_url = result.secure_url;
    
            // After successful upload remove the file from local storage
            fs.rm(`uploads/${req.file.filename}`);
          }
        } catch (error) {
          return next(
            new AppError(error || 'File not uploaded, please try again', 400)
          );
        }
      }
    await user.save()
    //generating jwt token
    const token=await user.generateJWTToken()
    //setting the password to undefined as it doed not get sent in the response
    user.password=undefined
    res.cookie("token",token,cookieOptions)
    //if all good send the response to the frontend
    res.status(201).json({
        success:true,
        message:"User registered successively",
        user
    })
}
export const loginUser=async(req,res,next)=>{
  const {email,password}=req.body;
  //check if data is there or not,if not throw error message
  if(!email || !password){
    return next(new AppError("Email and password are required",400))
  }
  //Find the user with the sent email
  const user=await User.findOne({email}).select("+password")
  //If no user or sent password do not match,then send generic response
  if(!(user && (await user.comparePassword(password)))){
    return next(new AppError("Email or password does not match or user does not exist"))
  }
  //Generating a jwt token
  const token=await user.generateJWTToken();
  //setting the password to undefined so it does not get send in the response
  user.password=undefined
  //setting the token in the cookie with name token along with cokkie options
  res.cookie("token",token,cookieOptions)
  //If all good ,send the response to the frontend
  res.status(200).json({
    success:true,
    message:"user logged in successively",
    user
  })
}
export const logoutUser=async (req,res,next)=>{
  //setting the cookie value to null
  res.cookie("token",null,{
    secure:process.env.NODE_ENV==="production"?true:false,
    maxAge:0,
    httpOnly:true
  })
  //sending the response
  res.status(200).json({
    success:true,
    message:"User logged out successively"
  })
}
export const getLoggedInUserDetails=async (req,res,next)=>{
  //finding the user using the id from modified req object
  const user=await User.findById(req.user.id)
  res.status(200).json({
    success:true,
    message:"user details",
    user
  })
}
export const forgotPassword=async(req,res,next)=>{
  //Extracting email from request body
  const {email} =req.body
  //if no email ,sent email require message
  if(!email){
    return next(new AppError("Email is required",400))
  }
  //Finding the user via email
  const user=await User.findOne({email})
  //If no email found send the message email not found
  if(!user){
    return next(new AppError("Email not registered",400))
  }
  const resetToken=await user.generatePasswordResetToken()
  await user.save()
  const resetPasswordUrl=`${process.env.FRONTEND-URL}/reset-password/${resetToken}`
  //we have to send an email to the user with the token
  const subject="ResetPassword"
  const message="you can reset your password "
  try{
    await sendEmail(email,subject,message)
    //if email sent successively sent the success response
    res.status(200).json({
      success:true,
      message:`Reset password token has been sent tour email:${resetToken}`
    })
  }
  catch(error){
    //if some error happenned we need to clear the forgot passowrd fields over DB
    user.forgotPasswordToken=undefined;
    user.forgotPasswordExpiry=undefined
    return next(new AppError(
      error.message ||"Something went wrong,please try again",500
    ))
  }
}
export const resetPassword=async(req,res,next)=>{
  //Extracting resetToken from req.params object
  const { resetToken } = req.params;
  console.log(resetToken)
  const {password}=req.body;
  //we are again hashing the resetToken using sha256 since,we have stored our reset token in db using the same algorithm
  const forgotPasswordToken = crypto
  .createHash('sha256')
  .update(resetToken)
  .digest('hex');
  //check if password is not there then send response saying password is required
  if(!password){
    return next(new AppError("Password is required",400))
  }
  //checking if token matches in DB and if it is still valid(not expired)
  const user=await User.findOne({
    forgotPasswordToken,
    forgotPasswordExpiry:{$gt:Date.now()}
  })
  //If not found or expired ,send the response 
  if(!user){
    return next(
      new AppError("Token is invalid or expired,please try again,400")
    )
  }
  //update the password if token is valid and not expired
  user.password=password
  //making forgot Password value to undefined in the db
  user.forgotPasswordExpiry=undefined;
  user.forgotPasswordToken=undefined
  //Saving the updated user values
  await user.save()
  //sending the response when everthing goes good 
  res.status(200).json({
    success:true,
    message:"Password changed successively"
  })
}
export const changePassword=async(req,res,next)=>{
  //Destructing the neccessary data from the req object
  const {oldPassword,newPassword}=req.body
  const {id}=req.user;
  //check if the values are there or not
  if(!oldPassword || !newPassword){
    return next(new AppError("old passowrd and new passowrd are required",400))
  }
  //Finding the userById and selecting the password
  const user=await User.findById(id).select("+password")
  //if no user then throw an error messgae
  if(!user){
    return next(new AppError("Invalid user id or user does not exist",400))
  }
  //check if the old pssword is correct
  const isPasswordValid=await user.comparePassword(oldPassword)
  if(!isPasswordValid){
    return next(new AppError("Invalid old password",400))
  }
  //setting the password
  user.password=newPassword
  //save the data in DB
  await user.save()
  //setting the password undefined so that it wont get sent to the response
  user.password=undefined
  res.status(200).json({
    success:true,
    message:"Pssword changed successively"
  })
}
export const updateUser=async(req,res,next)=>{
  //Destruting the necessary data from the req object
  const {fullName}=req.body;
  const {id}=req.user
  const user=await User.findById(id)
  if(!user){
    return next(new AppError("Invalid user id or user does not exist"))
  }
  if(fullName){
    user.fullName=fullName
  }
  //Run only if user sends the file
  if(req.file){
    //Delete the old image uploaded by user
    await cloudinary.v2.uploader.destroy(user.avatar.public_id)
    try{
      const result=await cloudinary.v2.uploader.upload(req.file.path,{
        folder:"lms",
        width:250,
        height:250,
        gravity:"faces",
        crop:"fill"
      })
      //if seccess
      if(result){
        //set the public id and secure url in db
        user.avatar.public_id=result.public_id
        user.avatar.secure_url=result.secure_url
        //After successfull upload remove the file from local storage
        fs.rm(`uploads/${req.file.filename}`)
      }
    }
    catch(error){
      return next(
        new AppError(error || "File not uploaded,please try again",400) 
      )
    }
  }
  //save the user object
  await user.save()
  res.status(200).json({
    success:true,
    message:"User details updated successively"
  })
}