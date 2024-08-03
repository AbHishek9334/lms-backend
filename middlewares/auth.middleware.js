import AppError from "../utils/appError.js"
import jwt from "jsonwebtoken"

export const isLoggedIn=async (req,res,next)=>{
    //extracting token from the cookie
    const {token}=req.cookies;
    //if no token send unauthorized message
    if(!token){
        return next(new AppError("unauthorized ,please login to continue",401))
    }
    //Decoding the token using jwt package verify method
    const decoded=await jwt.verify(token,process.env.JWT_SECRET)
    //if no decode,send the message unauthorized
    if(!decoded){
        return next(new AppError("Unauthorized,please login to continue",400))
    }
    //if all good store the id in req object,here we are modifying the request object and adding a field user in it
    req.user=decoded
    //do not forgot to call the next otherwise the flow of execution will not passed further
    next()
}

// Middleware to check if user is admin or not
export const authorizeRoles = (...roles) =>
   async (req, _res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError("You do not have permission to view this route", 403)
      );
    }

    next();
  };
  // Middleware to check if user has an active subscription or not
export const authorizeSubscribers = async (req, _res, next) => {
  // If user is not admin or does not have an active subscription then error else pass
  if (req.user.role !== "ADMIN" && req.user.subscription.status !== "active") {
    return next(new AppError("Please subscribe to access this route.", 403));
  }

  next();
};