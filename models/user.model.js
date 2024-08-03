import {Schema,model} from "mongoose"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"
import crypto from 'crypto';
const userSchema=new Schema({
    fullName:{
        type:String,
        required:[true,"Name is required"],
        minlength:[3,"Name must be atleast 3 characters"],
        lowercase:true,
        trim:true
    },
    email:{
        type:String,
        required:[true,"Email is required"],
        unique:true,
        lowercase:true,
        match:[/[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/g]
    },
    password:{
        type:String,
        required:[true,"Password is required"],
        minlength:[8,"Password must be atleast 8 characters"],
        select:false
    },
    subscription:{
        id:String,
        status:String
    },
    role:{
        type:String,
        enum:["USER","ADMIN"],
        default:"USER"
    },
    avatar: {
        public_id: {
          type: String,
        },
        secure_url: {
          type: String,
        },
    },
    forgotPasswordToken: String,
    forgotPasswordExpiry: Date

},
{
    timeStamps:true
}
)
//before saving password will be encrypted and save
userSchema.pre("save",async function(next){
    if(!this.isModified("password"))
    return next()
    this.password=await bcrypt.hash(this.password,10)
})
userSchema.methods={
    comparePassword:async function(plainPassword){
        return await bcrypt.compare(plainPassword,this.password)
    },
    generateJWTToken:async function(){
        return await jwt.sign(
            {
                id:this._id,
                role:this.role,
                subscription:this.subscription
            },
            process.env.JWT_SECRET,
            {expiresIn:process.env.JWT_EXPIRY}
        )
    },
    generatePasswordResetToken:async function(){
        //creating a random token using build in crypto module
        const resetToken=crypto.randomBytes(20).toString("hex")
        //Again using crypto module to hash the generated resetToken with sha256 algorithm and storing in the database
        this.forgotPasswordToken=crypto.createHash("sha256").update(resetToken).digest("hex")
        //adding forgot password expiry to 15 minutes
        this.forgotPasswordExpiry=Date.now()+16*60*1000
        return resetToken
    }
}
const User=model("User",userSchema)
export default User