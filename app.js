import cookieParser from "cookie-parser"
import userRoutes from "./routes/user.routes.js"
import paymentRoutes from "./routes/payment.routes.js"
import courseRoutes from "./routes/course.routes.js"
import express from "express"
import {config} from "dotenv"
config()
import cors from "cors"
import morgan from "morgan"
const app=express()
app.use(express.json())
app.use(morgan("dev"))
app.use(cookieParser())
app.use(express.urlencoded({ extended: true }));
app.use(
    cors({
      origin: [process.env.FRONTEND_URL],
      credentials: true,
    })
  );
app.get("/ping",(req,res)=>{
    res.send("/pong")
})
app.use("/api/v1/user",userRoutes)
app.use("/api/v1/payments",paymentRoutes)
app.use('/api/v1/courses', courseRoutes);
app.all("*",(req,res)=>{
    res.status(404).send("OOPS || 404 Pagenot found")
})
export default app