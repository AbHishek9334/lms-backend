import {Router} from "express"

import { changePassword, forgotPassword, getLoggedInUserDetails, loginUser, logoutUser, registerUser, resetPassword, updateUser } from "../controllers/user.cntrollers.js"
import upload from "../middlewares/multer.middleware.js"
import { isLoggedIn } from "../middlewares/auth.middleware.js"
const router=Router()
router.post("/register",upload.single("avatar"),registerUser)
router.post("/login", loginUser);
router.get("/me",isLoggedIn,getLoggedInUserDetails)
router.post("/reset", forgotPassword);
router.post("/reset/:resetToken", resetPassword);
router.post("/change-password", isLoggedIn, changePassword);
router.put("/update", isLoggedIn, upload.single("avatar"), updateUser);
router.post("/logout",logoutUser);
export default router