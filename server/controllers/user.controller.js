import sendEmail from '../config/sendEmail.js'
import UserModel from '../models/user.model.js'
import bcryptjs from 'bcryptjs'
import verifyEmailTemplate from '../utils/verifyEmailTemplate.js'
import generatedAccessToken from '../utils/generateAccessToken.js'
import generatedrefreshToken from '../utils/generateRefreshToken.js'
import uploadImageCloudinary from '../utils/uploadImageCloudinary.js'
import generateOtp from '../utils/generayeOTP.js'
import forgotPasswordTemplate from '../utils/forgotPasswordTemplate.js'
import jwt from 'jsonwebtoken'
export async function registerUserController(request,response) { 
    try{
        const {name, email, password} = request.body

        if(!name || !email || !password){
            return response.status(400).json({
                message : "provide email, name, password",
                error : true,
                success : false
            })
        }
        const user = await UserModel.findOne({email})
            if (user) {
                return response.json({
                    message : "Already register email",
                    error : true,
                    success : false
                
                })
            }

            const salt = await bcryptjs.genSalt(10)
            const hashPassword = await bcryptjs.hash(password,salt)

            const payload = {
                name,
                email,
                password : hashPassword
            }
            const newUser = new UserModel(payload)
            const save = await newUser.save()

            const verifyEmailUrl = `${process.env.FRONTEND_URL}/verify-email?code=${save?._id}`

            const verifyEmail = await sendEmail({
                sendTo : email,
                subject : "verify email from blinkeyit",
                html : verifyEmailTemplate({
                    name,
                    url : verifyEmailUrl
                })
            })

            return response.json({
                message : "user register successfully",
                error : false,
                success : true,
                data : save
            })
    }catch (error){
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}

export  async function verifyEmailController(request,response) {
    try{
        const { code } = request.body

        const user = await UserModel.findOne({_id : code})

        if(!user){
            return response.status(400).json({
                message : "invalid code",
                error : true,
                success : false
            })
        }
        const updateUser = await UserModel.updateOne({_id : code},{
            verify_email : true
        })
        return response.json({
            message : "verify email done",
            success : true,
            error : false
        })
    }catch(error){
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : true
        })
    }
}

// login controller

export async function loginController(request,response) {
    try {
        const {email , password} = request.body
        if(!email || !password){
            return response.status(400).json({
                message : "provide email ,password",
                error : true,
                success : false
            })
        }

        const  user = await UserModel.findOne({email})

        if(!user){
            return response.status(400).json({
                message: "user not register",
                error : true,
                success : false
            })
        }
 

        if (user.status !== "Active") {
            return response.status(400).json({
                 message : "contact to Admin",
                 error : true,
                 success : false
            })
        }

        const checkPassoword = await bcryptjs.compare(password,user.password)

        if(!checkPassoword){
            return response.status(400).json({
                message : "check your password",
                error : true,
                success : false
            })
        }
        const accesstoken  = await generatedAccessToken(user._id)
        const refreshtoken = await generatedrefreshToken(user._id)

        const cookiesOption = {
            httpOnly : true,
            secure : true,
            sameSite : "None"
        }
        response.cookie('accesstoken',accesstoken,cookiesOption)
        response.cookie('refreshtoken',refreshtoken,cookiesOption)

        return response.json({
            message : "Login successfully",
            error : false,
            success : true,
            data : {
                accesstoken,
                refreshtoken, 
            }
        })
    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}

//  logout controller

export async function logoutController(request,response) {
    try {
    const userid = request.userId
        const cookiesOption = {
            httpOnly : true,
            secure : true,
            sameSite : "None"
        }
        response.clearCookie("accesstoken",cookiesOption)
        response.clearCookie("refreshtoken",cookiesOption)

       const removeRefreshToken = await UserModel.findByIdAndUpdate(userid,{
        refresh_token : ""
       })





        return response.json({
            message : "Logout successfully",
            error : false,
            success : true
        })
    } catch (error) {
        return message.status(500).json({
            message : error.message ||error,
            error : true,
            success : false
        })
    }
    
}

// upload user avtar
export async function uploadAvatar(request,response) {
    try {
        const userId = request.userId //auth middleware
        const image = request.file  // multer middle ware
        const upload = await uploadImageCloudinary(image)
        
        const updateUser = await UserModel.findByIdAndUpdate(userId,{
            avatar : upload.url
        })

        return response.json({
            message : "upload profile",
            data : {
                _id : userId,
                avatar : upload.url
            }
        })
        // console.log("image",image);
        
    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
    
}

export async function updateUserDetails(request,response) {
    try {
        const userId = request.userId
        const{ name, email, mobile , password } = request.body

        let hashPassword = ""

        if(password){
            const salt = await bcryptjs.genSalt(10)
             hashPassword = await bcryptjs.hash(password,salt)
        }

        const updateUser = await UserModel.updateOne({_id : userId},{
            ...(name && {name : name}),
            ...(email && {email : email}),
            ...(mobile && {mobile : mobile}),
            ...(password && {password : hashPassword})
        })
        return response.json({
            message : "update user successfully",
            error : false,
            success : true,
            data : updateUser
        })
    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error :true,
            success : false
        })
    }
    
}

// forgot password
export async function forgotUserPasswordController(request,response) {
    try {
        const { email } = request.body
        const user = await UserModel.findOne({email})

        if(!user){
            return response.status(400).json({
                message :"eamil not registered",
                error : true,
                success : false
            })
        }


        const otp = generateOtp()
        const expireTime = new Date() + 60 *60 * 1000

        const update = await UserModel.findByIdAndUpdate(user._id,{
            forgot_password_otp : otp,
            forgot_password_expiry : new Date(expireTime).toISOString()
        })

        await sendEmail({
            sendTo : email,
            subject : "forgot password from blinkeyit",
            html : forgotPasswordTemplate({
                name : user.name,
                otp : otp
            })
        })

        return response.json({
            message : "check your email",
            error : false,
             success : true
        })
    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}

// verify forgot password
export async function verifyForgotPasswordOtp(request,response) {
    try {
        const {email,otp} = request.body
        if(!email || otp){
            return response.status(400).json({
                message : "provide required field email ,otp.",
                error : true,
                success: false
            })
        }
        const user = await UserModel.findOne({email})

        if(!user){
            return response.status(400).json({
                message :"eamil not registered",
                error : true,
                success : false
            })
        }

        const currentTime = new Date().toISOString()
        if(user.forgot_password_expiry < currentTime){
            return response.status(400).json({
                message : " otp was expired",
                error : true,
                 success : false
            })
        }

        if(otp === user.forgot_password_otp){
            return response.status(400).json({
                message : "Invalid otp",
                error : true,
                success : false
            })
        }

        return response.json({
            message : " verify otp successfully",
            error : false,
            success : true
        })
    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}

// reset the password 

export async function resetPassword(request,response) {
    try {
        const {email , newPassword , confirmPassword} = request.body
        if (!email || !newPassword || !confirmPassword) {
            return response.status(400).json({
                message : "provide required field email, newPassword, confirmPassword "
                
            })
        }

        const user = await UserModel.findOne({email})

        if(!user){
            return response.status(400).json({
                message : "email is not available",
                error : true,
                success: false
            })
        }

        if(newPassword !== confirmPassword){
            return response.status(400).json({
                message : "newPassword and confirmPassword must be same.",
                error : true,
                success : false
            })
        }

        const salt = await bcryptjs.genSalt(10)
        const hashPassword = await bcryptjs.hash(newPassword,salt)

        const update = await UserModel.findOneAndUpdate(user._id,{
            password : hashPassword
        })

        return response.json({
            message : "password update successfully",
            error : false,
            success : true
        })
    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}

// refreshtoken controller 

export async function refreshtoken(request,response) {
    try {
        const refreshtoken = request.cookies.refreshtoken || request?.header?.authorization?.split(" ")[1]

        if(!refreshtoken){
            return response.status(401).json({
                message : "invalid token",
                error : true,
                success : false
            })
        }
        const verifyToken = await jwt.verify(refreshtoken,process.env.SECRET_KEY_REFRESH_TOKEN)

        if(!verifyToken){
            return response.status(401).json({
                message : "token is expired",
                error : true,
                success : false
            })
        }


        console.log("verifytoken",verifyToken);
        
        const userId = verifyToken?._id
        const newAccessToken = await generatedAccessToken(userId)

        const cookiesOption = {
            httpOnly : true,
            secure : true,
            sameSite : "None"
        }
        response.cookie('accesstoken',newAccessToken,cookiesOption)
        return response.json({
            message : "new access token generated",
            error : false,
            success : true,
            data : {
                accesstoken : newAccessToken
            }
        })

    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error :true,
            success :false
        })
    }
}