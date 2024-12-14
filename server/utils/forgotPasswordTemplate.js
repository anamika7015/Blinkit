const forgotPasswordTemplate = ({ name, otp }) => {
    return `
  <div> 
  <p>Dear, ${name}</p>
  <p> you're requested a password reset . please use following OTP code to resetyour Password.</p>
  <div style = "background: yellow; font-size : 20px;padding : 20px; text-align : center;
  font-weight : 800;">
  ${otp}
  </div>
  
  <p>This otp is valid for 1 hour only . Enter this otp in the blinkeyit
  website to proceed with resetting your password.</p>
  <br/>
  </br>
  <p> Thanks</p>
  <p> Blinkeyit</p>
  </div>

  `
}
export default forgotPasswordTemplate