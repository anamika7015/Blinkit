 const verifyEmailTemplate = ({name,url}) =>{
    return`
    <p>Dear ${name}</p>
    <p>thankyou for registering Blinkeyit.</p>
    <a href=${url} style= "color: black; background : blue; margin-top : 10px , padding : 20px ">
    verify Email
    </a>
    `
 }
 export default verifyEmailTemplate