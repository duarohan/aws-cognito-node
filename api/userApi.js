const cognito = require('../util/cognito')

exports.createUser = async function (req,res){
    const {username,password} = req.body
    const response = await cognito.signUp(username,password);
    res.status(201).send(response);
}

exports.signOutUser = async function (req,res){
    try{
        const username = req.username;
        await cognito.signOut(username);
        res.status(200).send({status:'success'});
    }catch(e){
        res.status(500).send({status:'Internal Server Error'});
    }
}

exports.verifyUser = async function (req,res){
    try{
        const {username,token} = req.body;
        const response = await cognito.verify(username,token);
        res.status(200).send(response);
    }catch(e){
        console.log(err)
        res.status(500).send({stauts: 'Internal Server Error'});
    }
}

exports.resendVerification = async function(req,res){
    try{
        const {username} = req.body
        await cognito.resendVerification(username)
        res.status(200).send({status : 'Code Sent'});
    }catch(err){
        console.log(err)
        res.status(500).send({stauts: 'Internal Server Error'});
    }
}

exports.loginUser= async function (req,res){
    try{
        const {username,password} = req.body
        const response = await cognito.signIn(username,password);
        res.status(200).send(response);
    }catch(e){
        res.status(500).send('Internal Server Error');
    }
}

exports.getUser= async function (req,res){
    res.status(200).send({status:'success'});
}

exports.refreshToken = async function(req,res){
    try{
        const username = req.username
        const {refresh_token} = req.body
        const response = await cognito.renew(refresh_token,username)
        res.status(200).send(response);
    }catch(e){
        console.log(e)
        res.status(500).send('Internal Server Error');
    }
}

exports.deleteUser = async function(req,res){
    try{
        const username = req.username
        const response = await cognito.DeleteUser(username)
        res.status(200).send(response);
    }catch(e){
        console.log(e)
        res.status(500).send('Internal Server Error');
    }
}

exports.updateUser = async function(req,res){
    try{
        const username = req.username;
        const {password} = req.body
        if(password){
            response = await cognito.ChangePassword(username, password)
        }
        res.status(200).send(response);
    }catch(e){
        console.log(e)
        res.status(500).send('Internal Server Error');
    }
}

exports.validateToken = async function (req,res,next){
    const HEADER_AUTH=  'Authorization'
    if (!req.get(HEADER_AUTH)) {
        return false;
      }
    const clientCredentials = req.get(HEADER_AUTH).split(' ')[1];
    try{
        const {payload} = await cognito.ValidateToken(clientCredentials)
        req.username = payload.username
    }catch(e){
        res.status(400).send({response : e})
        return;
    }
    next()
}   

exports.confirmForgotPassword = async function (req,res){
    try{
        const {confirmationCode,password,username} = req.body;
        const response = await cognito.confirmForgotPassword(confirmationCode,password,username)
        res.status(200).send(response);
    }catch(e){
        console.log(e)
        res.status(500).send('Internal Server Error');
    }
    
}

exports.forgotPassword = async function (req,res){
    try{
        const {username} = req.body;
        const response = await cognito.forgotPassword(username)
        res.status(200).send(response);
    }catch(e){
        console.log(e)
        res.status(500).send('Internal Server Error');
    }
}