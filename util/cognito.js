const axios= require('axios');
const jwkToPem = require('jwk-to-pem');
const jwt = require('jsonwebtoken');
const jwtDecode = require('jwt-decode');
require('dotenv').config();
global.fetch = require('node-fetch')
const AmazonCognitoIdentity = require('amazon-cognito-identity-js');
const AWS = require('aws-sdk');
const poolRegion = process.env.AWS_COGNITO_REGION;

AWS.config.update({
  accessKeyId: process.env.AWS_ACCESS_KEY,
  secretAccessKey: process.env.AWS_SECRET,
  region: poolRegion,
});

const poolData = {
  UserPoolId :  process.env.AWS_COGNITO_USER_POOL_ID,
  ClientId : process.env.AWS_COGNITO_CLIENT_ID
};
const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);



async function signUp(username, password) {
  return new Promise((resolve) => {
    const attributeList = [];
    userPool.signUp(username, password, attributeList, null, function(err, result){
      if (err) {
        console.log(err)
        return resolve({ statusCode: 422, response: err });
      }
      const cognitoUser = result.user;
      const response = {
        username: result.user.username,
        userConfirmed: result.userConfirmed,
        userAgent: result.user.client.userAgent,
      }
      console.log('user name is ' + cognitoUser.getUsername());
      return resolve({ statusCode: 201, response });
    });
  })
}

function verify(email, code) {
  return new Promise((resolve) => {
    const userData = {
      Username : email,
      Pool : userPool
    };
    const cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
    cognitoUser.confirmRegistration(code, true, (err, result) => {
      if (err) {
        return resolve({ statusCode: 422, response: err });
      }
      return resolve({ statusCode: 200, response: result });
    });
  });
}

function resendVerification(email){
  return new Promise((resolve) => {
  const userData = {
    Username : email,
    Pool : userPool
  };
  const cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
  cognitoUser.resendConfirmationCode(function(err, result) {
    if (err) {
      return resolve({ statusCode: 422, response: err });
    }
      return resolve({ statusCode: 200, response: result });
    });
  })
}
function decodeJWTToken(token) {
  const {  email, exp, auth_time , token_use, sub} = jwtDecode(token.idToken);
  return {  token, email, exp, uid: sub, auth_time, token_use };
}

function signIn(email, password) {
  return new Promise((resolve) => {
    const userData = {
      Username : email,
      Pool : userPool
    };
    const authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails({
      Username : email,
      Password : password,
    });
    const cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
    cognitoUser.authenticateUser(authenticationDetails, {
      onSuccess: (result) => {
        const token = {
          accessToken: result.getAccessToken().getJwtToken(),
          idToken: result.getIdToken().getJwtToken(),
          refreshToken: result.getRefreshToken().getToken(),
        }  
        return resolve({ statusCode: 200, response: decodeJWTToken(token) });
      },
      onFailure: (err) => {
        return resolve({ statusCode: 400, response: err.message || JSON.stringify(err)});
      },
    });
  });
}

async function ValidateToken(token) {
  try{
    const response = await axios.get(`https://cognito-idp.${process.env.AWS_COGNITO_REGION}.amazonaws.com/${process.env.AWS_COGNITO_USER_POOL_ID}/.well-known/jwks.json`)
    if (!response) {
      throw new Error("Unable to load JWK");
    }
    const pems = {};
    const keys = response.data.keys;
    for(key of keys) {
        const keyId = key.kid;
        const modulus = key.n;
        const exponent = key.e;
        const keyType = key.kty;
        const jwk = { kty: keyType, n: modulus, e: exponent};
        const jwkPem = jwkToPem(jwk);
        pems[keyId] = jwkPem;
    }
    //validate the token
    const decodedJwt = await jwt.decode(token, {complete: true});
    if (!decodedJwt) {
        throw new Error("Not a valid JWT token");
    }
    const kid = decodedJwt.header.kid;
    const pem = pems[kid];
    if (!pem) {
      throw new Error("Invalid Token");
    }
    await jwt.verify(token, pem)
    return decodedJwt
  }catch(e){
    console.log(e);
    throw e
  }
}

function renew(refresh_token,username) {
  return new Promise((resolve)=>{
    const RefreshToken = new AmazonCognitoIdentity.CognitoRefreshToken({RefreshToken: refresh_token});
    const userData = {
        Username: username,
        Pool: userPool
    };
    const cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
    cognitoUser.refreshSession(RefreshToken, (err, session) => {
        if (err) {
            console.log(err);
            return resolve({ statusCode: 400, response: err.message || JSON.stringify(err)});
        } 
        const token = {
            access_token: session.accessToken.jwtToken,
            id_token: session.idToken.jwtToken,
            refresh_token: session.refreshToken.token,
        }
        return resolve({ statusCode: 200, response: token });
    })
  })
  
}

async function ChangePassword(username, password) {
  const userData = {
    UserPoolId: process.env.AWS_COGNITO_USER_POOL_ID,
    Username: username,
    Password: password,
    Permanent: true || false
  }
  const cognitoAdmin = new AWS.CognitoIdentityServiceProvider();
  await cognitoAdmin.adminSetUserPassword(userData).promise();
}

async function DeleteUser(username) {
    const userData = {
      UserPoolId: process.env.AWS_COGNITO_USER_POOL_ID,
      Username: username
    }
    const cognitoAdmin = new AWS.CognitoIdentityServiceProvider();
    await cognitoAdmin.adminDeleteUser(userData).promise();
}

function signOut(username){
  const userData = {
    Username: username,
    Pool: userPool
  };
  const cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
  cognitoUser.signOut();
}

async function confirmForgotPassword(confirmationCode,password,username){
  return new Promise((resolve)=>{
    const userData = {
        Username: username,
        Pool: userPool
    };
    const cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);

    cognitoUser.confirmPassword(confirmationCode, password, {
        onFailure(err) {
          return resolve({ statusCode: 400, response: err.message || JSON.stringify(err)})
        },
        onSuccess() {
            console.log("Success");
            return resolve({ statusCode: 200, response: 'success' })
        },
    });
  })
}

function forgotPassword(username){
  return new Promise((resolve)=>{
    const userData = {
      Username: username,
      Pool: userPool
    };
    const cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
    cognitoUser.forgotPassword({
      onSuccess: function(result) {
          console.log('call result: ' + result);
          return resolve({ statusCode: 200, response: result })
      },
      onFailure: function(err) {
        return resolve({ statusCode: 400, response: err.message || JSON.stringify(err)})
      },
  });
  })
}

module.exports = {
    signUp,
    verify,
    resendVerification,
    signIn,
    signOut,
    ValidateToken,
    renew,
    ChangePassword,
    DeleteUser,
    confirmForgotPassword,
    forgotPassword
}
