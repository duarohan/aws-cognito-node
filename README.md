## Description
NodeJS implementation of AWS Cognito user pool service for user Sign Up/ Sign In / OAuth Token validations

## Application Setup

1. env file parameters

    - Setting up the userpool
        
        AWS_COGNITO_USER_POOL_ID=XXXXXXXXXXXXXXXXXXXX\
        AWS_COGNITO_CLIENT_ID=XXXXXXXXXXXXXXXXXXXXXX\
        AWS_COGNITO_REGION=XXXXXXXX\
        AWS_COGNITO_IDENTITY_POOL_ID=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX


    - Configure IAM user with permissions (cognito-idp Write permissions)
    
        AWS_ACCESS_KEY=XXXXXXXXXXXXXXXXXX\
        AWS_SECRET=XXXXXXXXXXXXXXXXXXXXXXXXXXXX

2. Pull the application in local and npm install

3. Use npm start/ npm restart/ npm stop for there respective operations 


## Operations in User flow

#### Makes use AmazonCognitoIdentity
- signUp
- verification
- resendVerification
- signIn
- signOut
- confirmForgotPassword
- forgotPassword
- ValidateToken - to be used as a middleware
- refresh token
#### Makes use of CognitoIdentityServiceProvider
- ChangePassword
- DeleteUser