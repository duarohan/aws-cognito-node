const express = require('express');
const router = express.Router();
const userApi = require('./api/userApi');

router.post('/user', userApi.createUser)
router.post('/user/verification', userApi.verifyUser)
router.post('/user/resendVerification', userApi.resendVerification)
router.post('/user/forgotPassword', userApi.forgotPassword)
router.post('/user/confirmForgotPassword', userApi.confirmForgotPassword)
router.post('/user/login', userApi.loginUser)
router.post('/user/logout', userApi.validateToken, userApi.signOutUser)
router.get('/user',userApi.validateToken, userApi.getUser)
router.post('/token', userApi.refreshToken)
router.post('/user',userApi.validateToken, userApi.updateUser)
router.delete('/user',userApi.validateToken, userApi.deleteUser)

module.exports = router
