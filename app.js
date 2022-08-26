const express= require('express')
const routes = require('./routes');
const bodyParser = require('body-parser');

const app = new express()
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(routes);
app.listen(3001)

module.exports = app