require('dotenv').config();
const express = require('express');
const morgan = require('morgan');
const helmet = require('helmet');
const axios = require('axios');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');

const middlewares = require('./middlewares/middlewares');
const wrap = require('./middlewares/wrap');
const api = require('./api');

mongoose.Promise = global.Promise;
if (process.env.NODE_ENV === 'development') {
  mongoose.connect('mongodb://localhost/BlockOTPDev', { useNewUrlParser: true });
} else {
  mongoose.connect('mongodb://localhost/BlockOTP', { useNewUrlParser: true });
}

const app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(morgan('dev'));
app.use(helmet());

app.get('/', wrap(async (req, res) => {
  let apiStatus = await axios.get('http://rest.bitcoin.com/v1/control/getInfo')
    .then(result => {
      return result.data;
    })
    .catch(err => {
      return err;
    });

  res.status(200).json({
    apiStatus: apiStatus
  });
}));

app.use('/api/v1', api);
// Testing JWT login
app.use('/login', require('./routes/user'));

app.use(middlewares.notFound);
app.use(middlewares.errorHandler);

module.exports = app;
