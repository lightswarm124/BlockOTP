require('dotenv').config();

const axios = require('axios');
const jwt = require('jsonwebtoken');
//const wrap = require('../../middlewares/wrap');

module.exports = async function (expirationBlock) {
  let blockHeight = await axios.get('https://rest.bitcoin.com/v1/blockchain/getBlockCount').then(function (result) {
    return result.data;
  }).catch(function (err) {
    return err;
  });
  let merkleRoot = await axios.get(`https://rest.bitcoin.com/v1/block/details/${blockHeight}`).then(function (result) {
    return result.data.merkleroot;
  }).catch(function (err) {
    return err;
  });
  return await {
    bkh: blockHeight,
    mkr: merkleRoot,
    ebn: blockHeight + expirationBlock
  };
};
