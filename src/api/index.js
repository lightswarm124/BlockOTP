const express = require('express');
const axios = require('axios');

const wrap = require('../middlewares/wrap');
const blockData = require('./blockchain/bchblockchain');
const addressData = require('./blockchain/addresses');

const router = express.Router();

router.get('/', wrap(async (req, res) => {
  let blockchainStatus = await axios.get('http://rest.bitcoin.com/v1/blockchain/getBlockchainInfo')
    .then(result => {
      return result.data;
    })
    .catch(err => {
      return err;
    });

  res.status(200).json({
    blockchainStatus: blockchainStatus
  });
}));

router.use('/blockdata', blockData);
router.use('/addressdata', addressData);

module.exports = router;
