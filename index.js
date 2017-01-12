var janoAuthFilter = require('./authFilter');
var janoAutzFilter = require('./autzFilter');
var janoSslFilter = require('./sslFilter');
var janoAuth = require('./auth');

var _conf = {
  whitelisted: [],
  rules: [
      { url: '\\/[a-zA-Z]*', method:'POST|GET', role:'\\w+', anon: true }
  ],
  publicKey: './test/public.pem',
  privateKey: './test/private_unencrypted.pem', 
  validateIp: false,
  checkUser: function(){ return true; }
}

module.exports = {
  
  configure: function(conf) {
    _conf = conf;
  },
  
  /**
  * Filters any request that doesnt provide any authentication credential
  */
  authFilter: function(req, res, next){
    if (!req.janoConf) {
      req.janoConf= _conf;
    }
    return janoAuthFilter.filter(req, res, next);
  },

  /**
   * Filters any request that doesnt match authorization criteria
   */
  autzFilter: function(req, res, next) {
    if (!req.janoConf) {
      req.janoConf = _conf;
    }
    return janoAutzFilter.filter(req, res, next);
  }, 
  
  /**
   * Filters any request not made via secure protocol
  */
  sslFilter: function(req, res, next) {
    return janoSslFilter.filter(req, res, next)
  },
  
  auth: janoAuth
};