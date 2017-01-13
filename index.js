var janoAuthFilter = require('./authFilter');
var janoAutzFilter = require('./autzFilter');
var janoSslFilter = require('./sslFilter');
var janoAuth = require('./auth');
var token = require("./token");

var _conf = {
  appName: 'testApp',
  whitelisted: [],
  rules: [
      { url: '\/api\/login', method:'POST', role:'\\w+', anon: true },
      { url: '\/api\/securedMethod', method:'POST|GET', role:'\\w+', anon: false },
      { url: '\/api\/anotherMethod', method:'POST', role:'admin|sales', anon: false },
      { url: '\/api[a-zA-Z]*', method:'POST|GET', role:'\\w+', anon: false },
      { url: '\/', method:'\\w+', role:'\\w+', anon: true }
  ],
  publicKey: '/home/workspace/public.pem',
  privateKey: '/home/workspace/private_unencrypted.pem',
  validateIp: false,
  sessionFile: '/home/workspace/janoSessions.json',
  authenticateFn: undefined,
  checkUserFn: undefined,
}

module.exports = {
  
  configure: function(conf) {
    _conf = conf;
  },
  
  /**
   * Function to sign a JWT
   */
  tokenSign: token.sign,
  
  /**
   * Function to verify a signed JWT
   */ 
  tokenVerify: token.verify,
  
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
    if (!req.janoConf) {
      req.janoConf = _conf;
    }    
    return janoSslFilter.filter(req, res, next)
  },
  
  auth: function (req, res, next) {
    if (!req.janoConf) {
      req.janoConf = _conf;
    }    
    return janoAuth(req, res, next);
  }
  
};