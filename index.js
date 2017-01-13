var janoAuthFilter = require('./authFilter');
var janoAutzFilter = require('./autzFilter');
var janoSslFilter = require('./sslFilter');
var janoAuth = require('./auth');
var token = require("./token");
var loki = require("lokijs");

var db;

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
  keysFolder:  '/home/ubuntu/workspace/jano/keys',
  validateIp: false,
  sessionFile: '/home/ubuntu/workspace/jano/janoSessions.json',
  authenticateFn: undefined,
  checkUserFn: undefined,
}

module.exports = {
  
  configure: function(conf) {
    _conf = conf;
    
    var sessionFile;
    if (!_conf.sessionFile) {
      _conf.sessionFile = './janoSessions.json';
    } 
    db = new loki(_conf.sessionFile);
    _conf.db = db;
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
  
  signIn: function (req, res, next) {
    if (!req.janoConf) {
      req.janoConf = _conf;
    }    
    return janoAuth.signIn(req, res, next);
  },
  
  signOut: function (req, res, next) {
    if (!req.janoConf) {
      req.janoConf = _conf;
    }    
    return janoAuth.signOut(req, res, next);
  }
  
};