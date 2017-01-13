var express = require('express');
var bodyParser = require('body-parser');
var login = require("./routes/loginRoute");
var app = express();
var jano;

app.use(bodyParser.json()); // for parsing application/json
app.use(bodyParser.urlencoded({ extended: false })); // for parsing application/x-www-form-urlencoded
app.enable('trust proxy');

var conf = function(_jano) {
  jano = _jano;
  jano.configure({
    appName: 'testApp',
    rules: [
        { url: '\/api\/login', method:'POST', role:'\\w+', anon: true },
        { url: '\/api\/securedMethod', method:'POST|GET', role:'\\w+', anon: false },
        { url: '\/api\/anotherMethod', method:'POST', role:'admin|sales', anon: false },
        { url: '\/api[a-zA-Z]*', method:'POST|GET', role:'\\w+', anon: false },
        { url: '\/', method:'\\w+', role:'\\w+', anon: true }
    ],
    keysFolder: '/home/ubuntu/workspace/jano/test',
    validateIp: false,
    sessionFile: '/home/ubuntu/workspace/jano/test/janoSessions.json',
    authenticateFn: login.authenticateUserAgainstRepo,
    checkUserFn: login.isValidUserInRepo
  });
  
  //app.use(jano.sslFilter);
  app.use(jano.authFilter);
  app.use(jano.autzFilter);
  
  app.post('/api/login', 
    jano.signIn,                  //Jano function that invokes 'janoConf.authenticateFn' and generates a JWT
    function(req, res, next) {    //function to process response
      if (req.error) {
        res.status(500).json({ status: {code:500, message: req.error.message} });
        return;
      }
      //just return the signed JWT. Optionally this function could send a Cookie.
      res.status(200).json({ status: {'code':200, 'message':"user signed in"}, response: { 'jwt': req.jwt } });
  });
  
  app.post('/api/securedMethod', function(req, res) {
    res.status(200).json({ status: {code:200, message:"ok"}, response: { id:1, name:'secure transaction invoked' }});
  });
  
  app.post('/api/anotherMethod', function(req, res) {
    res.status(200).json({ status: {code:200, message:"ok"}, response: { id:1, name:'secure and role validated transaction invoked' }});
  });
  
  app.post('/api/logout', 
    jano.signOut,                  //Jano function that invalidates a previously generated JWT
    function(req, res, next) {     //function to process response 
      if (req.error) {
        res.status(500).json({ status: {code:500, message: req.error.message} });
        return;
      }
      //just return the signed JWT. Optionally this function could send a Cookie.
      res.status(200).json({ status: {'code':200, 'message':"user signed out"}, response: null });
  });
  
  app.listen(process.env.PORT, function () {
    console.log('Test server listening on '+process.env.IP+' port ' + process.env.PORT);
  })
}

module.exports = {
  app: app,
  conf: conf
};