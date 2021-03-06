var chai = require('chai'),
    should = chai.should(),
    expect = chai.expect(),
    chaiHttp = require('chai-http'),
    fs = require("fs"),
    server = require("./server"),
    scapegoat = require('../index');

chai.use(chaiHttp);
server.conf(scapegoat);

var signedJwt = '';
var signedJwt2 = '';
var authJwt = '';

var expiredJWT = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqZG9lIiwiaXNzIjoidGVzdEFwcCIsImlwYWRkciI6IjIwMC4xNi43OS4yMiIsInJvbGVzIjpbInJvbGUxIiwicm9sZTIiXSwidXVpZCI6Ijg4N2E0ZDg3LTdhZDQtNDk3Yi04OGEwLTAwODZmYTFlNzU5OSIsImlhdCI6MTQ4NDE2Mjk0OCwiZXhwIjoxNDg0MTY2NTQ4fQ.XQI8HgO-aTPy9Acm0oIn_5CPaqvwBcw1TXw_7xVCsxwhroVRGo4cxQl2qlaTiz_lfSPvYIWGjr_5YsnWQpMmzQuraN4uIfWjUTAMeGrKMGR78CiLVQzvwtk_7W4lDHQeUx1OsM96CaBXhj3vC3p_L14nyvev2-3ENDX3dcmAtlKCi-M1lf1ZNj6U2yZZIsQTsLPoD0dTPRU6aY1NcaLv8muspYi0S52ugo0Vcg012MuuRXXccTcjq85N_lMACFon7_v0AEXGB37AtGQM5FMBMtIyyYcycfUNgsNrjnrkojmOE70N6fqNXQhziFe32Q2NB_5L8r9Pp-DoHNzfK-WdFQ';

var privateKey = '/home/ubuntu/workspace/jano/test/testApp.pem';
var publicKey = '/home/ubuntu/workspace/jano/test/testApp_public.pem';

var privateKey_sourceApp = '/home/ubuntu/workspace/jano/test/sourceApp.pem';
var publicKey_sourceApp = '/home/ubuntu/workspace/jano/test/sourceApp_public.pem';


describe('#token-sign', function() {
  it('should sign a JWT', function() {
    var payload = { 
        sub: 'jdoe',
        iss: 'applicationName',
        aud: 'applicationName',
        ipaddr: '127.0.0.1'
    }
    var result = scapegoat.tokenSign(payload, privateKey);
    signedJwt = result.jwt;
    signedJwt.should.not.equal('')
  });
  
  it('should sign a JWT - using source app cert', function() {
    var payload = {
        sub: 'jsmith',
        iss: 'sourceApp',
        aud: 'testApp',
        ipaddr: '127.0.0.1'
    }
    var result = scapegoat.tokenSign(payload, privateKey_sourceApp);
    signedJwt2 = result.jwt;
    signedJwt2.should.not.equal('');
  });
  
  it('should not sign a JWT - no payload', function() {
    var payload = undefined;
    try {
      scapegoat.tokenSign(payload, privateKey)
    } catch(err) {
      err.message.should.equal("Payload not defined");
    }
  });
  
  it('should not sign a JWT - no cert file', function() {
    var payload = { 
        sub: 'jdoe',
        iss: 'applicationName',
        ipaddr: '127.0.0.1'
    }
    var certFile = undefined;
    try {
      scapegoat.tokenSign(payload, certFile)
    } catch(err) {
      err.message.should.equal("invalid certificate");
    }
  });
  
  it('should not sign a JWT - no subject defined', function() {
    var payload = { 
        iss: 'applicationName',
        ipaddr: '127.0.0.1'
    }
    try {
      scapegoat.tokenSign(payload, privateKey)
    } catch(err) {
      err.message.should.equal("No 'subject' defined in payload");
    }
  });
  
  it('should not sign a JWT - no issuer defined', function() {
    var payload = { 
        sub: 'jdoe',
        ipaddr: '127.0.0.1'
    }
    try {
      scapegoat.tokenSign(payload, privateKey)
    } catch(err) {
      err.message.should.equal("No 'issuer' defined in payload");
    }
  });
  
  it('should not sign a JWT - no ip addres defined', function() {
    var payload = { 
        sub: 'jdoe',
        iss: 'applicationName'
    }
    try {
      scapegoat.tokenSign(payload, privateKey)
    } catch(err) {
      err.message.should.equal("No 'ipaddr' defined in payload");
    }
  });  
  
});

describe('#token-verify', function() {
  it('should verify a JWT', function() {
    var payload = scapegoat.tokenVerify(signedJwt, publicKey);
    payload.should.not.equal('');
    payload.sub.should.equal('jdoe');
    payload.iss.should.equal('applicationName');
  });

  it('should verify fail - issuer validation', function() {
    try {
      var claims = { 'iss': 'someApp'}
      var payload = scapegoat.tokenVerify(signedJwt, publicKey, 'someApp');
    } catch (err) {
      err.message.should.equal('jwt issuer invalid. expected: someApp')
    }
  });
  
  it('should verify fail - audience validation', function() {
    try {
      var claims = { 'aud': 'someRandomAudience'}
      var payload = scapegoat.tokenVerify(signedJwt, publicKey, claims);
    } catch (err) {
      err.message.should.equal('jwt audience invalid. expected: someRandomAudience')
    }
  });
  
  it('should verify fail - expired', function() {
    try {
      var payload = scapegoat.tokenVerify(expiredJWT, publicKey);
    } catch (err) {
      err.message.should.equal('jwt expired');
    }
  });  
  
  it('should verify fail - cert file does not exist', function() {
    try {
      var payload = scapegoat.tokenVerify(expiredJWT, '/some/path/to/nonexistent/file.pem');
    } catch (err) {
      err.message.should.equal("Error reading priv/pub key file for validation");
    }
  });    
  
  it('should verify fail - no cert file', function() {
    try {
      var payload = scapegoat.tokenVerify(expiredJWT, undefined);
    } catch (err) {
      err.message.should.equal("invalid certificate");
    }
  });   
  
  it('should verify fail - invalid token', function() {
    try {
      var payload = scapegoat.tokenVerify('ey.anf.sdff', publicKey);
    } catch (err) {
      err.message.should.equal("invalid token");
    }
  });   
  
  it('should verify fail - undefined token', function() {
    try {
      var payload = scapegoat.tokenVerify(undefined, publicKey);
    } catch (err) {
      err.message.should.equal("invalid token string");
    }
  });  
  
  it('should verify fail - null token', function() {
    try {
      var payload = scapegoat.tokenVerify(null, publicKey);
    } catch (err) {
      err.message.should.equal("invalid token string");
    }
  });    
});

describe('#sign in process', function() {
  
  it('should sign in - username and password', (done) => {
    var host = "http://" + process.env.IP + ':' + process.env.PORT;
    chai.request(host)
      .post('/api/login')
      .set('content-type', 'application/json')
      .send({username: 'jdoe', password: 'secret'})
      .end((err, res) => {
          if (err) {
            console.log(err);
          }
          res.should.have.status(200);
          res.body.should.be.a('object');
          res.body.should.have.property('response');
          res.body.response.should.have.property('jwt');
          authJwt = res.body.response.jwt;
        done();
      });
  });
  
  it('should not sign in - username and/or password missing', (done) => {
    var host = "http://" + process.env.IP + ':' + process.env.PORT;
    chai.request(host)
      .post('/api/login')
      .set('content-type', 'application/json')
      .send({username: 'rsmith'})
      .end((err, res) => {
          res.should.have.status(500);
          res.error.should.have.property('message');
          res.error.text.should.equal('{"status":{"code":500,"message":"Username and/or password credentials not provided in request body."}}');
        done();
      });
  });
  
  it('should not sign in - unknowk strategy', (done) => {
    var host = "http://" + process.env.IP + ':' + process.env.PORT;
    chai.request(host)
      .post('/api/login')
      .end((err, res) => {
          res.should.have.status(500);
          res.error.should.have.property('message');
          res.error.text.should.equal('{"status":{"code":500,"message":"Unable to determine authentication strategy."}}');
        done();
      });
  });
  
  it('should sign in - jwt strategy', (done) => {
    var host = "http://" + process.env.IP + ':' + process.env.PORT;
    chai.request(host)
      .get('/api/login?token='+signedJwt2)
      .end((err, res) => {
          res.should.have.status(200);
          res.body.should.have.property('response');
          res.body.response.should.have.property('jwt');
        done();
      });
  });
  
  it('should not sign in - jwt strategy - expired', (done) => {
    var host = "http://" + process.env.IP + ':' + process.env.PORT;
    chai.request(host)
      .get('/api/login?token='+expiredJWT)
      .end((err, res) => {
          res.should.have.status(500);
          res.error.should.have.property('message');
          res.error.text.should.equal('{"status":{"code":500,"message":"Token validation failed"}}');
        done();
      });
  });
  
});
  
describe('#authentication Filter', function() {
  
  it('should allow an authenticaded user to invoke api', (done) => {
    var host = "http://" + process.env.IP + ':' + process.env.PORT;
    chai.request(host)
      .post('/api/securedMethod')
      .set('content-type', 'application/json')
      .set('Authorization', 'Bearer ' + authJwt)
      .end((err, res) => {
          if (err) {
            console.log(err);
          }
          res.should.have.status(200);
          res.body.should.be.a('object');
          res.body.should.have.property('response');
        done();
      });
  });
  
  it('should not allow api invocation due to expired JWT', (done) => {
    var host = "http://" + process.env.IP + ':' + process.env.PORT;
    chai.request(host)
      .post('/api/securedMethod')
      .set('content-type', 'application/json')
      .set('Authorization', 'Bearer ' + expiredJWT)
      .end((err, res) => {
          res.should.have.status(401);
          res.error.text.should.equal('{"error":"jwt expired"}');
          done();
      });
  });
  
  it('should not allow api invocation due to Authorization header missing', (done) => {
    var host = "http://" + process.env.IP + ':' + process.env.PORT;
    chai.request(host)
      .post('/api/securedMethod')
      .set('content-type', 'application/json')
      .end((err, res) => {
          res.should.have.status(401);
          res.error.should.have.property('message');
          res.error.text.should.equal('{"error":"No authorization header present"}');
        done();
      });
  });
  
})

describe('#authorization Filter', function() {
  
  it('should not allow authenticaded user invoke api due lack of privileges', (done) => {
    var host = "http://" + process.env.IP + ':' + process.env.PORT;
    chai.request(host)
      .post('/api/anotherMethod')
      .set('content-type', 'application/json')
      .set('Authorization', 'Bearer ' + authJwt)
      .end((err, res) => {
          res.should.have.status(403);
          res.error.should.have.property('message');
          res.error.text.should.equal('{"error":"Insufficient privileges to invoke api method"}');
        done();
      });
  });
  
})

describe('#sign out process', function() {
  
  it('should sign out', (done) => {
    var host = "http://" + process.env.IP + ':' + process.env.PORT;
    chai.request(host)
      .post('/api/logout')
      .set('content-type', 'application/json')
      .set('Authorization', 'Bearer ' + authJwt)
      .end((err, res) => {
          if (err) {
            console.log(err);
          }
          res.should.have.status(200);
          res.body.should.be.a('object');
          res.body.should.have.property('response');
        done();
      });
  });
  
  it('should not allow signed out user to invoke api', (done) => {
    var host = "http://" + process.env.IP + ':' + process.env.PORT;
    chai.request(host)
      .post('/api/securedMethod')
      .set('content-type', 'application/json')
      .set('Authorization', 'Bearer ' + authJwt)
      .end((err, res) => {
          res.should.have.status(401);
          res.error.should.have.property('message');
          res.error.text.should.equal('{"error":"Not a valid token"}');
        done();
      });
  });
  
});
  