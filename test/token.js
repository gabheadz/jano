var should = require('chai').should(),
    expect = require('chai').expect(),
    scapegoat = require('../token'),
    fs = require("fs"),
    sign = scapegoat.sign,
    verify = scapegoat.verify;

var signedJwt = '';

describe('#sign', function() {
  it('sign ok', function() {
    var payload = { 
        sub: 'jdoe',
        iss: 'applicationName',
        ipaddr: '127.0.0.1'
    }
    var cert = fs.readFileSync('./test/private_unencrypted.pem');  // get private key
    signedJwt = sign(payload, cert);
    signedJwt.should.not.equal('')
  });
  
  it('sign - no payload', function() {
    var payload = undefined;
    var cert = fs.readFileSync('./test/private_unencrypted.pem');  // get private key
    try {
      sign(payload, cert)
    } catch(err) {
      err.message.should.equal("Payload not defined");
    }
  });
  
  it('sign - no cert', function() {
    var payload = { 
        sub: 'jdoe',
        iss: 'applicationName',
        ipaddr: '127.0.0.1'
    }
    var cert;
    try {
      sign(payload, cert)
    } catch(err) {
      err.message.should.equal("invalid certificate");
    }
  });
  
  it('sign - no subject', function() {
    var payload = { 
        iss: 'applicationName',
        ipaddr: '127.0.0.1'
    }
    var cert = fs.readFileSync('./test/private_unencrypted.pem');  // get private key
    try {
      sign(payload, cert)
    } catch(err) {
      err.message.should.equal("No 'subject' defined in payload");
    }
  });
  
  it('sign - no issuer', function() {
    var payload = { 
        sub: 'jdoe',
        ipaddr: '127.0.0.1'
    }
    var cert = fs.readFileSync('./test/private_unencrypted.pem');  // get private key
    try {
      sign(payload, cert)
    } catch(err) {
      err.message.should.equal("No 'issuer' defined in payload");
    }
  });
  
  it('sign - no ip addr', function() {
    var payload = { 
        sub: 'jdoe',
        iss: 'applicationName'
    }
    var cert = fs.readFileSync('./test/private_unencrypted.pem');  // get private key
    try {
      sign(payload, cert)
    } catch(err) {
      err.message.should.equal("No 'ipaddr' defined in payload");
    }
  });  
  
});

describe('#verify', function() {
  it('verify ok', function() {
    var cert = fs.readFileSync('./test/public.pem');  // get public key
    var payload = verify(signedJwt, cert);
    payload.should.not.equal('');
    payload.sub.should.equal('jdoe');
    payload.iss.should.equal('applicationName');
  });

  it('verify - wrong issuer', function() {
    var cert = fs.readFileSync('./test/public.pem');  // get public key
    try {
      var payload = verify(signedJwt, cert, 'someApp');
    } catch (err) {
      err.message.should.equal('jwt issuer invalid. expected: someApp')
    }
  });
  
});