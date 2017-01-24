var jwt = require('jsonwebtoken');
var fs = require("fs");

const uuidV4 = require('uuid/v4');
const debug = require('debug')('jano');

module.exports = {
  /**
  * Takes an object payload and a private cert and generates a signed JWT.
  *
  * @param  {object} payload
  * @param  {String} private cert file name
  * @return {String} jwt
  */
  sign: function(payload, cert) {
    
    var options = {
      algorithm: "RS256",
      expiresIn: "1h"
    };
    
    if (!payload || payload === undefined) {
      throw new Error('Payload not defined');
    }
    
    if (!payload.iss || payload.iss === undefined) { 
      throw new Error('No \'issuer\' defined in payload');
    }
    
    if (!payload.sub || payload.sub === undefined) { 
      throw new Error('No \'subject\' defined in payload');
    }
    
    if (!payload.ipaddr || payload.ipaddr === undefined) { 
      throw new Error('No \'ipaddr\' defined in payload');
    }
    
    if (!cert || cert === undefined) {
      throw new Error('invalid certificate');
    }
    
    payload.uuid = uuidV4();
    
    if (!cert) {
      throw new Error('invalid certificate file for signing');
    }
    
    var thisAppPrivateKey;  

    try {
        thisAppPrivateKey = fs.readFileSync(cert); // read private key file
    } catch (err) {
        debug(err);
        throw err;
    }
    
    var token = jwt.sign(payload, thisAppPrivateKey, options);
    
    return { 'payload': payload, 'jwt': token};

  },

  /**
   * Takes a signed JWT and a private cert and verifies its signature. On success, this
   * function returns the jwt payload
   *
   * @param  {String} signed jwt
   * @param  {String} the public cert file name
   * @param  {object} claims to validate (optional)
   * @return {object} the object payload
   */
  verify: function(token, cert, claims) {
    
    if (!token || token === undefined) {
      throw new Error('invalid token string');
    }
    
    if (!cert || cert === undefined) { 
      throw new Error('invalid certificate');
    }
    
    var options = {
      algorithms: ['RS256']
    }
    
    
    if (claims) {
      if (claims.iss)
        options.issuer = claims.iss;
      if (claims.aud)
          options.audience = claims.aud;
    }
    
    var thisAppPublicKey;  

    try {
        thisAppPublicKey = fs.readFileSync(cert); // read public key file
    } catch (err) {
        debug(err);
        throw new Error('Error reading priv/pub key file for validation');
    }
    
    return jwt.verify(token, thisAppPublicKey, options);
    
  },
  
    /**
   * Takes a signed JWT and decode it (whitout signature validation)
   *
   * @param  {String} signed jwt
   * @return {object} the object payload
   */
  decode: function(token) {
    if (!token || token === undefined) {
      throw new Error('invalid token string');
    }
    
    return jwt.decode(token, {complete: true});
  }
  
};