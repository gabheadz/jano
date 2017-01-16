```
       _                   
      | |                  
      | | __ _ _ __   ___  
  _   | |/ _` | '_ \ / _ \ 
 | |__| | (_| | | | | (_) |
  \____/ \__,_|_| |_|\___/ 
                               
```
---------------------------------

Security framework for REST APIs implemented with Express. 

This framework is aimed to restrict/permit API invocation based on authentication token (JWT) and authorization rules. 


# Install

```
npm install jano
```

# Usage

## Import into project

```
var jano = require("jano");
```

## Configuration

```
jano.configure({
  appName: 'testApp',
  rules: [
      { url: '\/api\/login', method:'POST', role:'\\w+', anon: true },
      { url: '\/api\/securedMethod', method:'POST|GET', role:'\\w+', anon: false },
      { url: '\/api\/anotherMethod', method:'POST', role:'admin|sales', anon: false },
      { url: '\/api[a-zA-Z]*', method:'POST|GET', role:'\\w+', anon: false },
      { url: '\/', method:'\\w+', role:'\\w+', anon: true }
  ],
  keysFolder: '/home/ubuntu/workspace/keys',
  validateIp: true,
  sessionFile: '/home/ubuntu/workspace/janoSessions.json',
  authenticateFn: authenticateUserAgainstRepo,
  checkUserFn: isUserValidInRepo
});
```


| Property | Description  |
|---|---|
| appName  | Name of API application being secured.  |
| rules | Array of rules for authorization. URL based.  |
| keysFolder |  Folder where Private and Public keys are located (for JWT signing and validation) |
| sessionFile | File for registering users that have been signed in |
| authenticateFn | User provided function invoked by the framework to autenticate an user/password against a repository |
| checkUserFn | User provided function invoked by the framework to validate an user in a repository |

### Using middleware in express app

```
app.use(jano.authFilter);
app.use(jano.autzFilter);
```

## Sign In

```
app.post('/api/login', 
  jano.signIn,                    //Jano function that invokes 'authenticateFn' and generates a signed JWT
  function(req, res, next) {      //function to process response
    if (req.error) {
      res.status(500).json({ status: {code:500, message: req.error.message} });
      return;
    }
    //just return the signed JWT. Optionally this function could send a Cookie.
    res.status(200).json({ status: {'code':200, 'message':"ok"}, response: { 'jwt': req.jwt } });
});
```

## Sign Out

```
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
```

## Securing API invocation

Basically no aditional code is required to secure routes. Since in ```app.use(..)``` we have especified the use of authentication and authorization filters defined in jano. 

```
app.post('/api/securedMethod', function(req, res) {
  //at this point jano has allowed the invocation of this route
  res.status(200).json({ status: {code:200, message:"ok"}, response: { id:1, name:'secure transaction invoked' }});
});

app.post('/api/anotherMethod', function(req, res) {
  //at this point jano has allowed the invocation of this route, based on rules defined in janoConf.
  res.status(200).json({ status: {code:200, message:"ok"}, response: { id:1, name:'secure and role validated transaction invoked' }});
});
```

The Client has to send the ```Authorization``` header in every request so jano can determine if user is authenticated/authorized.

```
var invokeMethod1 = function() {
 return $q(function(resolve, reject){

     $http.defaults.headers.common.Authorization = 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.[...]';

     $http.post('/api/securedMethod').
         success(function(data) {
             //method successfully invoked (http status 200) 
             resolve(data);
         })
         .error(function(err) {
             //method invocation unsuccessful. Rules were not satisfied (http status 401 or 403)
             console.log(err);
             reject(err);
         });
 });
};
``` 
