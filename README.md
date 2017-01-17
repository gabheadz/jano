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



## Rules

Jano configuration includes an array of rules to be applied to incoming requests in order to determine if an application endpoint is to be autorized and a route method invoked.

Rules are defined as follows:

```
var aRule = { url: '\/api\/securedMethod', method:'POST|GET', role:'\\w+', anon: false }
```

| Property | Description  |
|---|---|
| url  | The application endpoint defined in app (regular expression)  |
| method | Method or methods allowed (regular expression)  |
| role | user role o roles required to grant application endpoint invocation (regular expression) |
| anon | flag indicating that the application endpoint may be called anonymously. If this property is ```true``` no authentication validation is performed and roles defined un ```role``` atribute are not enforced. |

Order is important: First rule matched given a url and method will be used to authorize the request. All subsequent rules are discarded.

## Keys and Keys Folder

Jano uses private/public keys to Sign and Validate Json Web Tokens (JWTs). JWTs are generated and signed using a private key and returned to client upon successful authentication. Client is bound to send this JWT in the ```Authorization``` header in every request. Jano will validate the existence of this header value and will validate the JWT signature using a public Key.

So, every application should have a key pair (private/public) which will be used by Jano. The location of these keys are specified in ```keysFolder``` property.

The certificate files shoud be named in accordance to the application name defined in the ```appName```attribute. Let's say:

```
jano.configure({
  appName: 'testApp',
  ...
  keysFolder: '/home/ubuntu/workspace/keys',
  ...
```
Jano will expect two files in **/home/ubuntu/workspace/keys** folder: 

- **testApp.pem** (the private key)  
- **testApp_public.pem** (the public key)


## Session File

Jano uses a in-memmory database (LokiJS) to mantain a registry of signed JWT's. This is not a web session or web session related data,  since API should be stateless. This in-memmory db uses this file to persist data automatically from time to time.

So, 

- Every time a user signs in and a JWT is generated, the JWT uuid is registered in this db, with a status ```isActive = true```
- When an user signs out, the JWT associated with that user is marked as no longer active. ```isActive = false```

This helps to determine which JWTs are not longer valid, since JWTs have an expiry time that cannot be altered. A user may sign out after a short period of time and the JWT associated is still valid (since it has not expired). This registry helps to control the future use of a JWT that a user 'discarded' when signed out.

## Sign In

Jano provides a function to sign a JWT with the user subject name and its roles ```signIn```. This method relies on the **authenticateFn** provided by the app.

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
### The *'authenticateFn'* function

Jano expects this function to return a Promise. The function will be passed the username and password parameters.

```
/*
* Function to perform authentication against an user repo.
*/
exports.authenticateUserAgainstRepo = function(username, password) {
    return new Promise(function(resolve, reject){
        if (!username || !password) {
            reject(new Error("username and/or password not provided"));
        }
        else {
            //TODO: Connect to an user repository (example: ldap) and check user/password
            //TODO: Get user groups, and translate them into roles

            /* If successful, return an JSON object with the subject and roles.
             * Jano will use this info in the payload that will be signed into the JWT
             */
            resolve({ 'subject': username, 'roles': ['role1', 'role2'] })
            
            //If authentication not successful reject promise with an error:
            //reject(new Error("Wrong username and/or password"));
            //reject(new Error("Unexpected error during login process"));
        }
	});
};
```


## Sign Out

Jano provides a signOut function which registers the associated user JWT as no longer valid. Subsequent invocations by the client of the API using that JWT in the authorization header, will fail with a 401 error.

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

## Securing API endpoints

In order to secure API endpoints defined in Express, you have to indicate the app to use the Jano Filters:

```
app.use(jano.authFilter);
app.use(jano.autzFilter);
```

Basically no aditional code is required in the routing endpoints or endpoint methods. 

```
app.post('/api/securedMethod', function(req, res) {
  
  //hey Mom look... no hands (a.k.a business logic)
  
  res.status(200).json({ status: {code:200, message:"ok"}, response: { id:1, name:'secure transaction invoked' }});
});

```

The Client has to send the ```Authorization``` header in every request so jano filters can determine if user is authenticated/authorized.

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
