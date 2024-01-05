
# Myinfo Connector NodeJS

[![Known Vulnerabilities](https://snyk.io/test/github/singpass/myinfo-connector-nodejs/badge.svg)](https://snyk.io/test/github/singpass/myinfo-connector-v4-nodejs)

Myinfo Connector NodeJS aims to simplify consumer's integration effort with MyInfo by providing an easy to use Javascript library to integrate into your application.


## Contents

- [Myinfo Connector NodeJS](#myinfo-connector-nodejs)
  - [Contents](#contents)
  - [1. Installation](#1-installation)
    - [1.1. Using npm:](#11-using-npm)
  - [2. Usage](#2-usage)
    - [2.1. Sample Code](#21-sample-code)
    - [2.2. Process Environment file](#22-process-environment-file)
  - [3. Individual Method](#3-individual-method)
    - [3.1. Get MyInfo Person Data](#31-get-myinfo-person-data)
    - [3.2. Generate Code Verifier and Code Challenge](#32-generate-code-verifier-and-code-challenge)
    - [3.3. Get Access Token](#33-get-access-token)
    - [3.4. Get Person Data](#34-get-person-data)
  - [Reporting Issue](#reporting-issue)




## <a name="installation"></a>1. Installation

### <a name="install"></a>1.1. Using npm:

``` 
$ npm install myinfo-connector-v4-nodejs 
```

## <a name="usage"></a>2. Usage

### <a name="sample"></a>2.1. Sample Code

```
var MyInfoConnector = require('myinfo-connector-v4-nodejs'); //Call constructor to initialize library and pass in the configurations.

let connector = new MyInfoConnector(config.MYINFO_CONNECTOR_CONFIG); // MYINFO_CONNECTOR_CONFIG is the Process Environment file (in JSON format), please refer to Process Environment file in 2.2


  /**
   * Get Myinfo Person Data (Myinfo Token + Person API)
   *
   * This method takes in all the required variables, invoke the following APIs.
   * - Get Access Token (Token API) - to get Access Token by using the Auth Code
   * - Get Person Data (Person API) - to get Person Data by using the Access Token
   *
   * @param {string} authCode - Authorization Code from Authorize API
   * @param {string} codeVerifier - Code verifier that corresponds to the code challenge used to retrieve authcode
   * @param {string} privateSigningKey -  Your application private signing key in .pem format
   * @param {Array} privateEncryptionKeys -  Your application private encryption keys in .pem format, pass in a list of private keys that corresponds to JWKS encryption public keys
   *
   * @returns {Promise} - Returns the Person Data (Payload decrypted + Signature validated)
   */

try{
  let personData = await connector.getMyInfoPersonData(authCode, codeVerifier, privateSigningKey, privateEncryptionKeys);

  return personData;
} catch (error) {
  throw error;
}

```

    
### <a name="config"></a>2.2. Process Environment file
You are required to create an environment file (in JSON format) with the following process environments for this library. You may look at the sample Process Environment file [HERE](https://github.com/singpass/myinfo-demo-app-v4/blob/main/config/config.js). 

| Required Properties | Description |
| -------- | ----------- |
| CLIENT_ID |  Client id provided during onboarding (e.g. _STG2-MYINFO-SELF-TEST_)|
| REDIRECT_URL | The callback URL specified when invoking the authorize call. For our sample application, it is http://localhost:3001/callback |
| SCOPE | Comma separated list of attributes requested. Possible attributes are listed in the Person object definition in the API specifications. (e.g. _name mobileno_) |
| AUTHORIZE_JWKS_URL | The URL to retrieve the JWKS public key from Authorize. The URL is available in two environments:<ul><li> TEST: https://test.authorise.singpass.gov.sg/.well-known/keys.json</li><li>PRD: https://authorise.singpass.gov.sg/.well-known/keys.json</li>|
| MYINFO_JWKS_URL | The URL to retrieve Myinfo JWKS public key. The URL is available in two environments:<ul><li> TEST: https://test.myinfo.singpass.gov.sg/.well-known/keys.json</li><li>PRD: https://myinfo.singpass.gov.sg/.well-known/keys.json</li>|
| TOKEN_URL | Specify the TOKEN API URL for MyInfo. The API is available in two environments:<ul><li>TEST: https://test.api.myinfo.gov.sg/com/v4/token</li><li>PROD: https://api.myinfo.gov.sg/com/v4/token</li></ul> |
| PERSON_URL | Specify the PERSON API URL for MyInfo. The API is available in two environments: <ul><li>TEST: https://test.api.myinfo.gov.sg/com/v4/person</li><li>PROD: https://api.myinfo.gov.sg/com/v4/person</li></ul>|
| CLIENT_ASSERTION_SIGNING_KID <br>_(OPTIONAL)_ | kid that will be appended to client_assertion header to match JWKS kid. | 
| SUBENTITY_ID <br>_(OPTIONAL)_ | for platform applications only to specify subentity | 
| USE_PROXY <br>_(OPTIONAL)_ | Indicate the use of proxy url. It can be either `Y` or `N`.|
| PROXY_TOKEN_URL <br>_(OPTIONAL)_ | _(REQUIRED if `USE_PROXY` is `Y`)_ <br> If you are using a proxy url, specify the proxy URL for TOKEN API here. |
| PROXY_PERSON_URL <br>_(OPTIONAL)_ | _(REQUIRED if `USE_PROXY` is `Y`)_ <br> If you are using a proxy url, specify the proxy URL for PERSON API here.|
| DEBUG_LEVEL <br>_(OPTIONAL)_ | _(OPTIONAL: if empty will be defaulted to no logs)_ <br> Configuration to set logging level for debugging within the library.  <table><tr><th>Mode</th><th>Description</th></tr><tr><td>`error`</td><td>Log out all the errors returned from the library</td></tr><tr><td>`info`</td><td>Log urls called, authorization headers and errors from the library</td></tr><tr><td>`debug`</td><td>Full logs from the library, i.e (errors, urls, authorization headers, API response)</td></tr></table> IMPORTANT NOTE: `debug` mode **should never be turned on in production**



## <a name="helper"></a>3. Individual Method

Under the hood, MyInfo Connector NodeJS makes use of **SecurityHelper** and you may use the class as util methods to meet your application needs.
### <a name="getMyInfoPersonData"></a>3.1. Get MyInfo Person Data
This method takes in all the required parameters to get MyInfo Person Data.

```
var MyInfoConnector = require('myinfo-connector-nodejs'); //Call constructor to initialize library and pass in the configurations.

let connector = new MyInfoConnector(config.MYINFO_CONNECTOR_CONFIG); // MYINFO_CONNECTOR_CONFIG is the Process Environment file (in JSON format), please refer to Process Environment file in 2.2

  /**
   * Get MyInfo Person Data (MyInfo Token + Person API)
   *
   * This method takes in all the required variables, invoke the following APIs.
   * - Get Access Token (Token API) - to get Access Token by using the Auth Code
   * - Get Person Data (Person API) - to get Person Data by using the Access Token
   *
   * @param {string} authCode - Authorization Code from Authorize API
   * @param {string} codeVerifier - Code verifier that corresponds to the code challenge used to retrieve authcode
   * @param {string} privateSigningKey -  Your application private signing key in .pem format
   * @param {Array} privateEncryptionKeys -  Your application private encryption keys in .pem format, pass in a list of private keys that corresponds to JWKS encryption public keys
   *
   * @returns {Promise} - Returns the Person Data (Payload decrypted + Signature validated)
   */
  getMyInfoPersonData = function (authCode, codeVerifier, privateSigningKey, privateEncryptionKeys)
```

### <a name="generatePKCECodePair"></a>3.2. Generate Code Verifier and Code Challenge
This method generates the code verifier and the code challenge for the PKCE flow.

```
  /**
   * This method generates the code verifier and code challenge for the PKCE flow.
   * 
   * @returns {Object} - Returns an object consisting of the code verifier and the code challenge
   */
  generatePKCECodePair = function ()
```

### <a name="getAccessToken"></a>3.3. Get Access Token
This method takes in the authCode obtained from Authorize API and returns the access token.

```
  /**
   * Get Access Token from MyInfo Token API
   *
   * This method calls the Token API and obtain an "access token",
   * which can be used to call the Person API for the actual data.
   * Your application needs to provide a valid "authorisation code"
   * from the authorize API in exchange for the "access token".
   *
   * @param {string} authCode - Authorization Code from authorize API
   * @param {string} codeVerifier - Code verifier that corresponds to the code challenge used to retrieve authcode
   * @param {object} sessionEphemeralKeyPair - Session EphemeralKeyPair used to sign DPoP
   * @param {string} privateSigningKey -  Your application private signing key in .pem format
   * @returns {Promise} - Returns the Access Token
   */
  getAccessToken = function (authCode,codeVerifier,sessionEphemeralKeyPair,privateSigningKey)
```

### <a name="getPersonData"></a>3.4. Get Person Data
This method takes in the accessToken and returns the person data.

```
  /**
   * Get Person Data from MyInfo Person API
   *
   * This method calls the Person API and returns a JSON response with the
   * personal data that was requested. Your application needs to provide a
   * valid "access token" in exchange for the JSON data. Once your application
   * receives this JSON data, you can use this data to populate the online
   * form on your application.
   *
   * @param {string} accessToken - Access token from Token API
   * @param {object} sessionEphemeralKeyPair - Session EphemeralKeyPair used to sign DPoP
   * @param {Array} privateEncryptionKeys -  Your application private encryption keys in .pem format, pass in a list of private keys that corresponds to JWKS encryption public keys
   * @returns {Promise} Returns the Person Data (Payload decrypted + Signature validated)
   */
  getPersonData = function (accessToken, sessionPopKeyPair, privateEncryptionKeys)
```

## Reporting Issue

You may contact our [support](mailto:support@myinfo.gov.sg?subject=[MyInfoLib-NodeJs]%20Issue%20) for any other technical issues, and we will respond to you within 5 working days.
