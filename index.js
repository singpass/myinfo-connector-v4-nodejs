const querystring = require("querystring");
const constant = require("./common/constant");
const urlParser = require("url");
const requestHandler = require("./lib/requestHandler.js");
const schema = require("./common/config");
const log4js = require("log4js");
const logger = log4js.getLogger("MyInfoNodeJSConnector");
const crypto = require("crypto");

// ####################
// Exporting the Module
// ####################

/**
 * MyInfoConnector Constructor
 *
 * This is a constructor to validate and initialize all the config variables
 *
 * @param {{
 * CLIENT_ID {string},
 * SUBENTITY_ID {string},
 * REDIRECT_URL {string},
 * SCOPE {string},
 * AUTHORIZE_JWKS_URL {string},
 * MYINFO_JWKS_URL {string},
 * TOKEN_URL {string},
 * PERSON_URL {string},
 * CLIENT_ASSERTION_SIGNING_KID {string},
 * USE_PROXY {string},
 * PROXY_TOKEN_URL {string},
 * PROXY_PERSON_URL {string},
 * DEBUG_LEVEL {string},
 * }}
 */
class MyInfoConnector {
  isInitialized = false;
  CONFIG ={}

  constructor(config) {

    try {
      this.CONFIG = config;
      logger.level = this.CONFIG.DEBUG_LEVEL;
      this.securityHelper = require("./lib/securityHelper");

      this.securityHelper.validateSchema(config, schema);
      this.isInitialized = true;
    } catch (error) {
      this.isInitialized = false;
      logger.error("Error (Library Init): ", error);
      throw error;
    }
  }

  /**
   * This method generates the code verifier and code challenge for the PKCE flow.
   *
   * @returns {Object} - Returns an object consisting of the code verifier and the code challenge
   */
  generatePKCECodePair = function () {
    try {
      let codeVerifier = crypto.randomBytes(32).toString("hex"); //generate a cryptographically strong random string
      let codeChallenge = this.securityHelper.base64URLEncode(
        //base64url encode the sha256 hash of the codeVerifier
        this.securityHelper.sha256(codeVerifier)
      );
      return {
        codeVerifier: codeVerifier,
        codeChallenge: codeChallenge,
      };
    } catch (error) {
      logger.error("generateCodeChallenge - Error: ", error);
      throw error;
    }
  };

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
  getMyInfoPersonData = async function (
    authCode,
    codeVerifier,
    privateSigningKey,
    privateEncryptionKeys
  ) {
    if (!this.isInitialized) {
      throw constant.ERROR_UNKNOWN_NOT_INIT;
    }

    try {
      let sessionEphemeralKeyPair =
        await this.securityHelper.generateSessionKeyPair(); // Generate a new session Ephemeral Key pair for every request to sign DPoP

      //create API call to exchange autcode for access_token
      let access_token = await this.getAccessToken(
        authCode,
        codeVerifier,
        sessionEphemeralKeyPair,
        privateSigningKey
      );
      //create API call to exchange access_token to retrieve user's data
      let personData = await this.getPersonData(
        access_token,
        sessionEphemeralKeyPair,
        privateEncryptionKeys
      );
      return personData;
    } catch (error) {
      throw error;
    }
  };

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
  getAccessToken = async function (
    authCode,
    codeVerifier,
    sessionEphemeralKeyPair,
    privateSigningKey
  ) {
    if (!this.isInitialized) {
      throw constant.ERROR_UNKNOWN_NOT_INIT;
    }

    try {
      let tokenResult = await this.callTokenAPI(
        authCode,
        privateSigningKey,
        codeVerifier,
        sessionEphemeralKeyPair
      );
      logger.debug("Access Token Response: ", tokenResult);
      return tokenResult.access_token;
    } catch (error) {
      logger.error("getAccessToken - Error: ", error);
      throw error;
    }
  };

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
  getPersonData = async function (
    accessToken,
    sessionPopKeyPair,
    privateEncryptionKeys
  ) {
    if (!this.isInitialized) {
      throw constant.ERROR_UNKNOWN_NOT_INIT;
    }

    try {
      let callPersonRequestResult = await this.getPersonDataWithToken(
        accessToken,
        sessionPopKeyPair,
        privateEncryptionKeys
      );

      return callPersonRequestResult;
    } catch (error) {
      logger.error("getPersonData - Error: ", error);
      throw error;
    }
  };
  /**
   * Call (Access) Token API
   *
   * This method will generate the Token request
   * and call the Token API to retrieve access Token
   *
   * @param {string} authCode - Authorization Code from authorize API
   * @param {File} privateSigningKey - The Client Private Key in PEM format
   * @param {string} codeVerifier - Code verifier that corresponds to the code challenge used to retrieve authcode
   * @param {object} sessionEphemeralKeyPair - Session EphemeralKeyPair used to sign DPoP
   *
   * @returns {Promise} - Returns the Access Token
   */
  callTokenAPI = async function (
    authCode,
    privateSigningKey,
    codeVerifier,
    sessionEphemeralKeyPair
  ) {
    let cacheCtl = "no-cache";
    let contentType = "application/x-www-form-urlencoded";
    let method = constant.HTTP_METHOD.POST;
    let clientAssertionType =
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    //generate jkt thumbprint from Ephemeral public key
    let jktThumbprint = await this.securityHelper.generateJwkThumbprint(
      sessionEphemeralKeyPair.publicKey
    );
    let strParams;
    // assemble params for Token API
    strParams =
      `grant_type=authorization_code` +
      "&code=" + //grant type is 'code' for authorization_code flow
      authCode +
      "&redirect_uri=" +
      this.CONFIG.REDIRECT_URL + // redirect url should match redirect url used in /authorise call
      "&client_id=" +
      this.CONFIG.CLIENT_ID +
      "&code_verifier=" +
      codeVerifier +
      "&client_assertion_type=" +
      clientAssertionType +
      "&client_assertion=" +
      (await this.securityHelper.generateClientAssertion(
        this.CONFIG.TOKEN_URL,
        this.CONFIG.CLIENT_ID,
        privateSigningKey,
        jktThumbprint,
        this.CONFIG.CLIENT_ASSERTION_SIGNING_KID
      ));

    //generate corresponding DPoP for client_assertion
    let dPoP = await this.securityHelper.generateDpop(
      this.CONFIG.TOKEN_URL,
      null,
      constant.HTTP_METHOD.POST,
      sessionEphemeralKeyPair
    );

    // assemble headers for Token API
    let strHeaders = `Content-Type=${contentType}&Cache-Control=${cacheCtl}&DPoP=${dPoP}`;
    let headers = querystring.parse(strHeaders);

    // invoke Token API
    let tokenURL =
    this.CONFIG.USE_PROXY && this.CONFIG.USE_PROXY == "Y"
        ? this.CONFIG.PROXY_TOKEN_URL
        : this.CONFIG.TOKEN_URL;
    let accessToken = await requestHandler.getHttpsResponse(
      method,
      tokenURL,
      headers,
      strParams,
      null
    );

    return accessToken.data;
  };

  /**
   * Call Person API
   *
   * This method will generate the Person request and
   * call the Person API to get the encrypted Person Data
   *
   * @param {string} sub - The retrieved uuid sub from the decoded access_token
   * @param {string} accessToken - The encoded access_token from /token API
   * @param {object} sessionEphemeralKeyPair - Session EphemeralKeyPair used to sign DPoP
   *
   * @returns {Promise} Returns result from calling Person API
   */
  callPersonAPI = async function (sub, accessToken, sessionEphemeralKeyPair) {
    let urlLink;

    urlLink = this.CONFIG.PERSON_URL + "/" + sub;

    let cacheCtl = "no-cache";
    let method = constant.HTTP_METHOD.GET;

    // assemble params for Person API
    let strParams = "scope=" + encodeURIComponent(this.CONFIG.SCOPE);
    //append subentity if configured
    if (this.CONFIG.SUBENTITY_ID) {
      strParams = `${strParams}&subentity=${this.CONFIG.SUBENTITY_ID}`;
    }

    // assemble headers for Person API
    let strHeaders = "Cache-Control=" + cacheCtl;
    let headers = querystring.parse(strHeaders);

    //generate ath to append into DPoP
    let ath = this.securityHelper.base64URLEncode(
      this.securityHelper.sha256(accessToken)
    );
    //generate DPoP
    let dpopToken = await this.securityHelper.generateDpop(
      urlLink,
      ath,
      method,
      sessionEphemeralKeyPair
    );
    headers["dpop"] = dpopToken;

    headers["Authorization"] = "DPoP " + accessToken;

    logger.info(
      "Authorization Header for MyInfo Person API: ",
      JSON.stringify(headers)
    );

    // invoke person API
    let personURL =
    this.CONFIG.USE_PROXY && this.CONFIG.USE_PROXY == "Y"
        ? this.CONFIG.PROXY_PERSON_URL
        : this.CONFIG.PERSON_URL;
    let parsedUrl = urlParser.parse(personURL);
    let domain = parsedUrl.hostname;
    let requestPath = parsedUrl.path + "/" + sub + "?" + strParams;
    //invoking https to do GET call

    let personData = await requestHandler.getHttpsResponse(
      method,
      "https://" + domain + requestPath,
      headers,
      null,
      null
    );

    return personData.data;
  };

  /**
   * Get Person Data
   *
   * This method will take in the accessToken from Token API and decode it
   * to get the sub(eg either uinfin or uuid). It will call the Person API using the token and sub.
   * It will verify the Person API data's signature and decrypt the result.
   *
   * @param {string} accessToken - The encoded token that was returned from /token API
   * @param {object} sessionEphemeralKeyPair - Session EphemeralKeyPair used to sign DPoP
   * @param {Array} privateEncryptionKeys -  Your application private encryption keys in .pem format, pass in a list of private keys that corresponds to JWKS encryption public keys
   * @returns {Promise} Returns decrypted result from calling Person API
   */
  getPersonDataWithToken = async function (
    accessToken,
    sessionEphemeralKeyPair,
    privateEncryptionKeys
  ) {
    try {
      //decode and verify token
      let decodedToken = await this.securityHelper.verifyJWS(
        accessToken,
        this.CONFIG.AUTHORIZE_JWKS_URL
      );
      logger.debug(
        "Decoded Access Token (from MyInfo Token API): ",
        decodedToken
      );
      if (!decodedToken) {
        logger.error("Error: ", constant.ERROR_INVALID_TOKEN);
        throw constant.ERROR_INVALID_TOKEN;
      }

      let uinfin = decodedToken.sub;
      if (!uinfin) {
        logger.error("Error: ", constant.ERROR_UINFIN_NOT_FOUND);
        throw constant.ERROR_UINFIN_NOT_FOUND;
      }
      let personResult;
      personResult = await this.callPersonAPI(
        uinfin,
        accessToken,
        sessionEphemeralKeyPair
      );

      let decryptedResponse;
      if (personResult) {
        logger.debug("MyInfo PersonAPI Response (JWE+JWS): ", personResult);
        //Test decryption with different keys passed in (in the event that multiple enc keys configured on JWKS)
        for (let i = 0; i < privateEncryptionKeys.length; i++) {
          let jws = await this.securityHelper.decryptJWEWithKey(
            personResult,
            privateEncryptionKeys[i]
          );
          if (jws != constant.ERROR_DECRYPT_JWE) {
            logger.debug("Decrypted JWE: ", jws);
            decryptedResponse = jws;
            break;
          }
        }
      } else {
        logger.error("Error: ", constant.ERROR);
        throw constant.ERROR;
      }

      let decodedData;

      if (!decryptedResponse) {
        logger.error("Error: ", constant.ERROR_INVALID_DATA_OR_SIGNATURE);
        throw constant.ERROR_INVALID_DATA_OR_SIGNATURE;
      }

      //verify the signature of the decrypted JWS
      decodedData = await this.securityHelper.verifyJWS(
        decryptedResponse,
        this.CONFIG.MYINFO_JWKS_URL
      );
      // successful. return data back to frontend
      logger.debug(
        "Person Data (JWE Decrypted + JWS Verified): ",
        JSON.stringify(decodedData)
      );

      return decodedData;
    } catch (error) {
      throw error;
    }
  };
}
module.exports = MyInfoConnector;
