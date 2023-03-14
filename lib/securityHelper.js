//import statements
var log4js = require('log4js');
var logger = log4js.getLogger('MyInfoNodeJSConnector');
const requestHandler = require('./requestHandler');

const crypto = require('crypto');
const constant = require('../common/constant');
const jose = require('node-jose');
const srs = require('secure-random-string');
const Ajv = require("ajv")
/**
 * Verify JWS
 *
 * This method takes in a JSON Web Signature and will check against
 * the public key for its validity and to retrieve the decoded data.
 * This verification is required for the decoding of the access token and
 * response from Person API
 *
 * @param {string} compactJWS - Data in JWS compact serialization Format
 * @param {string} jwksUrl - The URL of the JWKS Endpoint to retrieve the public cert
 * @returns {Promise} - Promise that resolves decoded data
 */

module.exports.verifyJWS = async (compactJWS, jwksUrl) => {
  let jwks = await getJwks(jwksUrl);
  try {
    let keyStore = await jose.JWK.asKeyStore(jwks);
    let result = await jose.JWS.createVerify(keyStore).verify(compactJWS);
    let payload = JSON.parse(Buffer.from(result.payload).toString());

    return payload;
  } catch (error) {
    console.error('Error with verifying JWS:', error);
    throw constant.ERROR_VERIFY_JWS;
  }
};

/**
 * Decyption JWE
 *
 * This method takes in a JSON Web Encrypted object and will decrypt it using the
 * private key. This is required to decrypt the data from Person API
 *
 * @param {string} compactJWE - Data in compact serialization format - header.encryptedKey.iv.ciphertext.tag
 * @param {string} decryptionPrivateKey - Private Key used to decrypt JWE in .pem format
 * @returns {Promise} - Promise that resolve decrypted data
 */

module.exports.decryptJWEWithKey = async (compactJWE, decryptionPrivateKey) => {
  try {
    let keystore = jose.JWK.createKeyStore();
    let jweParts = compactJWE.split('.'); // header.encryptedKey.iv.ciphertext.tag
    if (jweParts.length != 5) {
      throw constant.ERROR_INVALID_DATA_OR_SIGNATURE;
    }

    //Session encryption private key should correspond to the session encryption public key passed in to client assertion
    let key = await keystore.add(decryptionPrivateKey, 'pem');

    let data = {
      type: 'compact',
      protected: jweParts[0],
      encrypted_key: jweParts[1],
      iv: jweParts[2],
      ciphertext: jweParts[3],
      tag: jweParts[4],
      header: JSON.parse(jose.util.base64url.decode(jweParts[0]).toString()),
    };

    let result = await jose.JWE.createDecrypt(key).decrypt(data);

    return result.payload.toString();
  } catch (error) {
    return constant.ERROR_DECRYPT_JWE;
  }
};

/**
 * Generate Key Pair
 *
 * This method will generate a keypair which consists of an eliptic curve public key and a private key in PEM format.
 *
 * @returns {Object} - Returns an object which consists of a public key and a private key
 */

module.exports.generateSessionKeyPair = async () => {
  let options = {
    namedCurve: 'P-256',
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'sec1',
      format: 'pem',
    },
  };

  let sessionKeyPair = crypto.generateKeyPairSync('ec', options);

  return sessionKeyPair;
};

/**
 * Generate Client Assertion
 *
 * This method will generate the client assertion which is needed as one of the query parameters when calling Token API
 *
 * @param {string} url - The URL of the audience that clientAssertion is for (/token API)
 * @param {string} clientId - Client id provided during onboarding
 * @param {string} privateSigningKey - Your application private signing key in .pem format
 * @param {string} jktThumbprint - JWK Thumbprint - base64url encoding of the JWK SHA-256 Thumbprint of the client's ephemeral public signing key used to sign the DPoP Proof JWT
 * @param {string} [kid=sha256 of JWK used to sign]  kid that will be used in JWT header
 * @returns {string} - Returns the client assertion
 */

module.exports.generateClientAssertion = async (url, clientId, privateSigningKey, jktThumbprint, kid) => {
  try {
    let now = Math.floor(Date.now() / 1000); // get the time of creation in unix

    let payload = {
      sub: clientId,
      jti: generateRandomString(40), // generate unique randomstring on every client_assertion for jti
      aud: url,
      iss: clientId,
      iat: now,
      exp: now + 300, // expiry of client_assertion set to 5mins max
      cnf: {
        jkt: jktThumbprint, //jkt thumbprint should match DPoP JWK used in the same request
      },
    };
    let jwsKey = await jose.JWK.asKey(privateSigningKey, 'pem');
    let jwtToken;
    if (kid) {
      // use custom kid to match public key in JWKS
      jwtToken = await jose.JWS.createSign({ format: 'compact', fields: { typ: 'JWT', kid: kid } }, jwsKey)
        .update(JSON.stringify(payload))
        .final();
    } else {
      //default use SHA256 of JWK used to sign as the kid
      jwtToken = await jose.JWS.createSign({ format: 'compact', fields: { typ: 'JWT' } }, jwsKey)
        .update(JSON.stringify(payload))
        .final();
    }
    logger.info('encoded client_assertion: ', jwtToken);
    return jwtToken;
  } catch (error) {
    throw constant.ERROR_GENERATE_CLIENT_ASSERTION;
  }
};

/**
 * Generate DPoP Token
 *
 * This method generates the DPoP Token which will be used when calling /token and /person API.
 *
 * @param {string} url - The URL of the audience that DPoP is for (/token API or /person API)
 * @param {string} [ath] - Access token hash (Payload) - The base64url encoded SHA-256 hash of the ASCII encoding of the associated access token's value (Required only for /person call after DPoP-bound access token is issued)
 * @param {string} method - The HTTP method used - e.g ('POST' for /token, 'GET' for /person)
 * @param {Object} sessionEphemeralKeyPair - Session ephemeral key pair used for signing DPoP
 * @returns {string} - Returns the DPoP Token
 */

module.exports.generateDpop = async (url, ath, method, sessionEphemeralKeyPair) => {
  try {
    let now = Math.floor(Date.now() / 1000); // get the time of creation in unix
    let payload = {
      htu: url,
      htm: method,
      jti: generateRandomString(40), // generate unique randomstring on every client_assertion for jti
      iat: now,
      exp: now + 120, // expiry of client_assertion set to 2mins max
    };
    if (ath) payload.ath = ath; //append ath if passed in (Required for /person call)

    let privateKey = await jose.JWK.asKey(sessionEphemeralKeyPair.privateKey, 'pem');
    let jwk = (await jose.JWK.asKey(sessionEphemeralKeyPair.publicKey, 'pem')).toJSON(true);
    jwk.use = 'sig';
    jwk.alg = 'ES256';
    let jwtToken = await jose.JWS.createSign({ format: 'compact', fields: { typ: 'dpop+jwt', jwk: jwk } }, { key: privateKey, reference: false })
      .update(JSON.stringify(payload))
      .final();
    logger.info('encoded DPoP: ', jwtToken);
    return jwtToken;
  } catch (error) {
    logger.error('generateDpop error', error);
    throw constant.ERROR_GENERATE_DPOP;
  }
};

/**
 * Base64 Encode
 *
 * This function encodes a string into Base64 URL format.
 *
 * @param {string} str - The string to be encoded in Base64 URL format
 * @returns {string} - Returns a string in Base64 URL format.
 */
module.exports.base64URLEncode = (str) => {
  return str.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

/**
 * SHA256 Hash
 *
 * This function hashes a string with the SHA256 algorithm.
 *
 * @param {string} buffer - The string to be hashed
 * @returns {string} - Returns a SHA256 hashed string
 */
module.exports.sha256 = (buffer) => {
  return crypto.createHash('sha256').update(buffer).digest();
};

/**
 * generateRandomString
 *
 * Generate an alphanumeric random string of specified length
 *
 * @param {int} length - length of alphanumeric random string
 * @returns {string} - Returns a random string
 */
module.exports.generateRandomString = generateRandomString;

/**
 * generateJwkThumbprint
 *
 * Generates base64url encoding of the JWK SHA-256 Thumbprint, can be used to generate cnf.jkt in client_assertion
 *
 * @param {object} jwk - JWK to generate the thumbprint from in pem form
 * @returns {string} - Returns the JWK thumbprint
 */
module.exports.generateJwkThumbprint = async (jwk) => {
  let jwkKey = await jose.JWK.asKey(jwk, 'pem'); //convert pem to jwk
  let jwkThumbprintBuffer = await jwkKey.thumbprint('SHA-256'); // sha256 has of the jwk object
  let jwkThumbprint = jose.util.base64url.encode(jwkThumbprintBuffer, 'utf8'); // base64 urlencode of the hash

  return jwkThumbprint;
};

function generateRandomString(length) {
  return srs({ alphanumeric: true, length: length ? length : 40 });
}

async function getJwks(jwksUrl) {
  var response = await requestHandler.getHttpsResponse('GET', jwksUrl, null, null, null);
  return response.data.keys;
}

/**
 * validateSchema
 * 
 * Function to validateSchema 
 * 
 * @param {Object} payload - payload to be validated
 * @param {Object} schema - schema to validate against
 * @param {Object} options 
 * @returns 
 */
module.exports.validateSchema = function (payload, schema, options = {}) {
    console.log("Validating Json Schema...");

    let ajv = new Ajv(options);
    let validate = ajv.compile(schema);
    let valid = validate(payload);
    if (!valid) {
      console.log("Json Schema Validation: ", validate.errors);
      throw validate.errors;
    } else {
      return valid;
    }
};