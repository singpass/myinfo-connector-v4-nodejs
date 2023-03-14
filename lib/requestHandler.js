const https = require('https');
const CONFIG = require('../common/config');
var log4js = require('log4js');
var logger = log4js.getLogger('MyInfoNodeJSConnector');
logger.level = CONFIG.DEBUG_LEVEL;
const axios = require('axios'); // https://www.npmjs.com/package/axios
const querystring = require('node:querystring');

exports.getHttpsResponse = function (method, url, headers = {}, body = {}, timeout = 30000) {
    /* 
      < Using application/x-www-form-urlencoded format >
      By default, axios serializes JavaScript objects to JSON. To send data in the application/x-www-form-urlencoded format instead, you need to encode data using the qs library
    */
    var bodyStringify;
    if ((typeof body == "object") && (headers && headers["content-type"] == "application/x-www-form-urlencoded")) {
      // If user pass in Object(JSON) & header is www-form-urlencoded, then convert the body to string
      bodyStringify = querystring.stringify(body);
    }
        
    const agent = new https.Agent();
    // < Request Config > https://www.npmjs.com/package/axios#request-config
    var config = {
      method: method.toUpperCase(),
      url: url,
      headers: headers,
      data: (bodyStringify ? bodyStringify : body), // Only applicable for request methods 'PUT', 'POST', and 'PATCH'
      timeout: timeout, // default is `0` (no timeout). Example, the request will wait 30 seconds (30000) before timing out
      responseType: 'json', // `responseType` indicates the type of data that the server will respond with 'arraybuffer', 'document', 'json', 'text', 'stream'
      responseEncoding: "utf8", // `responseEncoding` indicates encoding to use for decoding responses. Note: Ignored for `responseType` of 'stream' or client-side requests
      agent: agent
    };
       
    return axios(config)
      .then(function (response) {
        if (true) {
            delete response.headers;
            delete response.config;
            delete response.statusText;
            delete response.request;
          }
          if(response.status ==200 || response.status == 201){
            return response;
          }else{
            throw response
          }
      }).catch(error => {
        if (error.response) {
          // (Server response error) The request was made and the server responded with a status code that falls out of the range of 2xx (e.g. 4XX or 5XX)
          logger.info("Axios Error Msg (Server Response with Error):", error.message);
          throw {
            status: error.response.status,
            data: error.response.data
          };
        } else if (error.request) {
          // (Timeout) The request was made but no response was received. `error.request` is an instance of XMLHttpRequest in the browser and an instance of http.ClientRequest in node.js
          logger.info("Axios Error Msg (Timeout):", error.message);
          throw {
            status: 500,
            data: "Internal server error."
          };
        } else {
          // (Internal error) Something happened in setting up the request that triggered an Error
          logger.info("Axios Error Msg (Internal Error):", error.message);
          throw {
            status: 500,
            data: "Internal server error."
          };
        }
      });
  };