const ERROR = "Error";
const OK = "OK";
const ERROR_INVALID_TOKEN = "Invalid token";
const ERROR_UINFIN_NOT_FOUND = "Uinfin not found";
const ERROR_PERSON_DATA_NOT_FOUND = "Person data not found";
const ERROR_INVALID_DATA_OR_SIGNATURE = "Invalid data or signature for person data";
const ERROR_GENERATE_CLIENT_ASSERTION = "Error generating client assertion";
const ERROR_GENERATE_DPOP = "Error generating dpop token";
const ERROR_VERIFY_JWS = "Error with verifying JWS";
const ERROR_DECRYPT_JWE = "Error with decrypting JWE";

const ENVIRONMENT = {
    TEST: "TEST",
    PROD: "PROD"
};

const HTTP_METHOD = {
    GET: "GET",
    POST: "POST"
};

module.exports = {
    ERROR: ERROR,
    OK: OK,
    ENVIRONMENT: ENVIRONMENT,
    HTTP_METHOD: HTTP_METHOD,
    ERROR_INVALID_TOKEN: ERROR_INVALID_TOKEN,
    ERROR_UINFIN_NOT_FOUND: ERROR_UINFIN_NOT_FOUND,
    ERROR_PERSON_DATA_NOT_FOUND: ERROR_PERSON_DATA_NOT_FOUND,
    ERROR_INVALID_DATA_OR_SIGNATURE: ERROR_INVALID_DATA_OR_SIGNATURE,
    ERROR_GENERATE_CLIENT_ASSERTION,
    ERROR_GENERATE_DPOP,
    ERROR_VERIFY_JWS,
    ERROR_DECRYPT_JWE
};