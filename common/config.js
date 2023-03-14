let schema = {
    "type": "object",
    "additionalProperties": true,
    "properties": {
        "CLIENT_ID": {
            "type": "string",
        },
        "SUBENTITY_ID": {
            "type": "string",
        },
        "REDIRECT_URL": {
            "type": "string",
            "pattern": "^.[^<>]*$"
        },
        "SCOPE": {
            "type": "string"
        },
        "AUTHORIZE_JWKS_URL": {
            "type": "string",
            "pattern": "^.[^<>]*$"
        },
        "MYINFO_JWKS_URL": {
            "type": "string",
            "pattern": "^.[^<>]*$"
        },
        "TOKEN_URL": {
            "type": "string",
            "pattern": "^.[^<>]*$"
        },
        "PERSON_URL": {
            "type": "string",
            "pattern": "^.[^<>]*$"
        },
        "CLIENT_ASSERTION_SIGNING_KID": {
            "type": "string"
        },
        "USE_PROXY": {
            "type": "string"
        },
        "PROXY_TOKEN_URL": {
            "type": "string"
        },
        "PROXY_PERSON_URL": {
            "type": "string"
        },
        "DEBUG_LEVEL": {
            "type": "string"
        }
    },
    "required": ["CLIENT_ID", "REDIRECT_URL", "SCOPE", "AUTHORIZE_JWKS_URL", "MYINFO_JWKS_URL","TOKEN_URL", "PERSON_URL", "DEBUG_LEVEL"]
}


module.exports = schema;

