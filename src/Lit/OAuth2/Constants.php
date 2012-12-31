<?php

namespace Lit\OAuth2;

/**
 * @package Lito\OAuth2
 * @author lostintime
 */
class Constants
{
    const PARAM_RESPONSE_TYPE = "response_type";
    const PARAM_CLIENT_ID = "client_id";
    const PARAM_CLIENT_SECRET = "client_secret";
    const PARAM_REDIRECT_URI = "redirect_uri";
    const PARAM_SCOPE = "scope";
    const PARAM_STATE = "state";
    const PARAM_USERNAME = "username";
    const PARAM_PASSWORD = "password";

    const PARAM_CODE = "code";

    const PARAM_ASSERTION_TYPE = "assertion_type";
    const PARAM_ASSERTION = "assertion";

    const PARAM_ERROR = "error";
    const PARAM_ERROR_CODE = "error_code"; // not in specs! added by me
    const PARAM_ERROR_DESCRIPTION = "error_description";
    const PARAM_ERROR_URI = "error_uri";

    const PARAM_GRANT_TYPE = "grant_type";
    const PARAM_ACCESS_TOKEN = "access_token";
    const PARAM_TOKEN_TYPE = "token_type";
    const PARAM_EXPIRES_IN = "expires_in";
    const PARAM_REFRESH_TOKEN = "refresh_token";

    const PARAM_TOKEN_NAME = "oauth_token";

    const AUTH_RESPONSE_TYPE_AUTH_CODE = "code";
    const AUTH_RESPONSE_TYPE_TOKEN = "token";
    const AUTH_RESPONSE_TYPE_CODE_AND_TOKEN = "code_and_token";

    const GRANT_TYPE_AUTH_CODE = "authorization_code";
    const GRANT_TYPE_USER_CREDENTIALS = "password";
    const GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
    const GRANT_TYPE_ASSERTION = "assertion";
    const GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
    const GRANT_TYPE_NONE = "none";


    const ERROR_INVALID_REQUEST = "invalid_request"; // 101
    const ERROR_INVALID_CLIENT = "invalid_client"; // 102
    const ERROR_INVALID_GRANT = "invalid_grant"; // 103
    const ERROR_UNAUTHORIZED_CLIENT = "unauthorized_client"; // 104
    const ERROR_UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"; // 105
    const ERROR_INVALID_SCOPE = "invalid_scope"; // 106
    const ERROR_ACCESS_DENIED = "access_denied"; // 107
    const ERROR_UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type"; // 108

    /** @todo add errors numerical codes here **/
    const ERRCODE_INVALID_REQUEST = 101;
    const ERRCODE_INVALID_CLIENT = 102;
    const ERRCODE_INVALID_GRANT = 103;
    const ERRCODE_UNAUTHORIZED_CLIENT = 104;
    const ERRCODE_UNSUPPORTED_GRANT_TYPE = 105;
    const ERRCODE_INVALID_SCOPE = 106;
    const ERRCODE_ACCESS_DENIED = 107;
    const ERRCODE_UNSUPPORTED_RESPONSE_TYPE = 108;

    const ERRCODE_INVALID_CLIENT_ID = 121;
    const ERRCODE_PARAM_CLIENT_ID_REQUIRED = 122;
    const ERRCODE_CLIENT_ID_NOT_FOUND = 123;
    const ERRCODE_PARAM_REDIRECT_URI_REQUIRED = 124;
    const ERRCODE_REDIRECT_URI_MISMATCH = 125;
    const ERRCODE_PARAM_RESPONSE_TYPE_REQUIRED = 126;
    const ERRCODE_UNSUPPORTED_AUTH_GRANT_TYPE = 127;
    const ERRCODE_NOT_ALLOWED_AUTH_RESPONSE_TYPE = 128;
    const ERRCODE_NOT_SUPPORTED_SCOPE = 129;
    const ERRCODE_ACCESS_DENIED_BY_OWNER = 130;
    const ERRCODE_SECURE_CONNECTION_REQUIRED = 131;
    const ERRCODE_PARAM_GRANT_TYPE_REQUIRED = 132;
    const ERRCODE_CLIENT_CREDENTIALS_REQUIRED = 133;
    const ERRCODE_WRONG_CLIENT_CREDENTIALS = 134;
    const ERRCODE_GRANT_TYPE_NOT_ALLOWED_TO_CLIENT = 135;
    const ERRCODE_PARAM_CODE_REQUIRED = 136;
    const ERRCODE_AUTH_CODE_GRANT_NOT_FOUND = 137;
    const ERRCODE_AUTH_CODE_GRANT_EXPIRED = 138;
    const ERRCODE_PARAM_USERNAME_REQUIRED = 139;
    const ERRCODE_PARAM_PASSWORD_REQUIRED = 140;
    const ERRCODE_OWNER_AUTHORIZATION_FAILED = 141;
    const ERRCODE_PARAM_ASSERTION_TYPE_REQUIRED = 142;
    const ERRCODE_PARAM_ASSERTION_REQUIRED = 143;
    const ERRCODE_ASSERTION_AUTHORIZATION_FAILED = 144;
    const ERRCODE_PARAM_REFRESH_TOKEN_REQUIRED = 145;
    const ERRCODE_REFRESH_TOKEN_NOT_FOUND = 146;
    const ERRCODE_REFRESH_TOKEN_CLIENT_ID_MISMATCH = 147;
    const ERRCODE_REFRESH_TOKEN_EXPIRED = 148;
    const ERRCODE_CLIENT_CRED_AUTHORIZATION_FAILED = 149;
    const ERRCODE_AUTH_TOKEN_IN_GETPOST_AND_HEADER = 150;
    const ERRCODE_AUTH_HEADER_DOESNT_START_OAUTH = 151;
    const ERRCODE_MALFORMED_AUTH_HEADER = 152;
    const ERRCODE_AUTH_TOKEN_IN_GET_AND_POST = 153;
    const ERRCODE_ACCESS_TOKEN_NOT_PROVIDED = 154;
    const ERRCODE_ACCESS_TOKEN_NOT_FOUND = 155;
    const ERRCODE_ACCESS_TOKEN_EXPIRED = 156;


    /**
     * @todo move all error messages here, by errcode id
     *      add to Exception constructor initialization for error message using this array
     * @param int $code
     * @static array $errorMessages
     * @return string
     */
    public static function getErrorMessage($code)
    {
        static $errorMessages = null;
        if (!is_array($errorMessages)) {
            $errorMessages = array(
                self::ERRCODE_INVALID_REQUEST => 'invalid request',
                self::ERRCODE_INVALID_CLIENT => 'invalid client',
                self::ERRCODE_INVALID_GRANT => 'invalid grant',
                self::ERRCODE_UNAUTHORIZED_CLIENT => 'unauthorized client',
                self::ERRCODE_UNSUPPORTED_GRANT_TYPE => 'unsupported grant type',
                self::ERRCODE_INVALID_SCOPE => 'invalid scope',
                self::ERRCODE_ACCESS_DENIED => 'access denied',
                self::ERRCODE_UNSUPPORTED_RESPONSE_TYPE => 'unsupported response type',

                self::ERRCODE_INVALID_CLIENT_ID => 'invalid client id',
                self::ERRCODE_PARAM_CLIENT_ID_REQUIRED => self::PARAM_CLIENT_ID . ' parameter required',

                self::ERRCODE_CLIENT_ID_NOT_FOUND => self::PARAM_CLIENT_ID . ' parameter required',
                self::ERRCODE_PARAM_REDIRECT_URI_REQUIRED => self::PARAM_REDIRECT_URI . ' parameter required',
                self::ERRCODE_REDIRECT_URI_MISMATCH => 'redirect uri mismatch',
                self::ERRCODE_PARAM_RESPONSE_TYPE_REQUIRED => self::PARAM_RESPONSE_TYPE . ' parameter required',
                self::ERRCODE_UNSUPPORTED_AUTH_GRANT_TYPE => 'unsupported authorization grant response_type provided',
                self::ERRCODE_NOT_ALLOWED_AUTH_RESPONSE_TYPE => 'failed to authorize client, requested response type not allowed',
                self::ERRCODE_NOT_SUPPORTED_SCOPE => 'requested scope not supported',
                self::ERRCODE_ACCESS_DENIED_BY_OWNER => 'access denied by resource owner',
                self::ERRCODE_SECURE_CONNECTION_REQUIRED => 'secure connection required',
                self::ERRCODE_PARAM_GRANT_TYPE_REQUIRED => self::PARAM_GRANT_TYPE . ' parameter required',
                self::ERRCODE_CLIENT_CREDENTIALS_REQUIRED => 'client credentials required, not provided',
                self::ERRCODE_WRONG_CLIENT_CREDENTIALS => 'failed to authorize client, wrong credentials provided',
                self::ERRCODE_GRANT_TYPE_NOT_ALLOWED_TO_CLIENT => 'failed to authorize client, grant type not allowed',
                self::ERRCODE_PARAM_CODE_REQUIRED => self::PARAM_CODE . ' parameter required',
                self::ERRCODE_AUTH_CODE_GRANT_NOT_FOUND => 'authorization code grant not found',
                self::ERRCODE_AUTH_CODE_GRANT_EXPIRED => 'authorization code grant expired',
                self::ERRCODE_PARAM_USERNAME_REQUIRED => self::PARAM_USERNAME . ' parameter required',
                self::ERRCODE_PARAM_PASSWORD_REQUIRED => self::PARAM_PASSWORD . ' parameter required',
                self::ERRCODE_OWNER_AUTHORIZATION_FAILED => 'failed to authorize resource owner',
                self::ERRCODE_PARAM_ASSERTION_TYPE_REQUIRED => self::PARAM_ASSERTION_TYPE . ' parameter required',
                self::ERRCODE_PARAM_ASSERTION_REQUIRED => self::PARAM_ASSERTION . ' parameter required',
                self::ERRCODE_ASSERTION_AUTHORIZATION_FAILED => 'failed to authorize by assertion',
                self::ERRCODE_PARAM_REFRESH_TOKEN_REQUIRED => self::PARAM_REFRESH_TOKEN . ' parameter required',
                self::ERRCODE_REFRESH_TOKEN_NOT_FOUND => 'refresh token not found',
                self::ERRCODE_REFRESH_TOKEN_CLIENT_ID_MISMATCH => 'refresh token ' . self::PARAM_CLIENT_ID . ' property doesn\'t match request ' . self::PARAM_CLIENT_ID,
                self::ERRCODE_REFRESH_TOKEN_EXPIRED => 'refresh token expired',
                self::ERRCODE_CLIENT_CRED_AUTHORIZATION_FAILED => 'failed to authorize',
                self::ERRCODE_AUTH_TOKEN_IN_GETPOST_AND_HEADER => 'Auth token found in GET or POST when token present in header',
                self::ERRCODE_AUTH_HEADER_DOESNT_START_OAUTH => 'Auth header found that doesn\'t start with "OAuth"',
                self::ERRCODE_MALFORMED_AUTH_HEADER => 'Malformed auth header',
                self::ERRCODE_AUTH_TOKEN_IN_GET_AND_POST => 'Only send the token in GET or POST, not both',
                self::ERRCODE_ACCESS_TOKEN_NOT_PROVIDED => 'access token not found in request',
                self::ERRCODE_ACCESS_TOKEN_NOT_FOUND => 'The access token provided is invalid (not found)',
                self::ERRCODE_ACCESS_TOKEN_EXPIRED => 'The access token provided has expired.',
            );
        }

        return isset($errorMessages[$code]) ? $errorMessages[$code] : 'unknown error';
    }

}
