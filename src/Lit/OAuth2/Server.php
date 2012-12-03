<?php

namespace Lit\OAuth2;

/**
 * @package Lito\OAuth2
 * @author lostintime
 * @todo add token_type support http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-7.1
 */
abstract class Server
{

    /**
     * @static
     * @final
     * @param Request $request
     * @throws Exception
     * @return AuthorizationGrantResponse
     */
    final public function initAuthorization(Request $request)
    {
        $response = new AuthorizationGrantResponse();

        /**
         * @var string
         */
        $redirectUri = \filter_var($request[Constants::PARAM_REDIRECT_URI], \FILTER_SANITIZE_URL);

        /**
         * @var ErrorResponse
         */
        $errorResponse = null;

        try {
            // Make sure a valid client id was supplied
            if (!$request[Constants::PARAM_CLIENT_ID])
                throw new Exception(Constants::ERROR_INVALID_REQUEST, Constants::ERRCODE_PARAM_CLIENT_ID_REQUIRED);

            // redirect_uri is not required if already established via other channels
            // check an existing redirect URI against the one supplied
            $clientCredentials = $this->checkClientCredentials($request[Constants::PARAM_CLIENT_ID]);

            if (!$clientCredentials instanceof ClientCredentials)
                throw new Exception(Constants::ERROR_INVALID_REQUEST, Constants::ERRCODE_CLIENT_ID_NOT_FOUND);

            $storedRedirectUri = $clientCredentials->getRedirectUri();

            // At least one of: existing redirect URI or input redirect URI must be specified
            if (!$storedRedirectUri && !$redirectUri)
                throw new Exception(Constants::ERROR_INVALID_REQUEST, Constants::ERRCODE_PARAM_REDIRECT_URI_REQUIRED);

            // If there's an existing uri and one from input, verify that they match
            if ($redirectUri && $storedRedirectUri) {
                // Ensure that the input uri starts with the stored uri
                if (!$clientCredentials->checkRedirectUri($redirectUri))
                    throw new Exception(Constants::ERROR_INVALID_REQUEST, Constants::ERRCODE_REDIRECT_URI_MISMATCH);
            }
            elseif ($storedRedirectUri) { // They did not provide a uri from input, so use the stored one
                $redirectUri = $storedRedirectUri;
            }

            // type and client_id are required
            if (!$request[Constants::PARAM_RESPONSE_TYPE])
                throw new Exception(Constants::ERROR_INVALID_REQUEST, Constants::ERRCODE_PARAM_RESPONSE_TYPE_REQUIRED);

            // Check requested auth response type against the list of supported types
            if (false === array_search($request[Constants::PARAM_RESPONSE_TYPE], $this->getSupportedAuthResponseTypes()))
                throw new Exception(Constants::ERROR_UNSUPPORTED_RESPONSE_TYPE, Constants::ERRCODE_UNSUPPORTED_AUTH_GRANT_TYPE);

            // Restrict clients to certain authorization response types
            if (!$this->checkRestrictedAuthResponseType($request[Constants::PARAM_CLIENT_ID], $request[Constants::PARAM_RESPONSE_TYPE]))
                throw new Exception(Constants::ERROR_UNAUTHORIZED_CLIENT, Constants::ERRCODE_NOT_ALLOWED_AUTH_RESPONSE_TYPE);

            // Validate that the requested scope is supported
            $scope = isset($request[Constants::PARAM_SCOPE]) ? new Scope($request[Constants::PARAM_SCOPE]) : null;

            if ($scope && (!($this->getSupportedScopes() instanceof Scope) || !$this->getSupportedScopes()->contains($scope)))
                throw new Exception(Constants::ERROR_INVALID_SCOPE, Constants::ERRCODE_NOT_SUPPORTED_SCOPE);

            /** init params array * */
            // required parameters
            $response[Constants::PARAM_RESPONSE_TYPE] = $request[Constants::PARAM_RESPONSE_TYPE];
            $response[Constants::PARAM_CLIENT_ID] = $request[Constants::PARAM_CLIENT_ID];
            $response[Constants::PARAM_REDIRECT_URI] = $request[Constants::PARAM_REDIRECT_URI];

            // optional parameters
            $response[Constants::PARAM_SCOPE] = $scope;

            if (isset($request[Constants::PARAM_STATE]))
                $response[Constants::PARAM_STATE] = $request[Constants::PARAM_STATE];
        } catch (Exception $exc) {
            $errorResponse = new ErrorResponse($exc->getCodeName(), $exc->getCode(), $exc->getMessage(), $exc->getUri(),
                $request->get(Constants::PARAM_STATE));
        } catch (\Exception $exc) {
            $errorResponse = new ErrorResponse(Constants::ERROR_INVALID_REQUEST, 0, 'system error: ' . $exc->getMessage(),
                null, $request->get(Constants::PARAM_STATE));
        }

        // handle error response
        if ($errorResponse) {
            if ($redirectUri) {
                $this->sendHttpQueryResponse($redirectUri, $errorResponse);
            } else {
                $this->sendJsonResponse($errorResponse);
            }
        }

        return $response;
    }

    /**
     * OAuth2 Authorization endpoint implementation
     * @static
     * @final
     * @param boolean $authorized
     * @param Request $request
     * @param ResourceOwnerCredentials|null $resourceOwnerCredentials
     * @throws Exception
     */
    final public function grantAuthorization($authorized, Request $request, ResourceOwnerCredentials $resourceOwnerCredentials = null)
    {
        $response = new AuthorizationGrantResponse();
        $redirectUri = null;
        try {

            // initialize authorization
            $request = $this->initAuthorization($request);

            $redirectUri = $request[Constants::PARAM_REDIRECT_URI];
            $responseType = $request[Constants::PARAM_RESPONSE_TYPE];
            $clientId = $request[Constants::PARAM_CLIENT_ID];
            $scope = $request[Constants::PARAM_SCOPE];

            if (!$authorized) {
                throw new Exception(Constants::ERROR_ACCESS_DENIED, Constants::ERRCODE_ACCESS_DENIED_BY_OWNER);
            }

            if ($responseType == Constants::AUTH_RESPONSE_TYPE_AUTH_CODE
                || $responseType == Constants::AUTH_RESPONSE_TYPE_CODE_AND_TOKEN
            ) {
                $authorizationCode = $this->createAuthorizationCode($clientId, $redirectUri, $scope, $resourceOwnerCredentials);
                $response[Constants::PARAM_CODE] = $authorizationCode->getToken();
            }

            if ($responseType == Constants::AUTH_RESPONSE_TYPE_TOKEN
                || $responseType == Constants::AUTH_RESPONSE_TYPE_CODE_AND_TOKEN
            ) {
                $accessToken = $this->createAccessToken($clientId, $scope, $resourceOwnerCredentials);
                $response[Constants::PARAM_ACCESS_TOKEN] = $accessToken->getToken();
                $response[Constants::PARAM_EXPIRES_IN] = $accessToken->getExpiresIn();
            }

            if ($scope instanceof Scope)
                $response[Constants::PARAM_SCOPE] = (string)$scope;

            if (isset($request[Constants::PARAM_STATE]))
                $response[Constants::PARAM_STATE] = $request[Constants::PARAM_STATE];
        } catch (Exception $exc) {
            $response = new ErrorResponse($exc->getCodeName(), $exc->getCode(), $exc->getMessage(), $exc->getUri(),
                $request->get(Constants::PARAM_STATE));
        } catch (\Exception $exc) {
            $response = new ErrorResponse(Constants::ERROR_INVALID_REQUEST, 0, 'system error (' . $exc->getMessage() . ')',
                null, $request->get(Constants::PARAM_STATE));
        }

        // send response to redirectUri if provided or fetch as json
        if ($redirectUri) {
            $this->sendHttpQueryResponse($redirectUri, $response);
        } else {
            $this->sendJsonResponse($response);
        }
    }

    /**
     * OAuth2 Access Token endpoint implementation
     * @static
     * @final
     * @param Request $request
     * @param boolean $isSecure
     *      used to check if connection is secured (TLS required by specification)
     * @throws Exception
     * @return boolean
     */
    final public function grantAccessToken(Request $request, $isSecure = false)
    {
        try {
            // check if connection is secure
            if (!$isSecure)
                throw new Exception(Constants::ERROR_INVALID_REQUEST, Constants::ERRCODE_SECURE_CONNECTION_REQUIRED);

            // check grant type
            $grantType = $request[Constants::PARAM_GRANT_TYPE];
            if (!$grantType)
                throw new Exception(Constants::ERROR_INVALID_REQUEST, Constants::ERRCODE_PARAM_GRANT_TYPE_REQUIRED);

            // check grant type supported
            $supportedGrantTypes = $this->getSupportedGrantTypes();
            if (!\in_array($grantType, $supportedGrantTypes))
                throw new Exception(Constants::ERROR_UNSUPPORTED_GRANT_TYPE, Constants::ERRCODE_UNSUPPORTED_GRANT_TYPE);

            // init client credentials
            $requestClientCredentials = $this->getRequestClientCredentials();
            if (!$requestClientCredentials)
                throw new Exception(Constants::ERROR_INVALID_CLIENT, Constants::ERRCODE_CLIENT_CREDENTIALS_REQUIRED);

            // try to find client credentials by id [and secret]
            $clientCredentials = $this->checkClientCredentials($requestClientCredentials[Constants::PARAM_CLIENT_ID], $requestClientCredentials[Constants::PARAM_CLIENT_SECRET]);

            $resourceOwnerCredentials = null;

            // check client found
            if (!$clientCredentials instanceof ClientCredentials)
                throw new Exception(Constants::ERROR_UNAUTHORIZED_CLIENT, Constants::ERRCODE_WRONG_CLIENT_CREDENTIALS);

            if (!$this->checkClientGrantTypeSupport($clientCredentials->getId(), $grantType))
                throw new Exception(Constants::ERROR_UNAUTHORIZED_CLIENT, Constants::ERRCODE_GRANT_TYPE_NOT_ALLOWED_TO_CLIENT);

            /**
             * @var RefreshToken
             */
            $refreshToken = null;

            /**
             * @var Scope
             */
            $requestedScope = isset($request[Constants::PARAM_SCOPE]) ? new Scope($request[Constants::PARAM_SCOPE]) : null;

            /**
             * @var Scope
             */
            $allowedScope = null;

            switch ($grantType) {
                case Constants::GRANT_TYPE_AUTH_CODE:
                    if (!$request[Constants::PARAM_CODE])
                        throw new Exception(Constants::ERROR_INVALID_REQUEST, Constants::ERRCODE_PARAM_CODE_REQUIRED);

                    if (!$request[Constants::PARAM_REDIRECT_URI])
                        throw new Exception(Constants::ERROR_INVALID_REQUEST, Constants::ERRCODE_PARAM_REDIRECT_URI_REQUIRED);

                    /**
                     * @var AuthorizationCode
                     */
                    $authorizationCode = $this->findAuthorizationCode($request[Constants::PARAM_CODE]);

                    if (!$authorizationCode instanceof AuthorizationCode)
                        throw new Exception(Constants::ERROR_INVALID_GRANT, Constants::ERRCODE_AUTH_CODE_GRANT_NOT_FOUND);

                    if ($authorizationCode->expired())
                        throw new Exception(Constants::ERROR_INVALID_GRANT, Constants::ERRCODE_AUTH_CODE_GRANT_EXPIRED);

                    $allowedScope = $authorizationCode->getScope();
                    if ($authorizationCode->getResourceOwnerCredentials() instanceof ResourceOwnerCredentials) {
                        $resourceOwnerCredentials = $authorizationCode->getResourceOwnerCredentials();
                    }

                    $this->removeAuthorizationCode($authorizationCode->getToken());

                    break;
                case Constants::GRANT_TYPE_USER_CREDENTIALS:
                    if (!$request[Constants::PARAM_USERNAME])
                        throw new Exception(Constants::ERROR_INVALID_REQUEST, Constants::ERRCODE_PARAM_USERNAME_REQUIRED);

                    if (!$request[Constants::PARAM_PASSWORD])
                        throw new Exception(Constants::ERROR_INVALID_REQUEST, Constants::ERRCODE_PARAM_PASSWORD_REQUIRED);

                    $r = $this->checkResourceOwnerCredentials($clientCredentials->getId(), $request[Constants::PARAM_USERNAME], $request[Constants::PARAM_PASSWORD]);

                    if ($r instanceof ResourceOwnerCredentials) {
                        $resourceOwnerCredentials = $r;
                        if ($r->getAllowedScope() instanceof Scope)
                            $allowedScope = $r->getAllowedScope();
                    } else if (!$r) {
                        throw new Exception(Constants::ERROR_INVALID_GRANT, Constants::ERRCODE_OWNER_AUTHORIZATION_FAILED);
                    }

                    break;
                case Constants::GRANT_TYPE_ASSERTION:
                    if (!$request[Constants::PARAM_ASSERTION_TYPE])
                        throw new Exception(Constants::ERROR_INVALID_REQUEST, Constants::ERRCODE_PARAM_ASSERTION_TYPE_REQUIRED);

                    if (!$request[Constants::PARAM_ASSERTION])
                        throw new Exception(Constants::ERROR_INVALID_REQUEST, Constants::ERRCODE_PARAM_ASSERTION_REQUIRED);

                    $r = $this->checkAssertion($clientCredentials->getId(), $request[Constants::PARAM_ASSERTION_TYPE], $request[Constants::PARAM_ASSERTION]);

                    if ($r instanceof Scope)
                        $allowedScope = $r;
                    else if (!$r)
                        throw new Exception(Constants::ERROR_INVALID_GRANT, Constants::ERRCODE_ASSERTION_AUTHORIZATION_FAILED);

                    break;
                case Constants::GRANT_TYPE_REFRESH_TOKEN:
                    if (!$request[Constants::PARAM_REFRESH_TOKEN])
                        throw new Exception(Constants::ERROR_INVALID_REQUEST, Constants::ERRCODE_PARAM_REFRESH_TOKEN_REQUIRED);

                    /**
                     * @var RefreshToken
                     */
                    $refreshToken = $this->findRefreshToken($request[Constants::PARAM_REFRESH_TOKEN]);

                    if (!$refreshToken instanceof RefreshToken)
                        throw new Exception(Constants::ERROR_INVALID_GRANT, Constants::ERRCODE_REFRESH_TOKEN_NOT_FOUND);

                    if ($refreshToken->getClientId() != $clientCredentials->getId())
                        throw new Exception(Constants::ERROR_INVALID_GRANT, Constants::ERRCODE_REFRESH_TOKEN_CLIENT_ID_MISMATCH);

                    if ($refreshToken->expired())
                        throw new Exception(Constants::ERROR_INVALID_GRANT, Constants::ERRCODE_REFRESH_TOKEN_EXPIRED);

                    // init scope for gen
                    $allowedScope = $refreshToken->getScope();

                    $this->removeRefreshToken($refreshToken->getToken());

                    // set refresh token to null to ensure generation of new refresh token
                    $refreshToken = null;

                    break;
                case Constants::GRANT_TYPE_CLIENT_CREDENTIALS:
                case Constants::GRANT_TYPE_NONE:
                    $r = $this->checkNoneAccess($clientCredentials->getId());

                    if ($r instanceof Scope)
                        $allowedScope = $r;
                    else if (!$r)
                        throw new Exception(Constants::ERROR_INVALID_GRANT, Constants::ERRCODE_CLIENT_CRED_AUTHORIZATION_FAILED);

                    break;
                default:
                    throw new Exception(Constants::ERROR_UNSUPPORTED_GRANT_TYPE, Constants::ERRCODE_UNSUPPORTED_GRANT_TYPE);
                    break;
            }

            // check requested scope
            if ($requestedScope instanceof Scope
                && (!($allowedScope instanceof Scope) || !$allowedScope->contains($requestedScope))
            )
                throw new Exception(Constants::ERROR_INVALID_SCOPE, Constants::ERRCODE_NOT_SUPPORTED_SCOPE);

            $accessTokenScope = $requestedScope ? $requestedScope : ($allowedScope ? $allowedScope : null);

            $accessToken = $this->createAccessToken($clientCredentials->getId(), $accessTokenScope, $resourceOwnerCredentials);

            // check if refresh token grant type server support and client access rights and it not set before
            if (in_array(Constants::GRANT_TYPE_REFRESH_TOKEN, $this->getSupportedGrantTypes())
                && $this->checkClientGrantTypeSupport($accessToken->getClientId(), Constants::GRANT_TYPE_REFRESH_TOKEN)
                && !$refreshToken instanceof RefreshToken
            ) {
                $refreshToken = $this->createRefreshToken($accessToken, $request);
            }

            $response = new AccessTokenResponse($accessToken, $refreshToken);
        } catch (Exception $exc) {
            $response = new ErrorResponse($exc->getCodeName(), $exc->getCode(), $exc->getMessage(), $exc->getUri(), $request->get(Constants::PARAM_STATE));
        } catch (\Exception $exc) {
            $response = new ErrorResponse(Constants::ERROR_INVALID_REQUEST, 0, 'system error (' . $exc->getMessage() . ')');
        }

        return $this->sendJsonResponse($response);
    }

    /**
     * check's request (header/get/post) for access token
     * @throws Exception
     * @return AccessToken
     */
    public function verifyAccessToken()
    {
        $token_param = $this->getAccessTokenParams();

        if ($token_param === false) // Access token was not provided
            throw new Exception(Constants::ERROR_INVALID_REQUEST, Constants::ERRCODE_ACCESS_TOKEN_NOT_PROVIDED);

        // Get the stored token data (from the implementing subclass)
        $token = $this->findAccessToken($token_param);

        if (!$token instanceof AccessToken)
            throw new Exception(Constants::ERROR_INVALID_GRANT, Constants::ERRCODE_ACCESS_TOKEN_NOT_FOUND);

        if ($token->expired())
            throw new Exception(Constants::ERROR_INVALID_GRANT, Constants::ERRCODE_ACCESS_TOKEN_EXPIRED);

        return $token;
    }

    /**
     * extracts and checks ClientCredentials from request
     * @throws Exception
     * @return array
     */
    protected function getRequestClientCredentials()
    {
        $requestClientCredentials = $this->extractClientCredentials();
        if (!is_array($requestClientCredentials))
            throw new Exception(Constants::ERROR_INVALID_CLIENT, Constants::ERRCODE_CLIENT_CREDENTIALS_REQUIRED);

        return $requestClientCredentials;
    }

    /**
     * extracts client credentials from request
     * @return ClientCredentials
     */
    protected function extractClientCredentials()
    {
        if (isset($_SERVER["PHP_AUTH_USER"]) &&
            (($_POST && isset($_POST[Constants::PARAM_CLIENT_ID]))
                || ($_GET && isset($_GET[Constants::PARAM_CLIENT_ID])))
        )
            return false;

        // Try basic auth
        if (isset($_SERVER["PHP_AUTH_USER"]))
            return array(Constants::PARAM_CLIENT_ID => $_SERVER["PHP_AUTH_USER"], Constants::PARAM_CLIENT_SECRET => $_SERVER["PHP_AUTH_PW"]);

        // Try POST
        if ($_POST && isset($_POST[Constants::PARAM_CLIENT_ID])) {
            if (isset($_POST[Constants::PARAM_CLIENT_SECRET]))
                return array(Constants::PARAM_CLIENT_ID => $_POST[Constants::PARAM_CLIENT_ID], Constants::PARAM_CLIENT_SECRET => $_POST[Constants::PARAM_CLIENT_SECRET]);

            return array(Constants::PARAM_CLIENT_ID => $_POST[Constants::PARAM_CLIENT_ID], Constants::PARAM_CLIENT_SECRET => null);
        }

        // Try GET
        if ($_GET && isset($_GET[Constants::PARAM_CLIENT_ID])) {
            if (isset($_GET[Constants::PARAM_CLIENT_SECRET]))
                return array(Constants::PARAM_CLIENT_ID => $_GET[Constants::PARAM_CLIENT_ID], Constants::PARAM_CLIENT_SECRET => $_GET[Constants::PARAM_CLIENT_SECRET]);

            return array(Constants::PARAM_CLIENT_ID => $_GET[Constants::PARAM_CLIENT_ID], Constants::PARAM_CLIENT_SECRET => null);
        }

        return false;
    }

    /**
     * sends http request by redirection
     * @param string $uri
     * @param Response $response
     */
    protected function sendHttpQueryResponse($uri, Response $response)
    {
        $url = $uri . (false !== \strpos($uri, '?') ? '' : '?') . $response->toHttpQuery();
        header('Location: ' . $url);
        exit;
    }

    /**
     * sends response in json format
     * @param Response $response
     */
    protected function sendJsonResponse(Response $response)
    {
        header('Content-Type: application/json');
        header('Cache-Control: no-store');
        echo $response->toJson();
        exit;
    }

    /**
     * returns supported auth types
     *   override this method if want to restrict some types
     * @return array
     */
    protected function getSupportedAuthResponseTypes()
    {
        return array(
            Constants::AUTH_RESPONSE_TYPE_AUTH_CODE,
            Constants::AUTH_RESPONSE_TYPE_TOKEN,
            Constants::AUTH_RESPONSE_TYPE_CODE_AND_TOKEN,
        );
    }

    /**
     * Extracts Authorization HTTP header and return it
     *
     * @return bool
     *   The Authorization HTTP header, and FALSE if does not exist.
     */
    private function getAuthorizationHeader()
    {
        if (array_key_exists("HTTP_AUTHORIZATION", $_SERVER))
            return $_SERVER["HTTP_AUTHORIZATION"];

        if (function_exists("apache_request_headers")) {
            $headers = apache_request_headers();

            if (array_key_exists("Authorization", $headers))
                return $headers["Authorization"];
        }

        return false;
    }

    /**
     * Extracts the access token out of the HTTP request.
     *  http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-7.1
     *
     * @throws Exception
     * @return bool
     *   Access token value if present, and FALSE if it isn't.
     */
    private function getAccessTokenParams()
    {
        $auth_header = $this->getAuthorizationHeader();

        if ($auth_header !== false) {
            // Make sure only the auth header is set
            if (isset($_GET[Constants::PARAM_TOKEN_NAME]) || isset($_POST[Constants::PARAM_ACCESS_TOKEN]))
                throw new Exception(Constants::ERROR_INVALID_REQUEST, Constants::ERRCODE_AUTH_TOKEN_IN_GETPOST_AND_HEADER);

            $auth_header = trim($auth_header);

            // Make sure it's Token authorization
            if (strcmp(substr($auth_header, 0, 5), "OAuth ") !== 0)
                throw new Exception(Constants::ERROR_INVALID_REQUEST, Constants::ERRCODE_AUTH_HEADER_DOESNT_START_OAUTH);

            // Parse the rest of the header
            if (preg_match('/\s*OAuth\s*="(.+)"/', substr($auth_header, 5), $matches) == 0 || count($matches) < 2)
                throw new Exception(Constants::ERROR_INVALID_REQUEST, Constants::ERRCODE_MALFORMED_AUTH_HEADER);

            return $matches[1];
        }

        if (isset($_GET[Constants::PARAM_TOKEN_NAME])) {
            if (isset($_POST[Constants::PARAM_TOKEN_NAME])) // Both GET and POST are not allowed
                throw new Exception(Constants::ERROR_INVALID_REQUEST, Constants::ERRCODE_AUTH_TOKEN_IN_GET_AND_POST);

            return $_GET[Constants::PARAM_TOKEN_NAME];
        }

        if (isset($_POST[Constants::PARAM_TOKEN_NAME]))
            return $_POST[Constants::PARAM_TOKEN_NAME];

        return false;
    }

    /**
     * Check restricted authorization response types of corresponding Client
     * identifier.
     *
     * If you want to restrict clients to certain authorization response types,
     * override this function.
     *
     * @param $clientId
     *   Client identifier to be check with.
     * @param $responseType
     *
     * @return bool TRUE if the authorization response type is supported by this@ingroup oauth2_section_3
     */
    protected function checkRestrictedAuthResponseType($clientId, $responseType)
    {
        return true;
    }

    /**
     * returns supported grant types
     * @return array
     */
    protected function getSupportedGrantTypes()
    {
        return array(
        );
    }

    /**
     * check if client support grantType
     * @param string $client_id
     * @param string $grantType
     * @return boolean
     *      returns true if grantType is supported by client
     */
    protected function checkClientGrantTypeSupport($client_id, $grantType)
    {
        return true;
    }

    /**
     * Return supported scopes.
     *
     * If you want to support scope use, then have this function return a list
     * of all acceptable scopes (used to throw the invalid-scope error).
     * @static Scope $scope
     * @return \Lit\OAuth2\Scope|object A list as below, for example:@code
     * return new Scope('my-friends photos whatever-else');
     * @endcode
     *
     * @ingroup oauth2_section_3
     */
    protected function getSupportedScopes()
    {
        static $scope = null;
        if (!\is_object($scope)) {
            $scope = new Scope();
        }

        return $scope;
    }

    /**
     * @abstract
     * @param string $code
     * @return AuthorizationCode
     */
    abstract protected function findAuthorizationCode($code);

    /**
     * @abstract
     * @param string $clientId
     * @param string $redirectUri
     * @param Scope $scope
     * @param ResourceOwnerCredentials $resourceOwnerCredentials
     * @return AuthorizationCode
     */
    abstract protected function createAuthorizationCode($clientId, $redirectUri, Scope $scope, ResourceOwnerCredentials $resourceOwnerCredentials = null);

    /**
     * @abstract
     * @param string $code
     * @return boolean
     */
    abstract protected function removeAuthorizationCode($code);

    /**
     * @abstract
     * @param string $token
     * @return AccessToken|null
     */
    abstract protected function findAccessToken($token);

    /**
     * @abstract
     * @param string $clientId
     * @param Scope|null $scope
     * @param ResourceOwnerCredentials|null $resourceOwnerCredentials
     * @return AccessToken
     */
    abstract protected function createAccessToken($clientId, Scope $scope = null, ResourceOwnerCredentials $resourceOwnerCredentials = null);

    /**
     * @abstract
     * @param string $token
     * @return boolean
     */
    abstract protected function removeAccessToken($token);

    /**
     * @abstract
     * @param string $token
     * @return RefreshToken|null
     */
    abstract protected function findRefreshToken($token);

    /**
     * @abstract
     * @param Token $token
     * @return RefreshToken|null
     */
    abstract protected function createRefreshToken(Token $token);

    /**
     * @abstract
     * @param string $token
     * @return boolean
     */
    abstract protected function removeRefreshToken($token);

    /**
     * checks client credentials
     * @abstract
     * @param string $clientId
     *      unique client id identifier
     *
     * @param string $clientSecret
     *      if secret is not null - will check secret also
     *
     * @return ClientCredentials
     *      returns ClientCredentials instance if client found and secret check pass or FALSE instead
     */
    abstract protected function checkClientCredentials($clientId, $clientSecret = null);

    /**
     * check authorization by resource owner credentials
     * @abstract
     * @param string $clientId
     * @param string $username
     * @param string $password
     * @return boolean
     */
    abstract protected function checkResourceOwnerCredentials($clientId, $username, $password);

    /**
     * check authorization by assertion
     * @param string $clientId
     * @param string $assertionType
     * @param string $assertion
     * @return boolean
     */
    protected function checkAssertion($clientId, $assertionType, $assertion)
    {
        return false;
    }

    /**
     * check authorization by none (client_id only)
     * @param string $clientId
     * @return boolean
     */
    protected function checkNoneAccess($clientId)
    {
        return false;
    }

}