<?php

namespace Lit\OAuth2;

/**
 * @package Lito\OAuth2
 * @author lostintime
 */
class Client
{

    /**
     * @var string
     */
    private $clientId;

    /**
     * @var string
     */
    private $clientSecret;

    /**
     * @var string
     */
    private $authorizationUri;

    /**
     * @var string
     */
    private $accessTokenUri;

    /**
     * @var string
     */
    private $redirectUri;

    /**
     * @param string $clientId
     * @param string $clientSecret
     * @param string $authorizationUri
     * @param string $accessTokenUri
     * @param string $redirectUri
     */
    public function __construct($clientId, $clientSecret = null, $authorizationUri = null, $accessTokenUri = null, $redirectUri = null)
    {
        $this->setClientId($clientId);
        $this->setClientSecret($clientSecret);
        $this->setAuthorizationUri($authorizationUri);
        $this->setAccessTokenUri($accessTokenUri);
        $this->setRedirectUri($redirectUri);
    }

    /**
     * redirects user to authorization endpoint to get authorization_code
     *      which can be used later for getting access_token (see getAccessTokenFromAuthorizationCode method)
     *      http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-1.3.1
     * @param Scope $scope
     * @param string $state
     * @return boolean
     */
    public function getAuthorizationCode(Scope $scope = null, $state = null)
    {
        if ($this->getAuthorizationUri() && $this->getClientId() && $this->getRedirectUri()) {
            $params = array(
                Constants::PARAM_RESPONSE_TYPE => Constants::AUTH_RESPONSE_TYPE_AUTH_CODE,
                Constants::PARAM_CLIENT_ID => $this->getClientId(),
                Constants::PARAM_REDIRECT_URI => $this->getRedirectUri(),
            );

            if ($scope) {
                $params[Constants::PARAM_SCOPE] = (string)$scope;
            }

            if ($state) {
                $params[Constants::PARAM_STATE] = (string)$state;
            }

            $url = $this->getAuthorizationUri()
                . (false === \strpos($this->getAuthorizationUri(), '?') ? '?' : '')
                . \http_build_query($params);

            header('Location: ' . $url);
            exit;
        }

        return false;
    }

    /**
     * Get access token from OAuth2.0 token endpoint with authorization code.
     *      http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-1.3.1
     *
     * @param string $code
     *   Authorization code issued by authorization server's authorization endpoint.
     *
     * @return array|null
     *   A valid OAuth2.0 JSON decoded access token in associative array, and
     *   NULL if not enough parameters or JSON decode failed.
     */
    public function getAccessTokenFromAuthorizationCode($code)
    {
        if ($this->getAccessTokenUri() && $this->getClientId() && $this->getClientSecret()) {
            return \json_decode($this->httpRequest($this->getAccessTokenUri(), 'POST', array(
                    Constants::PARAM_GRANT_TYPE => Constants::GRANT_TYPE_AUTH_CODE,
                    Constants::PARAM_CLIENT_ID => $this->getClientId(),
                    Constants::PARAM_CODE => $code,
                    Constants::PARAM_REDIRECT_URI => $this->getRedirectUri())
            ), true);
        }

        return null;
    }

    /**
     * redirects user to authorization endpoint to get access_token directly
     *   or returns false (usually on wrong client configuration)
     *   http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-1.3.2
     *
     * @param Scope $scope
     * @param string $state
     * @return boolean
     */
    public function getAuthorizationToken(Scope $scope = null, $state = null)
    {
        if ($this->getAuthorizationUri() && $this->getClientId() && $this->getRedirectUri()) {
            $params = array(
                Constants::PARAM_RESPONSE_TYPE => Constants::AUTH_RESPONSE_TYPE_TOKEN,
                Constants::PARAM_CLIENT_ID => $this->getClientId(),
                Constants::PARAM_REDIRECT_URI => $this->getRedirectUri(),
            );

            if ($scope) {
                $params[Constants::PARAM_SCOPE] = (string)$scope;
            }

            if ($state) {
                $params[Constants::PARAM_STATE] = (string)$state;
            }

            $url = $this->getAuthorizationUri()
                . (false === \strpos($this->getAuthorizationUri(), '?') ? '?' : '')
                . \http_build_query($params);

            header('Location: ' . $url);
            exit;
        }

        return false;
    }

    /**
     * Get access token from OAuth2.0 token endpoint with basic user credentials.
     *   http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-1.3.3
     *
     * @param string $username
     *   Username to be authorized with.
     *
     * @param string $password
     *   Password to be authorized with.
     *
     * @param Scope|null $scope
     *   requested access scope
     *
     * @return array|null
     *   A valid OAuth2.0 JSON decoded access token in associative array, and
     *   NULL if not enough parameters or JSON decode failed.
     */
    public function getAccessTokenFromPassword($username, $password, Scope $scope = null)
    {
        if ($this->getAccessTokenUri() && $this->getClientId() && $this->getClientSecret()) {
            return \json_decode($this->httpRequest($this->getAccessTokenUri(), 'POST', array(
                    Constants::PARAM_GRANT_TYPE => Constants::GRANT_TYPE_USER_CREDENTIALS,
                    Constants::PARAM_CLIENT_ID => $this->getClientId(),
                    Constants::PARAM_USERNAME => $username,
                    Constants::PARAM_PASSWORD => $password,
                    Constants::PARAM_SCOPE => $scope)
            ), true);
        }

        return null;
    }

    /**
     * Get access token from OAuth2.0 token endpoit using client credentials
     *   http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-1.3.4
     *
     * @param Scope|null $scope
     * @return array|null
     *   A valid OAuth2.0 JSON decoded access token in associative array, and
     *   NULL if not enough parameters or json decode failed
     */
    public function getAccessTokenFromClient(Scope $scope = null)
    {
        if ($this->getAccessTokenUri() && $this->getClientId() && $this->getClientSecret()) {
            return \json_decode($this->httpRequest($this->getAccessTokenUri(), 'POST', array(
                    Constants::PARAM_GRANT_TYPE => Constants::GRANT_TYPE_CLIENT_CREDENTIALS,
                    Constants::PARAM_CLIENT_ID => $this->getClientId(),
                    Constants::PARAM_SCOPE => $scope)
            ), true);
        }

        return null;
    }

    /**
     * extracts authorization server response params from Request instance
     * @param Request $request
     * @return array|null
     */
    public function extractRequestParams(Request $request)
    {
        // authorization server code and token response (response_type = code_and_token)
        if (isset($request[Constants::PARAM_CODE]) && isset($request[Constants::PARAM_ACCESS_TOKEN])) {
            return array(
                Constants::PARAM_CODE => $request[Constants::PARAM_CODE],
                Constants::PARAM_ACCESS_TOKEN => $request[Constants::PARAM_ACCESS_TOKEN],
                Constants::PARAM_TOKEN_TYPE => isset($request[Constants::PARAM_TOKEN_TYPE]) ? $request[Constants::PARAM_TOKEN_TYPE] : null,
                Constants::PARAM_EXPIRES_IN => isset($request[Constants::PARAM_EXPIRES_IN]) ? $request[Constants::PARAM_EXPIRES_IN] : null,
                Constants::PARAM_SCOPE => isset($request[Constants::PARAM_SCOPE]) ? $request[Constants::PARAM_SCOPE] : null,
                Constants::PARAM_STATE => isset($request[Constants::PARAM_STATE]) ? $request[Constants::PARAM_STATE] : null,
            );
            // authorization server code response (response_type = code)
        } else if (isset($request[Constants::PARAM_CODE])) {
            return array(
                Constants::PARAM_CODE => $request[Constants::PARAM_CODE],
                Constants::PARAM_STATE => isset($request[Constants::PARAM_STATE]) ? $request[Constants::PARAM_STATE] : null,
            );
            // authorization server token response (response_type = token)
        } else if (isset($request[Constants::PARAM_ACCESS_TOKEN])) {
            return array(
                Constants::PARAM_ACCESS_TOKEN => $request[Constants::PARAM_ACCESS_TOKEN],
                Constants::PARAM_TOKEN_TYPE => isset($request[Constants::PARAM_TOKEN_TYPE]) ? $request[Constants::PARAM_TOKEN_TYPE] : null,
                Constants::PARAM_EXPIRES_IN => isset($request[Constants::PARAM_EXPIRES_IN]) ? $request[Constants::PARAM_EXPIRES_IN] : null,
                Constants::PARAM_SCOPE => isset($request[Constants::PARAM_SCOPE]) ? $request[Constants::PARAM_SCOPE] : null,
                Constants::PARAM_STATE => isset($request[Constants::PARAM_STATE]) ? $request[Constants::PARAM_STATE] : null,
            );
        } else if (isset($request[Constants::PARAM_ERROR])) {
            return array(
                Constants::PARAM_ERROR => $request[Constants::PARAM_ERROR],
                Constants::PARAM_ERROR_CODE => isset($request[Constants::PARAM_ERROR_CODE]) ? $request[Constants::PARAM_ERROR_CODE] : null,
                Constants::PARAM_ERROR_DESCRIPTION => isset($request[Constants::PARAM_ERROR_DESCRIPTION]) ? $request[Constants::PARAM_ERROR_DESCRIPTION] : null,
                Constants::PARAM_ERROR_URI => isset($request[Constants::PARAM_ERROR_URI]) ? $request[Constants::PARAM_ERROR_URI] : null,
                Constants::PARAM_STATE => isset($request[Constants::PARAM_STATE]) ? $request[Constants::PARAM_STATE] : null,
            );
        } else {
            return null;
        }
    }

    /**
     * @param string $clientId
     * @return void
     */
    public function setClientId($clientId)
    {
        $this->clientId = $clientId;
    }

    /**
     * @return string
     */
    public function getClientId()
    {
        return $this->clientId;
    }

    /**
     * @param string $clientSecret
     * @return void
     */
    public function setClientSecret($clientSecret)
    {
        $this->clientSecret = $clientSecret;
    }

    /**
     * @return string
     */
    public function getClientSecret()
    {
        return $this->clientSecret;
    }

    /**
     * @param string $authorizationUri
     * @return void
     */
    public function setAuthorizationUri($authorizationUri)
    {
        $this->authorizationUri = $authorizationUri;
    }

    /**
     * @return string
     */
    public function getAuthorizationUri()
    {
        return $this->authorizationUri;
    }

    /**
     * @param string $accessTokenUri
     * @return void
     */
    public function setAccessTokenUri($accessTokenUri)
    {
        $this->accessTokenUri = $accessTokenUri;
    }

    /**
     * @return string
     */
    public function getAccessTokenUri()
    {
        return $this->accessTokenUri;
    }

    /**
     * @param string $redirectUri
     * @return void
     */
    public function setRedirectUri($redirectUri)
    {
        $this->redirectUri = $redirectUri;
    }

    /**
     * @return string
     */
    public function getRedirectUri()
    {
        return $this->redirectUri;
    }

    /**
     * @param string $uri
     *      uri to make request
     *
     * @param string $method
     *      (GET or POST)
     *
     * @param array $params
     *      request parameters
     *
     * @return string
     *      response content received
     */
    private function httpRequest($uri, $method, $params = array())
    {
        $process = \curl_init();

        \curl_setopt($process, CURLOPT_HTTPHEADER, array(
            'accept' => 'Accept: text/json, application/json;q=0.9,*/*;q=0.8',
            'language' => 'Accept-Language: en-us,en;q=0.5',
            'charset' => 'Accept-Charset: UTF-8,utf-8;q=0.7,*;q=0.7',
        ));

        \curl_setopt($process, CURLOPT_HEADER, 0);
        \curl_setopt($process, CURLOPT_USERAGENT, 'HttpJsonTransport');
        \curl_setopt($process, CURLOPT_TIMEOUT, 15);

        \curl_setopt($process, CURLOPT_RETURNTRANSFER, 1);
        \curl_setopt($process, CURLOPT_FOLLOWLOCATION, 1);

        if ('POST' == \strtoupper($method)) {
            \curl_setopt($process, CURLOPT_POST, 1);
            \curl_setopt($process, CURLOPT_POSTFIELDS, \http_build_query($params));
        } else {
            $uri .= (false === \strpos($uri, '?') ? '?' : '') . \http_build_query($params, NULL, '&');
        }

        \curl_setopt($process, \CURLOPT_URL, $uri);

        $content = \curl_exec($process);
        \curl_close($process);

        return $content;
    }

}
