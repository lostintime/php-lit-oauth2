<?php

namespace Lit\OAuth2;

/**
 * @package Lito\OAuth2
 * @author lostintime
 */
class AccessTokenResponse extends Response
{

    /**
     * @var AccessToken
     */
    private $accessToken;

    /**
     * @var RefreshToken
     */
    private $refreshToken;

    /**
     * @param AccessToken $accessToken
     * @param RefreshToken|null $refreshToken
     */
    public function __construct(AccessToken $accessToken, RefreshToken $refreshToken = null)
    {
        $this->setAccessToken($accessToken);
        if ($refreshToken)
            $this->setRefreshToken($refreshToken);
    }

    /**
     * @param AccessToken $accessToken
     * @return void
     */
    public function setAccessToken(AccessToken $accessToken)
    {
        $this->accessToken = $accessToken;

        $this->set(Constants::PARAM_ACCESS_TOKEN, $accessToken->getToken());
        $this->set(Constants::PARAM_EXPIRES_IN, $accessToken->getExpiresIn());

        if ("" != (string)$accessToken->getScope()) {
            $this->set(Constants::PARAM_SCOPE, (string)$accessToken->getScope());
        } else {
            $this->remove(Constants::PARAM_SCOPE);
        }
    }

    /**
     * @return AccessToken
     */
    public function getAccessToken()
    {
        return $this->accessToken;
    }

    /**
     * @param RefreshToken $refreshToken
     * @return void
     */
    public function setRefreshToken(RefreshToken $refreshToken)
    {
        $this->refreshToken = $refreshToken;
        $this->set(Constants::PARAM_REFRESH_TOKEN, $refreshToken->getToken());
    }

    /**
     * @return void
     */
    public function unsetRefreshToken()
    {
        $this->refreshToken = null;
        $this->remove(Constants::PARAM_REFRESH_TOKEN);
    }

    /**
     * @return RefreshToken
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

}
