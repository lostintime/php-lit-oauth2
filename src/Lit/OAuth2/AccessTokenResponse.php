<?php

namespace Lit\OAuth2;

/**
 * @package Lito\OAuth2
 * @author lostintime
 */
class AccessTokenResponse extends Response
{

    /**
     * @var Token
     */
    private $accessToken;

    /**
     * @var Token
     */
    private $refreshToken;

    /**
     * @param Token $accessToken
     * @param Token|null $refreshToken
     */
    public function __construct(Token $accessToken, Token $refreshToken = null)
    {
        $this->setAccessToken($accessToken);
        if ($refreshToken)
            $this->setRefreshToken($refreshToken);
    }

    /**
     * @param Token $accessToken
     * @return void
     */
    public function setAccessToken(Token $accessToken)
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
     * @return Token
     */
    public function getAccessToken()
    {
        return $this->accessToken;
    }

    /**
     * @param Token $refreshToken
     * @return void
     */
    public function setRefreshToken(Token $refreshToken)
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
     * @return Token
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

}
