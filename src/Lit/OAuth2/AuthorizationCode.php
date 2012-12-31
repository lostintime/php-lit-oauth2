<?php

namespace Lit\OAuth2;

/**
 * @package Lito\OAuth2
 * @author lostintime
 */
class AuthorizationCode extends Token
{

    /**
     * @var string
     */
    private $redirectUri;

    /**
     * @param string $token
     * @param string $clientId
     * @param string $redirectUri
     * @param Scope $scope
     * @param int $expiresIn
     * @param int $expires
     * @param ResourceOwnerCredentials $resourceOwnerCredentials
     */
    public function __construct($token, $clientId, $redirectUri = null, Scope $scope = null, $expiresIn = self::EXPIRES_ONE_MINUTE, $expires = null, ResourceOwnerCredentials $resourceOwnerCredentials = null)
    {
        parent::__construct($token, $clientId, $scope, $expiresIn, $expires, $resourceOwnerCredentials);
        $this->setRedirectUri($redirectUri);
    }

    /**
     * @param string $redirectUri
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
     * creates new AuthorizationCode
     *
     * @param string $clientId
     * @param Scope|null $redirectUri
     * @param int|Scope|null $scope
     * @param int $expiresIn
     * @return Token
     */
    public static function factory($clientId, $redirectUri = null, Scope $scope = null, $expiresIn = self::EXPIRES_ONE_HOUR)
    {
        return new static(static::generateTokenString(), $clientId, $redirectUri, $scope, $expiresIn);
    }
}