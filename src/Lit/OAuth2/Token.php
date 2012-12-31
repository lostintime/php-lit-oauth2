<?php

namespace Lit\OAuth2;

/**
 * @abstract
 * @package Lito\OAuth2
 * @author lostintime
 */
class Token
{
    const EXPIRES_ONE_MINUTE = 60;
    const EXPIRES_ONE_HOUR = 3600;
    const EXPIRES_ONE_DAY = 86400;
    const EXPIRES_ONE_WEEK = 604800;
    const EXPIRES_TWO_WEEKS = 1209600;

    /**
     * token string
     * @var string
     */
    private $token;
    /**
     * client id
     * @var string
     */
    private $clientId;
    /**
     * token scope
     * @var Scope
     */
    private $scope;
    /**
     * token expiration time
     * @var int - unix timestamp
     */
    private $expires;

    /**
     * resource owner credentials related to access token
     * @var ResourceOwnerCredentials
     */
    private $resourceOwnerCredentials;

    /**
     * @param string $token
     * @param string $clientId
     * @param Scope $scope
     * @param int $expiresIn
     * @param int|null $expires
     * @param ResourceOwnerCredentials|null $resourceOwnerCredentials
     */
    public function __construct($token, $clientId, Scope $scope = null,
                                $expiresIn = self::EXPIRES_ONE_HOUR, $expires = null,
                                ResourceOwnerCredentials $resourceOwnerCredentials = null)
    {
        $this->setToken($token);
        $this->setClientId($clientId);
        $this->setScope($scope ? $scope : new Scope());
        $this->setExpiresIn($expiresIn);
        if ($expires)
            $this->setExpires($expires);

        $this->setResourceOwnerCredentials($resourceOwnerCredentials);
    }

    /**
     * @param string $token
     * @return Token
     */
    public function setToken($token)
    {
        $this->token = $token;
        return $this;
    }

    /**
     * @return string
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     * @param string $clientId
     * @return Token
     */
    public function setClientId($clientId)
    {
        $this->clientId = $clientId;
        return $this;
    }

    /**
     * @return string
     */
    public function getClientId()
    {
        return $this->clientId;
    }

    /**
     * @param Scope $scope
     * @return Token
     */
    public function setScope(Scope $scope)
    {
        $this->scope = $scope;
        return $this;
    }

    /**
     * @return Scope
     */
    public function getScope()
    {
        return $this->scope;
    }

    /**
     * @param int $expiresIn
     * @return Token
     */
    public function setExpiresIn($expiresIn)
    {
        $this->setExpires(time() + intval($expiresIn));
        return $this;
    }

    /**
     * @return int
     */
    public function getExpiresIn()
    {
        return $this->expires - time();
    }

    /**
     * @param int $expires
     * @return Token
     */
    public function setExpires($expires)
    {
        $this->expires = abs(intval($expires));
        return $this;
    }

    /**
     * @return int
     */
    public function getExpires()
    {
        return $this->expires;
    }

    /**
     * checks if token is expired
     * @return boolean
     */
    public function expired()
    {
        return $this->getExpiresIn() <= 0;
    }

    /**
     * setts ResourceOwnerCredentials instance
     *      if it's allowed_scope property is set - it overwrites token scope property!
     * @param ResourceOwnerCredentials $resourceOwnerCredentials
     * @return Token
     */
    public function setResourceOwnerCredentials(ResourceOwnerCredentials $resourceOwnerCredentials = null)
    {
        $this->resourceOwnerCredentials = $resourceOwnerCredentials;
        if ($resourceOwnerCredentials && ($resourceOwnerCredentials->getAllowedScope() instanceof Scope)) {
            $this->setScope($resourceOwnerCredentials->getAllowedScope());
        }

        return $this;
    }

    /**
     * @return ResourceOwnerCredentials
     */
    public function getResourceOwnerCredentials()
    {
        return $this->resourceOwnerCredentials;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return (string)$this->getToken();
    }

    /**
     * create new token
     * @param string $clientId
     * @param Scope|null $scope
     * @param int $expiresIn
     * @return Token
     */
    public static function factory($clientId, Scope $scope = null, $expiresIn = self::EXPIRES_ONE_HOUR)
    {
        return new static(static::generateTokenString(), $clientId, $scope, $expiresIn);
    }

    /**
     * generates new token string
     * @return string
     */
    public static function generateTokenString()
    {
        return md5(base64_encode(pack('N6', mt_rand(), mt_rand(), mt_rand(), mt_rand(), mt_rand(), uniqid())));
    }

}