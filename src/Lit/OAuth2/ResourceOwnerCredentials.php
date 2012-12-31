<?php

namespace Lit\OAuth2;

/**
 * instance of this class must be returned from Server.checkResourceOwnerCredentials on success
 * implement it depending on your needs, instance of this class will be passed to Server.createAccessToken method
 * @package Lito\OAuth2
 * @author lostintime
 */
class ResourceOwnerCredentials
{

    /**
     * @var Scope
     */
    private $allowedScope;

    /**
     * @param Scope $scope
     * @return void
     */
    public function setAllowedScope(Scope $scope = null)
    {
        $this->allowedScope = $scope;
    }

    /**
     * @return Scope
     */
    public function getAllowedScope()
    {
        return $this->allowedScope;
    }

}
