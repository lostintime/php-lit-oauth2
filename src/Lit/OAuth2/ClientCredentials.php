<?php

namespace Lit\OAuth2;

/**
 * @package Lito\OAuth2
 * @author lostintime
 */
class ClientCredentials
{

    /**
     * @var string
     */
    private $id;

    /**
     * @var string
     */
    private $secret;

    /**
     * @var string
     */
    private $redirectUri;

    /**
     * @param string $id
     * @param string|null $secretHash
     * @param string|null $redirectUri
     */
    public function __construct($id, $secretHash = null, $redirectUri = null)
    {
        $this->setId($id);
        $this->setSecretHash($secretHash);
        $this->setRedirectUri($redirectUri);
    }

    /**
     * @param string $id
     * @return void
     */
    public function setId($id)
    {
        $this->id = $id;
    }

    /**
     * @return string
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * @param string $secret
     * @return void
     */
    public function setSecret($secret)
    {
        $this->setSecretHash(md5($secret));
    }

    /**
     * @param string $secretHash
     * @return void
     */
    public function setSecretHash($secretHash)
    {
        $this->secret = $secretHash;
    }

    /**
     * @return string
     */
    public function getSecretHash()
    {
        return $this->secret;
    }

    /**
     * checks client secret
     * @param string $secret
     * @return boolean
     */
    public function checkSecret($secret)
    {
        return md5($secret) == $this->secret;
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
     * check requested redirectUri starts with stored client redirectUri
     *    so redirectUri is allowed to go
     * @param string $redirectUri
     * @return boolean
     */
    public function checkRedirectUri($redirectUri)
    {
        return strcasecmp(substr($redirectUri, 0, strlen($this->getRedirectUri())), $this->getRedirectUri()) === 0;
    }

}