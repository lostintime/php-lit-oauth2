<?php

namespace Lit\OAuth2;

/**
 * @package Lito\OAuth2
 * @author lostintime
 */
class Exception extends \Exception
{

    /**
     * @var string
     */
    protected $codeName;

    /**
     * @var string
     */
    protected $uri;

    /**
     * @param string|null $codeName
     * @param int $code
     * @param null $uri
     * @param \Exception $previous
     */
    public function __construct($codeName, $code = 0, $uri = null, \Exception $previous = null)
    {
        parent::__construct(Constants::getErrorMessage($code), $code, $previous);
        $this->codeName = $codeName;
        $this->uri = $uri;
    }

    /**
     * @return string
     */
    public function getCodeName()
    {
        return $this->codeName;
    }

    /**
     * @return string
     */
    public function getUri()
    {
        return $this->uri;
    }

}