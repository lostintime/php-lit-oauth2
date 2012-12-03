<?php

namespace Lit\OAuth2;

/**
 * @package Lito\OAuth2
 * @author lostintime
 */
class ErrorResponse extends Response
{

    /**
     * @param string $error
     * @param string $errorCode
     * @param string|null $errorDescription
     * @param string|null $errorUri
     * @param string|null $state
     */
    public function __construct($error, $errorCode, $errorDescription = null, $errorUri = null, $state = null)
    {
        $this->set(Constants::PARAM_ERROR, $error);
        $this->set(Constants::PARAM_ERROR_CODE, $errorCode);

        if ($errorDescription)
            $this->set(Constants::PARAM_ERROR_DESCRIPTION, $errorDescription);

        if ($errorUri)
            $this->set(Constants::PARAM_ERROR_URI, $errorUri);

        if ($state)
            $this->set(Constants::PARAM_STATE, $state);
    }

}