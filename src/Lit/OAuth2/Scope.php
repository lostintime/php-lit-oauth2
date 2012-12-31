<?php

namespace Lit\OAuth2;

/**
 * @package Lito\OAuth2
 * @author lostintime
 */
class Scope implements \Iterator
{
    /**
     * scope delimiter string
     */
    const ITEMS_DELIMITER = ' ';

    /**
     * scope items
     * @var array
     */
    private $items;

    /**
     * @param string $scope
     */
    public function __construct($scope = null)
    {
        $this->init($scope);
    }

    /**
     * initializes scope instance by string or array
     * @param mixed $scope
     */
    public function init($scope = null)
    {
        if (\is_array($scope)) {
            $this->items = $scope;
        } else if (\is_string($scope) && '' != trim($scope)) {
            $this->items = \explode(self::ITEMS_DELIMITER, trim($scope));
        } else {
            $this->items = array();
        }
    }

    /**
     *
     * @param Scope $scope
     *      scope to check if contained in this scope (all items)
     *      ex: "email phone name" is included in "name phone description name mobile"
     * @return boolean
     */
    public function contains(Scope $scope)
    {
        foreach ($scope as $scopeName) {
            if (!$this->containsName($scopeName)) {
                return false;
            }
        }

        return true;
    }

    /**
     * check if specific scope name is contained in this scope
     * @param string $scopeName
     *      scopeName to check if contained in this scope
     * @return boolean
     */
    public function containsName($scopeName)
    {
        return \in_array($scopeName, $this->items);
    }

    /**
     * adds scopeName to current scope list
     * @param string $scopeName
     * @return void
     */
    public function add($scopeName)
    {
        $this->items[] = (string)$scopeName;
    }

    /**
     * returns scope string representation
     * @return string
     */
    public function __toString()
    {
        return \implode(self::ITEMS_DELIMITER, $this->items);
    }

    /**
     * Iterator implementation: rewind method
     * @return void
     */
    public function rewind()
    {
        reset($this->items);
    }

    /**
     * Iterator implementation: current method
     * @return mixed
     */
    public function current()
    {
        $var = current($this->items);
        return $var;
    }

    /**
     * Iterator implementation: key method
     * @return mixed
     */
    public function key()
    {
        $var = key($this->items);
        return $var;
    }

    /**
     * Iterator implementation: next method
     * @return mixed
     */
    public function next()
    {
        $var = next($this->items);
        return $var;
    }

    /**
     * Iterator implementation: valid method
     * @return mixed
     */
    public function valid()
    {
        $key = key($this->items);
        $var = ($key !== NULL && $key !== FALSE);
        return $var;
    }

}