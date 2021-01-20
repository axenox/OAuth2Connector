<?php
namespace axenox\OAuth2Connector\Exceptions;

use exface\Core\Exceptions\RuntimeException;
use exface\Core\Interfaces\Security\AuthenticationProviderInterface;
use exface\Core\Interfaces\Exceptions\AuthenticationExceptionInterface;

class OAuthRuntimeException extends RuntimeException implements AuthenticationExceptionInterface
{
    private $provider = null;
    
    /**
     *
     * @param AuthenticationProviderInterface $authProvider
     * @param string $message
     * @param string $alias
     * @param \Throwable $previous     *
     */
    public function __construct(AuthenticationProviderInterface $authProvider, $message, $alias = null, $previous = null)
    {
        parent::__construct($message, $alias, $previous);
        $this->provider = $authProvider;
    }
    
    /**
     *
     * {@inheritDoc}
     * @see \exface\Core\Interfaces\Exceptions\AuthenticationExceptionInterface::getAuthenticationProvider()
     */
    public function getAuthenticationProvider() : AuthenticationProviderInterface
    {
        return $this->provider;
    }
}