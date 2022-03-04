<?php
namespace axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken;

use exface\Core\Interfaces\Facades\FacadeInterface;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;
use League\OAuth2\Client\Token\AccessTokenInterface;
use exface\Core\Interfaces\Facades\HttpFacadeInterface;

/**
 * Represents an OAuth2.0 access token that was received from the provider
 *  
 * @author andrej.kabachnik
 *
 */
class OAuth2AuthenticatedToken implements AuthenticationTokenInterface
{
    private $facade = null;
    
    private $username = null;
    
    private $accessToken = null;
    
    /**
     * 
     * @param string $username
     * @param AccessTokenInterface $accessToken
     * @param HttpFacadeInterface $facade
     */
    public function __construct(string $username, AccessTokenInterface $accessToken, HttpFacadeInterface $facade)
    {
        $this->accessToken = $accessToken;
        $this->facade = $facade;
        $this->username = $username;
    }
    
    /**
     * 
     * {@inheritDoc}
     * @see \exface\Core\Interfaces\UserImpersonationInterface::isAnonymous()
     */
    public function isAnonymous(): bool
    {
        return false;
    }

    /**
     * 
     * {@inheritDoc}
     * @see \exface\Core\Interfaces\Security\AuthenticationTokenInterface::getFacade()
     */
    public function getFacade(): ?FacadeInterface
    {
        return $this->facade;
    }

    /**
     * 
     * {@inheritDoc}
     * @see \exface\Core\Interfaces\UserImpersonationInterface::getUsername()
     */
    public function getUsername(): ?string
    {
        return $this->username;
    }
    
    /**
     * 
     * @return AccessTokenInterface
     */
    public function getAccessToken() : AccessTokenInterface
    {
        return $this->accessToken;
    }
}