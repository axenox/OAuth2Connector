<?php
namespace axenox\OAuth2Connector\CommonLogic\Security\Authenticators;

use axenox;

use exface\Core\CommonLogic\Security\Authenticators\AbstractAuthenticator;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;
use League\OAuth2\Client\Provider\GenericProvider;

class GoogleOAuth2Authenticator extends AbstractAuthenticator
{
    private $clientId = null;
    
    private $clientSecret = null;
    
    private $redirectUri = null;
    
    private $urlAuthorize = null;
    
    private $urlAccessToken = null;
    
    private $urlResourceOwnerDetails = null;
    
    private $provider = null;
    
    public function authenticate(AuthenticationTokenInterface $token): AuthenticationTokenInterface
    {
        
    }

    protected function getNameDefault(): string
    {
        return 'OAuth 2.0';
    }

    public function isAuthenticated(AuthenticationTokenInterface $token): bool
    {
        
    }

    public function isSupported(AuthenticationTokenInterface $token): bool
    {
        
    }
}