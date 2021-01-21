<?php
namespace axenox\OAuth2Connector\CommonLogic\Security\Authenticators;

use exface\Core\CommonLogic\Security\Authenticators\AbstractAuthenticator;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;
use League\OAuth2\Client\Token\AccessTokenInterface;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2RequestToken;
use exface\Core\Exceptions\Security\AuthenticationFailedError;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2AccessToken;
use exface\Core\DataTypes\EncryptedDataType;
use League\OAuth2\Client\Token\AccessToken;
use exface\Core\CommonLogic\Security\Authenticators\Traits\CreateUserFromTokenTrait;
use exface\Core\Interfaces\Security\AuthenticationProviderInterface;
use exface\Core\CommonLogic\Security\AuthenticationToken\RememberMeAuthToken;

class OAuth2Authenticator extends AbstractAuthenticator
{
    use OAuth2Trait;
    use CreateUserFromTokenTrait;
    
    private $authenticatedToken = null;
    
    /**
     * 
     * {@inheritDoc}
     * @see \exface\Core\Interfaces\Security\AuthenticationProviderInterface::authenticate()
     */
    public function authenticate(AuthenticationTokenInterface $token) : AuthenticationTokenInterface
    {
        if ($token instanceof RememberMeAuthToken) {
            if ($storedToken = $this->getTokenStored()) {
                $token = $storedToken;
            } else {
                throw new AuthenticationFailedError($this, 'No stored OAuth token found: Please sign in!');
            }
        }
        
        $token = $this->exchangeOAuthToken($token);
        
        $user = null;
        if ($this->userExists($token) === true) {
            $user = $this->getUserFromToken($token);
        } elseif ($this->getCreateNewUsers() === true) {
            $user = $this->createUserWithRoles($this->getWorkbench(), $token);
        } else {
            throw new AuthenticationFailedError($this, "Authentication failed, no PowerUI user with that username '{$token->getUsername()}' exists and none was created!", '7AL3J9X');
        }
        $this->logSuccessfulAuthentication($user, $token->getUsername());
        if ($token->getUsername() !== $user->getUsername()) {
            return new OAuth2AccessToken($user->getUsername(), $token->getAccessToken(), $token->getFacade());
        }
        $this->authenticatedToken = $token;
        $this->storeToken($token->getAccessToken());
        return $token;
    }

    /**
     * 
     * {@inheritDoc}
     * @see \exface\Core\CommonLogic\Security\Authenticators\AbstractAuthenticator::getNameDefault()
     */
    protected function getNameDefault(): string
    {
        return 'OAuth2';
    }

    /**
     * 
     * {@inheritDoc}
     * @see \exface\Core\Interfaces\Security\AuthenticatorInterface::isAuthenticated()
     */
    public function isAuthenticated(AuthenticationTokenInterface $token): bool
    {
        return $token === $this->authenticatedToken; 
    }

    /**
     * 
     * {@inheritDoc}
     * @see \exface\Core\Interfaces\Security\AuthenticatorInterface::isSupported()
     */
    public function isSupported(AuthenticationTokenInterface $token): bool
    {
        return $token instanceof OAuth2RequestToken 
        || $token instanceof OAuth2AccessToken 
        || ($token instanceof RememberMeAuthToken && $this->getTokenStored());
    }
    
    /**
     * {@inheritDoc}
     * @see OAuth2Trait::getTokenStored()
     */
    protected function getTokenStored(): ?AccessTokenInterface
    {
        $encrypted = $this->getWorkbench()->getContext()->getScopeSession()->getVariable('token', $this->getId());
        try {
            $serialized = EncryptedDataType::decrypt(EncryptedDataType::getSecret($this->getWorkbench()), $encrypted);
            $array = json_decode($serialized, true);
            return new AccessToken($array);
        } catch (\Throwable $e) {
            return null;
        }
    }

    /**
     * {@inheritDoc}
     * @see OAuth2Trait::getRefreshToken()
     */
    protected function getRefreshToken(): ?string
    {
        $encrypted = $this->getWorkbench()->getContext()->getScopeSession()->getVariable('refresh', $this->getId());
        try {
            return EncryptedDataType::decrypt(EncryptedDataType::getSecret($this->getWorkbench()), $encrypted);
        } catch (\Throwable $e) {
            return null;
        }
    }
    
    /**
     * {@inheritDoc}
     * @see OAuth2Trait::getAuthProvider()
     */
    protected function storeToken(AccessTokenInterface $token) : OAuth2Authenticator
    {
        $session = $this->getWorkbench()->getContext()->getScopeSession();
        $serialized = json_encode($token->jsonSerialize());
        $encrypted = EncryptedDataType::encrypt(EncryptedDataType::getSecret($this->getWorkbench()), $serialized);
        $session->setVariable('token', $encrypted, $this->getId());
        
        if ($token->getRefreshToken()) {
            $encryptedRefresh = EncryptedDataType::encrypt(EncryptedDataType::getSecret($this->getWorkbench()), $token->getRefreshToken());
            $session->setVariable('refresh', $encryptedRefresh, $this->getId());
        }
        return $this;
    }
    
    /**
     * {@inheritDoc}
     * @see OAuth2Trait::getAuthProvider()
     */
    protected function getAuthProvider() : AuthenticationProviderInterface
    {
        return $this;
    }
    
    /**
     * 
     * {@inheritDoc}
     * @see \exface\Core\CommonLogic\Security\Authenticators\AbstractAuthenticator::getTokenLifetime()
     */
    public function getTokenLifetime(AuthenticationTokenInterface $token) : ?int
    {
        return 0;
    }
}