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

class OAuth2Authenticator extends AbstractAuthenticator
{
    use OAuth2Trait {
        authenticate as authenticateViaTrait;
    }
    
    private $authenticatedToken = null;
    
    public function authenticate(AuthenticationTokenInterface $token) : AuthenticationTokenInterface
    {
        $token = $this->authenticateViaTrait($token);
        
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

    protected function getNameDefault(): string
    {
        return 'OAuth2';
    }

    public function isAuthenticated(AuthenticationTokenInterface $token): bool
    {
        return $token === $this->authenticatedToken;
    }

    public function isSupported(AuthenticationTokenInterface $token): bool
    {
        return $token instanceof OAuth2RequestToken;
    }
    
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

    protected function getRefreshToken(): ?string
    {
        $encrypted = $this->getWorkbench()->getContext()->getScopeSession()->getVariable('refresh', $this->getId());
        try {
            return EncryptedDataType::decrypt(EncryptedDataType::getSecret($this->getWorkbench()), $encrypted);
        } catch (\Throwable $e) {
            return null;
        }
    }
    
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
}