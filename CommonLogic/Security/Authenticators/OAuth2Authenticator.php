<?php
namespace axenox\OAuth2Connector\CommonLogic\Security\Authenticators;

use exface\Core\CommonLogic\Security\Authenticators\AbstractAuthenticator;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;
use League\OAuth2\Client\Token\AccessTokenInterface;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2RequestToken;
use exface\Core\Exceptions\Security\AuthenticationFailedError;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2AuthenticatedToken;
use exface\Core\DataTypes\EncryptedDataType;
use League\OAuth2\Client\Token\AccessToken;
use exface\Core\CommonLogic\Security\Authenticators\Traits\CreateUserFromTokenTrait;
use exface\Core\Interfaces\Security\AuthenticationProviderInterface;
use exface\Core\DataTypes\StringDataType;

/**
 * Authenticates users via OAuth 2.0 optionally creating new workbench users automatically.
 * 
 * This is a generic OAuth authenticator. If you are looking for OAuth with a popular cloud
 * service try looking for a specific connector app first: e.g. `axenox.GoogleConnector` or
 * `axenox.Microsoft365Connector`.
 * 
 * ## Examples
 * 
 * ```
 *  {
 *      "class": "\\axenox\\OAuth2Connector\\CommonLogic\\Security\\Authenticators\\OAuth2Autenticator",
 *      "id": "SOME_UNIQUE_ID",
 *      "client_id": "client id from your OAuth provider",
 *      "client_secret": "client secret from your OAuth provider",
 *      "url_authorize": "URL for the initial authorization request",
 *      "url_access_token": "URL to get the access token from",
 *      "url_resource_owner_details": "URL to fetch the owner data from",
 *      "username_resource_owner_field": "email",
 *      "create_new_users": true,
 *      "create_new_users_with_roles": [
 *          "your.App.SomeRole"
 *      ]
 *  }
 * 
 * ```
 * 
 * @author Andrej Kabachnik
 *
 */
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
        $token = $this->exchangeOAuthToken($token);
        
        $user = null;
        if ($this->userExists($token) === true) {
            $user = $this->getUserFromToken($token);
        } elseif ($this->getCreateNewUsers(true) === true) {
            $user = $this->createUserWithRoles($this->getWorkbench(), $token, $this->getNewUserData($token->getAccessToken()));
        } else {
            throw new AuthenticationFailedError($this, "Authentication failed, no PowerUI user with that username '{$token->getUsername()}' exists and none was created!", '7AL3J9X');
        }
        $this->logSuccessfulAuthentication($user, $token->getUsername());
        if ($token->getUsername() !== $user->getUsername()) {
            return new OAuth2AuthenticatedToken($user->getUsername(), $token->getAccessToken(), $token->getFacade());
        }
        $this->authenticatedToken = $token;
        $this->storeToken($token->getAccessToken());
        return $token;
    }
    
    /**
     * Returns an array of attribute values for the object `exface.Core.USER` that can be set from
     * the given token.
     * 
     * Override this method to implement ways to get `FIRST_NAME`, `LAST_NAME`, `EMAIL` etc. from
     * the OAuth resource owner details.
     * 
     * @param AccessTokenInterface $token
     * @return array
     */
    protected function getNewUserData(AccessTokenInterface $token) : array
    {
        return [];        
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
        return ($token instanceof OAuth2RequestToken && $token->getOAuthProviderHash() === $this->getOAuthProviderHash()) || $token instanceof OAuth2AuthenticatedToken;
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
    protected function getRefreshToken(AccessTokenInterface $authenticatedToken): ?string
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
     * @see OAuth2Trait::storeToken()
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
        if ($token instanceof OAuth2AuthenticatedToken) {
            if ($expires = $token->getAccessToken()->getExpires()) {
                $lifetime = $expires - time();
                return max([$lifetime, 0]);
            }
        }
        return null;
    }
    
    /**
     * Splits a give full name into first and last names.
     * 
     * Returns an array of the form [firstname, lastname].
     * 
     * @param string $fullName
     * @return string[]
     */
    protected function explodeName(string $fullName) : array
    {
        $firstName = '';
        $lastName = '';
        
        if (strpos($fullName, ', ')) {
            $lastName = StringDataType::substringBefore($fullName, ', ');
            $firstName = StringDataType::substringAfter($fullName, ', ');
        } else {
            $names = explode(' ', $fullName);
            if (count($names) === 2) {
                $firstName = $names[0];
                $lastName = $names[1];
            } else {
                $lastName = array_pop($names);
                $middleName = array_pop($names);
                $firstName = implode(' ', $names);
                switch (true) {
                    // Max M. Mustermann
                    case strlen($middleName) === 2 && substr($middleName, 1) === '.':
                        $firstName .= ' ' . $middleName;
                        break;
                        // Max Mustermann Jr
                    case strlen($lastName) <= 2:
                        $lastName = $middleName . ' ' . $lastName;
                        break;
                    default:
                        $firstName .= ' ' . $middleName;
                        break;
                }
            }
        }
        
        return [
            $firstName,
            $lastName
        ];
    }
}