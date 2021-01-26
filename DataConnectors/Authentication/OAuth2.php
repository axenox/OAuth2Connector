<?php
namespace axenox\OAuth2Connector\DataConnectors\Authentication;

use exface\Core\CommonLogic\UxonObject;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;
use exface\UrlDataConnector\CommonLogic\AbstractHttpAuthenticationProvider;
use exface\Core\Interfaces\Security\AuthenticationProviderInterface;
use League\OAuth2\Client\Token\AccessTokenInterface;
use League\OAuth2\Client\Token\AccessToken;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2AuthenticatedToken;
use exface\Core\Exceptions\InvalidArgumentException;
use Psr\Http\Message\RequestInterface;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2RequestToken;
use axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait;
use GuzzleHttp\Psr7\ServerRequest;
use exface\Core\Exceptions\Security\AuthenticationFailedError;

class OAuth2 extends AbstractHttpAuthenticationProvider
{
    use OAuth2Trait;
    
    const CREDENTIALS_TOKEN = 'token';
    const CREDENTIALS_REFRESH_TOKEN = 'refresh_token';
    const CREDENTIALS_PROVIDER_HASH = 'provider_hash';
    
    private $storedToken = null;
    
    private $refreshToken = null;
    
    public function authenticate(AuthenticationTokenInterface $token): AuthenticationTokenInterface
    {
        if (! $token instanceof OAuth2RequestToken) {
            throw new InvalidArgumentException('Cannot use token ' . get_class($token) . ' in OAuth2 authentication: only OAuth2RequestToken or derivatives allowed!');
        }
        
        return $this->exchangeOAuthToken($token);
    }
    
    /**
     *
     * {@inheritDoc}
     * @see \exface\UrlDataConnector\Interfaces\HttpAuthenticationProviderInterface::getDefaultRequestOptions()
     */
    public function getDefaultRequestOptions(array $defaultOptions): array
    {
        return $defaultOptions;
    }
    
    /**
     *
     * {@inheritDoc}
     * @see \exface\UrlDataConnector\Interfaces\HttpAuthenticationProviderInterface::signRequest()
     */
    public function signRequest(RequestInterface $request) : RequestInterface
    {
        if ($this->needsSigning($request) === false) {
            return $request;
        }
        
        $token = $this->getTokenStored();
        
        switch (true) {
            case ! $token:
                throw new AuthenticationFailedError($this->getConnection(), 'Please authenticate first!');
            case $token->hasExpired():
                $clientFacade = $this->getOAuthClientFacade();
                $hash = $this->getOAuthProviderHash();
                $fakeRequest = new ServerRequest('GET', $clientFacade->buildUrlForProvider($this, $hash));
                $requestToken = new OAuth2RequestToken($fakeRequest, $hash, $clientFacade);
                $token = $this->getConnection()->authenticate($requestToken, true, $this->getWorkbench()->getSecurity()->getAuthenticatedUser(), true);
                break;
        }
        
        $request = $request->withHeader('Authorization', 'Bearer ' . $token->getToken());
        
        return $request;
    }
    
    /**
     *
     * {@inheritDoc}
     * @see \exface\UrlDataConnector\Interfaces\HttpAuthenticationProviderInterface::getCredentialsUxon()
     */
    public function getCredentialsUxon(AuthenticationTokenInterface $authenticatedToken): UxonObject
    {
        if (! $authenticatedToken instanceof OAuth2AuthenticatedToken) {
            throw new InvalidArgumentException('Cannot store authentication token ' . get_class($authenticatedToken) . ' in OAuth2 credentials: only OAuth2AuthenticatedToken or derivatives supported!');
        }
        
        $accessToken = $authenticatedToken->getAccessToken();
        $uxon = new UxonObject([
            'authentication' => [
                'class' => '\\' . get_class($this),
                self::CREDENTIALS_TOKEN => $accessToken->jsonSerialize(),
                self::CREDENTIALS_REFRESH_TOKEN => ($accessToken->getRefreshToken() ? $accessToken->getRefreshToken() : $this->getRefreshToken($accessToken)),
                self::CREDENTIALS_PROVIDER_HASH => $this->getOAuthProviderHash()
            ]
        ]);
        
        return $uxon;
    }
    
    /**
     * 
     * @param RequestInterface $request
     * @return bool
     */
    protected function needsSigning(RequestInterface $request) : bool
    {
        return true;
    }
    
    /**
     * Use a custom token (only use this if really neccessary!)
     * 
     * @uxon-property token
     * @uxon-type object
     * 
     * @param UxonObject|AccessTokenInterface $uxon
     * @return OAuth2
     */
    protected function setToken($tokenOrUxon) : OAuth2
    {
        switch (true) {
            case $tokenOrUxon instanceof AccessTokenInterface:
                $token = $tokenOrUxon;
                break;
            case $tokenOrUxon instanceof UxonObject:
                $token = new AccessToken($tokenOrUxon->toArray());
                break;
            default:
                throw new InvalidArgumentException('Cannot store OAuth token: expecting AccessTokenInterface or UXON, got ' . gettype($tokenOrUxon) . ' instead!');
        }
        
        $this->storedToken = $token;
        
        return $this;
    }
    
    /**
     * 
     * @see OAuth2Trait::getTokenStored()
     */
    protected function getTokenStored() : ?AccessTokenInterface
    {
        return $this->storedToken;
    }
    
    /**
     *
     * @see OAuth2Trait::getRefreshToken()
     */
    protected function getRefreshToken(AccessTokenInterface $authenticatedToken) : ?string
    {
        return $this->refreshToken;
    }
    
    /**
     *
     * @param string|null $value
     * @return AuthenticationProviderInterface
     */
    protected function setRefreshToken($value) : AuthenticationProviderInterface
    {
        $this->refreshToken = $value;
        return $this;
    }
    
    /**
     * 
     * @return AuthenticationProviderInterface
     */
    protected function getAuthProvider() : AuthenticationProviderInterface
    {
        return $this->getConnection();
    }
    
    /**
     * 
     * {@inheritDoc}
     * @see \exface\Core\CommonLogic\Traits\ImportUxonObjectTrait::importUxonObject()
     */
    public function importUxonObject(UxonObject $uxon, array $skip_property_names = array())
    {
        $storedHash = $uxon->getProperty(self::CREDENTIALS_PROVIDER_HASH);
        $uxon->unsetProperty(self::CREDENTIALS_PROVIDER_HASH);
        
        parent::importUxonObject($uxon, $skip_property_names);
        
        if (! $storedHash || $storedHash !== $this->getOAuthProviderHash()) {
            $this->storedToken = null;
            $this->refreshToken = null;
        }
    }
}