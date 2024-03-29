<?php
namespace axenox\OAuth2Connector\CommonLogic\Security\Authenticators;

use exface\Core\CommonLogic\UxonObject;
use exface\Core\Interfaces\Widgets\iContainOtherWidgets;
use axenox\OAuth2Connector\Facades\OAuth2ClientFacade;
use exface\Core\Factories\FacadeFactory;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2AuthenticatedToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use exface\Core\Factories\WidgetFactory;
use exface\Core\Exceptions\Security\AuthenticationFailedError;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2RequestToken;
use League\OAuth2\Client\Provider\AbstractProvider;
use axenox\OAuth2Connector\Exceptions\OAuthHttpException;
use exface\Core\Interfaces\WidgetInterface;
use exface\Core\Interfaces\Security\AuthenticationProviderInterface;
use League\OAuth2\Client\Provider\GenericProvider;
use exface\Core\Exceptions\Security\AuthenticationRuntimeError;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;
use exface\Core\Exceptions\InvalidArgumentException;
use exface\Core\Interfaces\Widgets\iHaveButtons;
use exface\Core\Actions\Login;
use exface\Core\Exceptions\UnexpectedValueException;
use exface\Core\DataTypes\PhpClassDataType;
use exface\Core\Widgets\LoginPrompt;
use exface\Core\Widgets\Form;

trait OAuth2Trait
{    
    private $clientFacade = null;
    
    private $clientId = null;
    
    private $clientSecret = null;
    
    private $urlAuthorize = null;
    
    private $urlAccessToken = null;
    
    private $urlResourceOwnerDetails = null;
    
    private $provider = null;
    
    private $scopes = [];
    
    private $usernameResourceOwnerField = null;
    
    private $debug = false;
    
    /**
     * 
     * @return AuthenticationProviderInterface
     */
    protected abstract function getAuthProvider() : AuthenticationProviderInterface;
    
    /**
     * 
     * @return AccessTokenInterface|NULL
     */
    protected abstract function getTokenStored() : ?AccessTokenInterface;
    
    /**
     * 
     * @param AccessTokenInterface $authenticatedToken
     * @return string|NULL
     */
    protected abstract function getRefreshToken(AccessTokenInterface $authenticatedToken) : ?string;
    
    /**
     * 
     * @param AuthenticationTokenInterface $token
     * @throws AuthenticationFailedError
     * @throws OAuthHttpException
     * @return OAuth2AuthenticatedToken
     */
    protected function exchangeOAuthToken(AuthenticationTokenInterface $token) : OAuth2AuthenticatedToken
    {
        if ($token instanceof OAuth2AuthenticatedToken) {
            if ($token->getAccessToken()->hasExpired()) {
                throw new AuthenticationFailedError($this->getAuthProvider(), 'OAuth token expired: Please sign in again!');
            } else {
                return $token;
            }
        }
        
        if (! $token instanceof OAuth2RequestToken) {
            throw new AuthenticationRuntimeError($this, 'Cannot use "' . get_class($token) . '" as OAuth token!');
        }
        
        if ($token->getOAuthProviderHash() !== $this->getOAuthProviderHash()) {
            throw new AuthenticationFailedError($this->getAuthProvider(), 'OAuth token does not match the provider (hash mismatch)!');
        }
        
        $clientFacade = $this->getOAuthClientFacade();
        $request = $token->getRequest();
        $requestParams = $request->getQueryParams();
        $provider = $this->getOAuthProvider();
        
        switch (true) {
            
            // Got an error, probably user denied access
            case ! empty($requestParams['error']):
                $clientFacade->stopOAuthSession();
                // Wrap the OAuth exception in an ordinary AuthenticationFailedError to ensure they are
                // handled similarly to other types of password-mismatch errors. In particular, they
                // will produce propper 401 HTTP error codes.
                throw new AuthenticationFailedError(
                    $this,
                    'Failed to sign in with Microsoft account',
                    null,
                    new OAuthHttpException($this, 'OAuth2 error: ' . htmlspecialchars($requestParams['error'], ENT_QUOTES, 'UTF-8'), null, null, $request)
                );
                
            // If we are not processing a provider response, either use the stored token
            // or redirect to the provider to start authentication
            case empty($requestParams['code']):
                $authOptions = [];
                $oauthToken = $this->getTokenStored();
                if ($oauthToken) {
                    if ($this->isDebugMode()) {
                        $this->getWorkbench()->getLogger()->debug('OAuth2: authentication requested with stored token', $oauthToken->jsonSerialize());
                    }
                    $expired = $oauthToken->hasExpired();
                    if ($expired) {
                        if (! $this->getRefreshToken($oauthToken)) {
                            $authOptions = ['prompt' => 'consent'];
                        } else {
                            $oauthToken = $provider->getAccessToken('refresh_token', [
                                'refresh_token' => $this->getRefreshToken($oauthToken)
                            ]);
                        }
                    }
                } else {
                    if ($this->isDebugMode()) {
                        $this->getWorkbench()->getLogger()->debug('OAuth2: authentication requested without stored token');
                    }
                }
                if (! $oauthToken || ! empty($authOptions)) {
                    // If we don't have an authorization code then get one
                    $authUrl = $provider->getAuthorizationUrl($authOptions);
                    if ($this->isDebugMode()) {
                        $this->getWorkbench()->getLogger()->debug('OAuth2: redirecting to ' . $authUrl);
                    }
                    $redirectUrl = $request->getHeader('Referer')[0];
                    $clientFacade->startOAuthSession(
                        $this->getConnection(),
                        $this->getOAuthProviderHash(),
                        $redirectUrl,
                        ['state' => $provider->getState()]
                    );
                    if ($this->isDebugMode()) {
                        $this->getWorkbench()->getLogger()->debug('OAuth2: redirecting to provider', [
                            'oauth_hash' => $this->getOAuthProviderHash(),
                            'oauth_state' => $provider->getState(),
                            'provider_url' => $authUrl
                        ]);
                    }
                    $this->getWorkbench()->stop();
                    header('Location: ' . $authUrl);
                    exit;
                }
                break;
                
            // If code is not empty and there is no error, process provider response here
            default:
                $sessionVars = $clientFacade->getOAuthSessionVars();
                
                if (empty($requestParams['state']) || $requestParams['state'] !== $sessionVars['state']) {
                    $clientFacade->stopOAuthSession();
                    throw new OAuthHttpException($this, 'Invalid OAuth2 state: expecting "' . $sessionVars['state'] . '", received from provider "' . $requestParams['state'] . '"!', null, null, $request);
                }
                
                // Get an access token (using the authorization code grant)
                try {
                    $oauthToken = $provider->getAccessToken('authorization_code', [
                        'code' => $requestParams['code']
                    ]);
                    if ($this->isDebugMode()) {
                        $this->getWorkbench()->getLogger()->debug('OAuth2: authentication successfull. Received new token from provider', [
                            'oauth_session' => $sessionVars,
                            'oauth_access_token' => $oauthToken->jsonSerialize()
                        ]);
                    }
                } catch (\Throwable $e) {
                    $clientFacade->stopOAuthSession();
                    throw new OAuthHttpException($this->getAuthProvider(), 'Cannot get OAuth2 access token from provider response: ' . $e->getMessage(), null, $e, $request);
                }
        }
        
        $clientFacade->stopOAuthSession();
        if ($oauthToken) {
            return new OAuth2AuthenticatedToken($this->getUsername($oauthToken, $provider), $oauthToken, $token->getFacade());
        }
        
        throw new AuthenticationFailedError($this->getConnection(), 'Please sign in first!');
    }
    
    /**
     * 
     * {@inheritDoc}
     * @see \exface\Core\CommonLogic\Security\Authenticators\AbstractAuthenticator::createLoginForm()
     */
    protected function createLoginForm(Form $loginForm) : Form
    {
        $loginForm
        ->addWidget($this->createButtonWidget($loginForm))
        ->addWidget(WidgetFactory::createFromUxonInParent($loginForm, new UxonObject([
            'attribute_alias' => 'AUTH_TOKEN_CLASS',
            'value' => '\\' . OAuth2RequestToken::class,
            'widget_type' => 'InputHidden'
        ])));
        $container = $loginForm->getParent();
        if ($container instanceof iHaveButtons) {
            foreach ($container->getButtons() as $btn) {
                if ($btn->getAction() instanceof Login) {
                    $btn->setHidden(true);
                }
            }
        }
        return $loginForm;
    }
    
    /**
     * 
     * @return AbstractProvider
     */
    protected function getOAuthProvider() : AbstractProvider
    {
        $options = [
            'clientId'                  => $this->getClientId(),
            'clientSecret'              => $this->getClientSecret(),
            'redirectUri'               => $this->getRedirectUri(),
            'urlAuthorize'              => $this->getUrlAuthorize(),
            'urlAccessToken'            => $this->getUrlAccessToken(),
            'urlResourceOwnerDetails'   => $this->getUrlResourceOwnerDetails()
        ];
        return new GenericProvider($options);
    }
    
    /**
     * 
     * @throws UnexpectedValueException
     * @return string
     */
    public function getClientId() : string
    {
        if ($this->clientId === null) {
            throw new UnexpectedValueException('Missing `client_id` property in ' . PhpClassDataType::findClassNameWithoutNamespace($this) . ' configuration!');
        }
        return $this->clientId;
    }
    
    /**
     * The client ID assigned to you by the provider
     * 
     * @uxon-property client_id
     * @uxon-type string
     * @uxon-required true
     * 
     * @param string $value
     * @return AuthenticationProviderInterface
     */
    public function setClientId(string $value) : AuthenticationProviderInterface
    {
        $this->clientId = $value;
        return $this;
    }
    
    /**
     * 
     * @throws UnexpectedValueException
     * @return string
     */
    protected function getClientSecret() : string
    {
        if ($this->clientSecret === null) {
            throw new UnexpectedValueException('Missing `client_secret` property in ' . PhpClassDataType::findClassNameWithoutNamespace($this) . ' configuration!');
        }
        return $this->clientSecret;
    }
    
    /**
     * The client password assigned to you by the provider
     * 
     * @uxon-property client_secret
     * @uxon-type string
     * @uxon-required true
     * 
     * @return string
     */
    protected function setClientSecret(string $value) : AuthenticationProviderInterface
    {
        $this->clientSecret = $value;
        return $this;
    }
    
    /**
     * 
     * @param iContainOtherWidgets $container
     * @return WidgetInterface
     */
    protected function createButtonWidget(iContainOtherWidgets $container) : WidgetInterface
    {
        return WidgetFactory::createFromUxonInParent($container, new UxonObject([
            'widget_type' => 'Html',
            'hide_caption' => false,
            'inline' => true,
            'html' => <<<HTML
            
<a href="{$this->getOAuthClientFacade()->buildUrlForProvider($this, $this->getOAuthProviderHash())}" referrerpolicy="unsafe-url">
    <span style="float: left">
        <i style="padding: 3px 8px 3px 8px; font-size: 40px; color: gray" class="fa fa-key"></i>
    </span>
    <span style="line-height: 40px; display: inline-block; margin: 3px; padding: 0 8px 0 8px; font-weight: bold;">
        {$this->getWorkbench()->getApp('axenox.OAuth2Connector')->getTranslator()->translate('SIGN_IN_WITH')} OAuth 2.0
    </span>
</a>

HTML
        ]));
    }
    
    /**
     *
     * @return OAuth2ClientFacade
     */
    protected function getOAuthClientFacade() : OAuth2ClientFacade
    {
        if ($this->clientFacade === null) {
            $this->clientFacade = FacadeFactory::createFromString(OAuth2ClientFacade::class, $this->getWorkbench());;
        }
        return $this->clientFacade;
    }
    
    /**
     *
     * @return string
     */
    protected function getRedirectUri() : string
    {
        return $this->getOAuthClientFacade()->buildUrlToFacade(false);
    }
    
    /**
     * 
     * @param AccessTokenInterface $oauthToken
     * @return string|NULL
     */
    protected function getUsername(AccessTokenInterface $oauthToken) : ?string
    {
        $ownerDetails = $this->getOAuthProvider()->getResourceOwner($oauthToken);
        if (($field = $this->getUsernameResourceOwnerField()) !== null) {
            return $ownerDetails->toArray()[$field];
        }
        return $ownerDetails->getId();
    }
    
    /**
     *
     * @return string
     */
    protected function getUrlAuthorize() : string
    {
        return $this->urlAuthorize;
    }
    
    /**
     * The URL to start the authorization process
     *
     * @uxon-property url_authorize
     * @uxon-type uri
     * 
     * @param string $value
     * @return AuthenticationProviderInterface
     */
    protected function setUrlAuthorize(string $value) : AuthenticationProviderInterface
    {
        $this->urlAuthorize = $value;
        return $this;
    }
    
    /**
     *
     * @return string
     */
    protected function getUrlAccessToken() : string
    {
        return $this->urlAccessToken;
    }
    
    /**
     * The URL to get the access token from
     *
     * @uxon-property url_access_token
     * @uxon-type uri
     *
     * @param string $value
     * @return AuthenticationProviderInterface
     */
    protected function setUrlAccessToken(string $value) : AuthenticationProviderInterface
    {
        $this->urlAccessToken = $value;
        return $this;
    }
    
    /**
     * @return string
     */
    protected function getUrlResourceOwnerDetails() : string
    {
        return $this->urlResourceOwnerDetails;
    }
    
    /**
     * The URL to get the authenticated user data (name, email, etc.)
     *
     * @uxon-property url_resource_owner_details
     * @uxon-type uri
     * 
     * @param string $value
     * @return AuthenticationProviderInterface
     */
    protected function setUrlResourceOwnerDetails(string $value) : AuthenticationProviderInterface
    {
        $this->urlResourceOwnerDetails = $value;
        return $this;
    }
    
    /**
     * 
     * @return string[]
     */
    protected function getScopes() : array
    {
        return $this->scopes;
    }
    
    /**
     * The scopes to require
     * 
     * @uxon-property scopes
     * @uxon-type array
     * @uxon-template [""]
     * 
     * @param string[] $arrayOrUxon
     * @return AuthenticationProviderInterface
     */
    protected function setScopes($arrayOrUxon) : AuthenticationProviderInterface
    {
        switch (true) { 
            case $arrayOrUxon instanceof UxonObject:        
                $this->scopes = $arrayOrUxon->toArray();
                break;
            case is_array($arrayOrUxon):
                $this->scopes = $arrayOrUxon;
                break;
            default:
                throw new InvalidArgumentException('Invalid authenticator configuration for OAuth scopes: expecting array, got ' . gettype($arrayOrUxon));
        }
        return $this;
    }
    
    protected function getOAuthProviderHash() : string
    {
        return md5($this->getClientId() . $this->getUrlAuthorize());
    }
    
    /**
     * 
     * @return string|NULL
     */
    protected function getUsernameResourceOwnerField() : ?string
    {
        return $this->usernameResourceOwnerField;
    }
    
    /**
     * The field name in resource owner details, that contains the username.
     * 
     * Each authenticated token needs to have a username in the workbench. This property allows
     * to specify, which field of the resource owner details supplied by the OAuth provider is
     * to be used as username. Most providers include the `email` in the owner details, so that's
     * a good for a start.
     * 
     * If not set, the id of the resource owner will be used! This is technically OK, but very
     * cryptic, so it's a good idea to set a `username_resource_owner_field` explicitly.
     * 
     * @uxon-property username_resource_owner_field
     * @uxon-type string
     * 
     * @param string $fieldName
     * @return AuthenticationProviderInterface
     */
    protected function setUsernameResourceOwnerField(string $fieldName) : AuthenticationProviderInterface
    {
        $this->usernameResourceOwnerField = $fieldName;
        return $this;
    }
    
    /**
     *
     * @return bool
     */
    protected function isDebugMode() : bool
    {
        return $this->debug;
    }
    
    /**
     * Set to TRUE to log additional information for debugging: e.g. access tokens, etc.
     *
     * @uxon-property debug_log
     * @uxon-type boolean
     * @uxon-default false
     *
     * @param bool $value
     * @return OAuth2Authenticator
     */
    protected function setDebugLog(bool $value) : OAuth2Authenticator
    {
        $this->debug = $value;
        return $this;
    }
}