<?php
namespace axenox\OAuth2Connector\Facades;

use exface\Core\Facades\AbstractHttpFacade\AbstractHttpFacade;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use GuzzleHttp\Psr7\Response;
use exface\Core\Interfaces\DataSources\DataConnectionInterface;
use exface\Core\DataTypes\StringDataType;
use exface\Core\Factories\DataConnectionFactory;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2RequestToken;
use exface\Core\Interfaces\Security\AuthenticatorInterface;
use exface\Core\Exceptions\InvalidArgumentException;
use exface\Core\Exceptions\RuntimeException;
use exface\Core\Exceptions\Security\AuthenticationFailedError;
use axenox\OAuth2Connector\Exceptions\OAuthSessionNotStartedException;
use axenox\OAuth2Connector\Interfaces\OAuth2ClientFacadeInterface;
use exface\Core\Interfaces\Security\AuthenticationProviderInterface;
use exface\UrlDataConnector\Interfaces\HttpAuthenticationProviderInterface;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2AuthenticatedToken;

/**
 * 
 * @author Andrej Kabachnik
 *
 */
class OAuth2ClientFacade extends AbstractHttpFacade implements OAuth2ClientFacadeInterface
{
    const SESSION_CONTEXT_NAMESPACE = 'oauth2';
    
    const INITIATOR_TYPE_CONNECTION = 'connection';
    
    const INITIATOR_TYPE_AUTHENTICATOR = 'authenticator';
    
    /**
     * 
     * {@inheritDoc}
     * @see \exface\Core\Facades\AbstractHttpFacade\AbstractHttpFacade::getUrlRouteDefault()
     */
    public function getUrlRouteDefault(): string
    {
        return 'api/oauth2client';
    }
    
    /**
     * 
     * {@inheritDoc}
     * @see \exface\Core\Facades\AbstractHttpFacade\AbstractHttpFacade::createResponse($request)
     */
    protected function createResponse(ServerRequestInterface $request) : ResponseInterface
    {
        $path = $this->getUriPath($request);
        $user = $this->getWorkbench()->getSecurity()->getAuthenticatedUser();
        $authenticatedToken = null;
        $debug = [
            'workbench_user' => $user->getUsername()
        ];
        
        switch (true) {
            case StringDataType::startsWith($path, 'connection'):
                $requestToken = new OAuth2RequestToken($request, ($request->getQueryParams()['hash'] ?? ''), $this);
                $authProvider = DataConnectionFactory::createFromModel($this->getWorkbench(), StringDataType::substringAfter($path, 'connection/'));
                $debug['oauth_hash'] = $requestToken->getOAuthProviderHash();
                $debug['oauth_provider'] = $authProvider->getAliasWithNamespace();
                $this->getWorkbench()->getLogger()->debug('OAuth2 facade: URL-based start of connection for "' . $authProvider->getAliasWithNamespace() . '"', $debug);
                if ($user->isAnonymous()) {
                    throw new RuntimeException('Cannot save OAuth credentials without a user being logged on!');
                }
                $refreshedToken = $authProvider->authenticate($requestToken, true, $user, true);
                if ($refreshedToken) {
                    $redirect = $request->getHeader('referer')[0];
                }
                break;
            case StringDataType::startsWith($path, 'authenticate'):
                $requestToken = new OAuth2RequestToken($request, ($request->getQueryParams()['hash'] ?? ''), $this);
                $authProvider = $this->getWorkbench()->getSecurity();
                $debug['oauth_hash'] = $requestToken->getOAuthProviderHash();
                $debug['oauth_provider'] = 'Workbench security';
                $this->getWorkbench()->getLogger()->debug('OAuth2 facade: URL-based start of authentication via workbench security', $debug);
                $refreshedToken = $authProvider->authenticate($requestToken);
                if ($refreshedToken) {
                    $this->getWorkbench()->getLogger()->debug('OAuth2 facade: token refreshed for user "' . $refreshedToken->getUsername() . '"', $debug);
                    $redirect = $request->getHeader('referer')[0];
                }
                break;
            default:            
                $session = $this->getOAuthSession();
                $redirect = $session['redirect'];
                $requestToken = new OAuth2RequestToken($request, ($session['hash'] ?? ''), $this);
                $debug['oauth_session'] = $session;
                
                switch ($session['type']) {
                    case self::INITIATOR_TYPE_AUTHENTICATOR:
                        $debug['session_type'] = self::INITIATOR_TYPE_AUTHENTICATOR;
                        $debug['oauth_provider'] = 'Workbench security';
                        $this->getWorkbench()->getLogger()->debug('OAuth2 facade: session-based start of ' . $debug['session_type'], $debug);
                        $authProvider = $this->getWorkbench()->getSecurity();
                        try {
                            $authenticatedToken = $authProvider->authenticate($requestToken);
                        } catch (AuthenticationFailedError $e) {
                            $this->getWorkbench()->getLogger()->logException($e);
                        }
                        break;
                    case self::INITIATOR_TYPE_CONNECTION:
                        $debug['session_type'] = self::INITIATOR_TYPE_AUTHENTICATOR;
                        $this->getWorkbench()->getLogger()->debug('OAuth2 facade: session starting ' . $debug['session_type'] . ' "' . $session['selector'] . '" for user "' . $user->getUsername() . '"', $debug);
                        // TODO get the user from the Login action somehow!
                        if ($user->isAnonymous()) {
                            throw new RuntimeException('Cannot save OAuth credentials without a user being logged on!');
                        }
                        $authProvider = DataConnectionFactory::createFromModel($this->getWorkbench(), $session['selector']);
                        $debug['oauth_provider'] = $authProvider->getAliasWithNamespace();
                        try {
                            $authenticatedToken = $authProvider->authenticate($requestToken, true, $user, true);
                            $this->getWorkbench()->getLogger()->debug('OAuth2 facade: Authenticated user "' . $authenticatedToken->getUsername() . '"', $debug);
                        } catch (AuthenticationFailedError $e) {
                            $this->getWorkbench()->getLogger()->logException($e);
                        }
                        break;
                    default:
                        throw new RuntimeException('Invalid OAuth2 session type "' . $session['type'] . '"!');
                }
        }
        
        switch (true) {
            case $redirect:
                $debug['result'] = 'Redirecting to "' . $redirect . '"';
                $response = new Response(200, ['Location' => $redirect]);
                break;
            case $authenticatedToken instanceof OAuth2AuthenticatedToken:
                $debug['result'] = 'Authenticated user "' . $authenticatedToken->getUsername() . '". Closing window.';
                $response = new Response(200, [], $this->buildHtmlSuccess($authenticatedToken));
                break;
            default:
                $debug['result'] = 'ERROR, no redirect URL';
                $response = new Response(500, [], 'ERROR: cannot determine redirect URL!');
                break;
        }
        $this->getWorkbench()->getLogger()->debug('OAuth2 facade: ' . $debug['result'], $debug);
        return $response;
    }
    
    /**
     * 
     * @param ServerRequestInterface $request
     * @return string|NULL
     */
    protected function getUriPath(ServerRequestInterface $request) : ?string
    {
        $uri = $request->getUri()->getPath();
        return trim(StringDataType::substringAfter($uri, $this->buildUrlToFacade(true)), "/");
    }
    
    /**
     * 
     * {@inheritDoc}
     * @see \axenox\OAuth2Connector\Interfaces\OAuth2ClientFacadeInterface::startOAuthSession()
     */
    public function startOAuthSession(object $initiator, string $providerHash, string $redirect = null, array $vars = []) : OAuth2ClientFacadeInterface
    {
        $class = get_class($initiator);
        $sessionId = $this->getWorkbench()->getContext()->getScopeSession()->getScopeId();
        $this->getWorkbench()->getLogger()->debug('OAuth2 facade: starting OAuth session ' . $sessionId, [
            'session_id' => $sessionId,
            'initiator' => $class,
            'provider_hash' => $providerHash,
            'redirect' => $redirect, 
            'vars' => $vars
        ]);
        
        switch (true) {
            case $initiator instanceof DataConnectionInterface:
                $type = self::INITIATOR_TYPE_CONNECTION;
                $selector = $initiator->getAliasWithNamespace();
                break;
            case $initiator instanceof AuthenticatorInterface:
                $type = self::INITIATOR_TYPE_AUTHENTICATOR;
                $selector = get_class($initiator);
                break;
            default:
                throw new InvalidArgumentException('Cannot use ' . get_class($initiator) . ' as initiator of an OAuth2 session: only data connections or authenticators allowed!');
        }
        
        $this->getWorkbench()->getContext()->getScopeSession()->setVariable(self::SESSION_CONTEXT_NAMESPACE, [
            'type' => $type,
            'class' => $class,
            'selector' => $selector,
            'redirect' => $redirect,
            'hash' => $providerHash,
            'vars' => $vars
        ]);
        
        return $this;
    }
    
    /**
     * 
     * {@inheritDoc}
     * @see \axenox\OAuth2Connector\Interfaces\OAuth2ClientFacadeInterface::stopOAuthSession()
     */
    public function stopOAuthSession() : OAuth2ClientFacadeInterface
    {
        $sessionId = $this->getWorkbench()->getContext()->getScopeSession()->getScopeId();
        $this->getWorkbench()->getLogger()->debug('OAuth2 facade: stopping OAuth session ' . $sessionId, [
            'session_id' => $sessionId,
            'oauth_session' => $this->getWorkbench()->getContext()->getScopeSession()->getVariable(self::SESSION_CONTEXT_NAMESPACE)
        ]);
        $this->getWorkbench()->getContext()->getScopeSession()->unsetVariable(self::SESSION_CONTEXT_NAMESPACE);
        return $this;
    }
    
    /**
     * 
     * {@inheritDoc}
     * @see \axenox\OAuth2Connector\Interfaces\OAuth2ClientFacadeInterface::getOAuthSessionVars()
     */
    public function getOAuthSessionVars() : array
    {
        return $this->getOAuthSession()['vars'] ?? [];
    }
    
    /**
     * 
     * @throws OAuthSessionNotStartedException
     * @return array
     */
    protected function getOAuthSession() : array
    {
        $data = $this->getWorkbench()->getContext()->getScopeSession()->getVariable(self::SESSION_CONTEXT_NAMESPACE);
        $sessionId = $this->getWorkbench()->getContext()->getScopeSession()->getScopeId();
        $this->getWorkbench()->getLogger()->debug('OAuth2 facade: reading OAuth session ' . $sessionId, [
            'session_id' => $sessionId,
            'oauth_session' => $data
        ]);
        
        if (empty($data)) {
            throw new OAuthSessionNotStartedException('Cannot get OAuth2 session: no session was started!');
        }
        return $data;
    }
    
    public function buildUrlForProvider(AuthenticationProviderInterface $provider, string $hash, $relativeToSiteRoot = true) : string
    {
        $base = $this->buildUrlToFacade(! $relativeToSiteRoot);
        switch (true) {
            case $provider instanceof DataConnectionInterface:
                $path = '/connection/' . $provider->getAliasWithNamespace() . '?hash=' . $hash;
                break;
            case $provider instanceof HttpAuthenticationProviderInterface:
                $path = '/connection/' . $provider->getConnection()->getAliasWithNamespace() . '?hash=' . $hash;
                break;
            case $provider instanceof AuthenticatorInterface:
                $path = '/authenticate' . '?hash=' . $hash;
                break;
        }
        
        return $base . $path;
    }
    
    protected function buildHtmlSuccess(OAuth2AuthenticatedToken $authenticatedToken) : string
    {
        return <<<HTML
<!DOCTYPE html>
<html>
<head>
</head>
<body>
    <script>
        let token = "{$authenticatedToken->getAccessToken()}";
        if (window.opener && window.opener.parent) {
            window.opener.parent.oauthCallback(token);
        } else {
            window.parent.oauthCallback(token);
        }
        window.close();
    </script>
</body>
</html>
HTML;
    }
}