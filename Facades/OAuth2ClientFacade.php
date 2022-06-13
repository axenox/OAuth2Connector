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
        
        switch (true) {
            case StringDataType::startsWith($path, 'connection'):
                $requestToken = new OAuth2RequestToken($request, ($request->getQueryParams()['hash'] ?? ''), $this);
                $authProvider = DataConnectionFactory::createFromModel($this->getWorkbench(), StringDataType::substringAfter($path, 'connection/'));
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
                $refreshedToken = $authProvider->authenticate($requestToken);
                if ($refreshedToken) {
                    $redirect = $request->getHeader('referer')[0];
                }
                break;
            default:            
                $session = $this->getOAuthSession();
                $redirect = $session['redirect'];
                $requestToken = new OAuth2RequestToken($request, ($session['hash'] ?? ''), $this);
                
                switch ($session['type']) {
                    case self::INITIATOR_TYPE_AUTHENTICATOR:
                        $authProvider = $this->getWorkbench()->getSecurity();
                        try {
                            $authProvider->authenticate($requestToken);
                        } catch (AuthenticationFailedError $e) {
                            $this->getWorkbench()->getLogger()->logException($e);
                        }
                        break;
                    case self::INITIATOR_TYPE_CONNECTION:
                        // TODO get the user from the Login action somehow!
                        if ($user->isAnonymous()) {
                            throw new RuntimeException('Cannot save OAuth credentials without a user being logged on!');
                        }
                        $authProvider = DataConnectionFactory::createFromModel($this->getWorkbench(), $session['selector']);
                        try {
                            $authProvider->authenticate($requestToken, true, $user, true);
                        } catch (AuthenticationFailedError $e) {
                            $this->getWorkbench()->getLogger()->logException($e);
                        }
                        break;
                    default:
                        throw new RuntimeException('Invalid OAuth2 session type "' . $session['type'] . '"!');
                }
        }
        
        if ($redirect) {
            return new Response(200, ['Location' => $redirect]);
        } else {
            return new Response(500, [], 'ERROR: cannot determine redirect URL!');
        }
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
        $class = get_class($initiator);
        
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
}