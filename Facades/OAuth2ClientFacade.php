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
     * @see \Psr\Http\Server\RequestHandlerInterface::handle()
     */
    public function handle(ServerRequestInterface $request) : ResponseInterface
    {
        $requestToken = new OAuth2RequestToken($request, $this);
        
        $path = $this->getUriPath($request);
        
        if ($path) {
            $authProvider = DataConnectionFactory::createFromModel($this->getWorkbench(), $path);
            $authProvider->authenticate($requestToken);
        } else {
            $session = $this->getOAuthSession();
            $redirect = $session['redirect'];
            
            switch ($session['type']) {
                case self::INITIATOR_TYPE_AUTHENTICATOR:
                    // TODO
                    break;
                case self::INITIATOR_TYPE_CONNECTION:
                    $authProvider = DataConnectionFactory::createFromModel($this->getWorkbench(), $session['selector']);
                    try {
                        $authProvider->authenticate($requestToken, true, $this->getWorkbench()->getSecurity()->getAuthenticatedUser(), true);
                    } catch (AuthenticationFailedError $e) {
                        $this->getWorkbench()->getLogger()->logException($e);
                    }
                    break;
                default:
                    throw new RuntimeException('Invalid OAuth2 session type "' . $session['type'] . '"!');
            }
        }
        
        $redirect = $redirect ? $redirect : $this->getWorkbench()->getUrl();
        
        return new Response(200, ['Location' => $redirect]);
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
    public function startOAuthSession(object $initiator, string $redirect, array $vars = []) : OAuth2ClientFacadeInterface
    {
        switch (true) {
            case $initiator instanceof DataConnectionInterface:
                $type = self::INITIATOR_TYPE_CONNECTION;
                $selector = $initiator->getAliasWithNamespace();
                break;
            case $initiator instanceof AuthenticatorInterface:
                $type = self::INITIATOR_TYPE_AUTHENTICATOR;
                $selector = get_class($selector);
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
}