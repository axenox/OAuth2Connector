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
use exface\Core\Exceptions\Facades\FacadeRuntimeError;
use exface\Core\Exceptions\Security\AuthenticationFailedError;

/**
 * 
 * @author Andrej Kabachnik
 *
 */
class OAuth2ClientFacade extends AbstractHttpFacade
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
        
        if (! $authProvider = $this->getDataConnection($request)) {
            $sessions = $this->getOAuthSessions();
            if (empty($sessions)) {
                throw new FacadeRuntimeError('No pending OAuth2 sessions found!');
            }
            
            $redirect = null;
            foreach ($sessions as $sessionData) {
                switch ($sessionData['type']) {
                    case self::INITIATOR_TYPE_AUTHENTICATOR:
                        // TODO
                        break;
                    case self::INITIATOR_TYPE_CONNECTION:
                        $connection = DataConnectionFactory::createFromModel($this->getWorkbench(), $sessionData['selector']);
                        if ($connection->isOAuthInitiator($requestToken, $sessionData['vars'])) {
                            $authProvider = $connection;
                            $redirect = $sessionData['redirect'];
                            
                            try {
                                $connection->authenticate($requestToken, true, $this->getWorkbench()->getSecurity()->getAuthenticatedUser(), true);
                            } catch (AuthenticationFailedError $e) {
                                $this->getWorkbench()->getLogger()->logException($e);
                            }
                            
                            break 2;
                        }
                        break;
                    default:
                        throw new RuntimeException('Invalid OAuth2 session type "' . $sessionData['type'] . '"!');
                }
            }
        }
        
        // TODO detect broken sessions (state mismatch) and remove them!
        
        if (! $authProvider) {
            throw new FacadeRuntimeError('No OAuth2 session found for current request!');
        }
        
        $redirect = $redirect ? $redirect : $this->getWorkbench()->getUrl();
        
        return new Response(200, ['Location' => $redirect]);
    }
    
    protected function getDataConnection(ServerRequestInterface $request) : ?DataConnectionInterface
    {
        if ($path = $this->getUriPath($request)) {
            return DataConnectionFactory::createFromModel($this->getWorkbench(), $path);
        }
        return null;
    }
    
    protected function getUriPath(ServerRequestInterface $request) : ?string
    {
        $uri = $request->getUri()->getPath();
        return trim(StringDataType::substringAfter($uri, $this->buildUrlToFacade(true)), "/");
    }
    
    public function addOAuthSession(string $id, object $initiator, string $redirect, array $vars = []) : OAuth2ClientFacade
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
        
        $sessionScope = $this->getWorkbench()->getContext()->getScopeSession();
        
        $sessionData = $sessionScope->getVariable(self::SESSION_CONTEXT_NAMESPACE) ?? [];
        $sessionData[$id] = [
            'type' => $type,
            'class' => $class,
            'selector' => $selector,
            'redirect' => $redirect,
            'vars' => $vars
        ];
        $sessionScope->setVariable(self::SESSION_CONTEXT_NAMESPACE, $sessionData);
        
        return $this;
    }
    
    public function clearOAuthSession(string $id) : OAuth2ClientFacade
    {
        $sessionScope = $this->getWorkbench()->getContext()->getScopeSession();
        $vars = $sessionScope->getVariable(self::SESSION_CONTEXT_NAMESPACE) ?? [];
        unset($vars[$id]);
        $sessionScope->setVariable(self::SESSION_CONTEXT_NAMESPACE, $vars);
    }
    
    protected function getOAuthSessions() : array
    {
        return $this->getWorkbench()->getContext()->getScopeSession()->getVariable(self::SESSION_CONTEXT_NAMESPACE) ?? [];
    }
}