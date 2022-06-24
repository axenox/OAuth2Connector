<?php
namespace axenox\OAuth2Connector\Exceptions;

use exface\Core\Exceptions\Security\AuthenticationRuntimeError;
use exface\Core\Interfaces\Security\AuthenticationProviderInterface;
use exface\Core\Interfaces\Exceptions\AuthenticationExceptionInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use exface\Core\Widgets\DebugMessage;
use exface\Core\CommonLogic\Debugger\HttpMessageDebugWidgetRenderer;

/**
 * 
 * @author andrej.kabachnik
 *
 */
class OAuthHttpException extends AuthenticationRuntimeError implements AuthenticationExceptionInterface
{
    private $request = null;
    
    private $response = null;
    
    /**
     * 
     * @param AuthenticationProviderInterface $authProvider
     * @param string $message
     * @param string|NULL $alias
     * @param \Throwable|NULL $previous
     * @param RequestInterface|NULL $psr7Request
     * @param ResponseInterface|NULL $psr7Response
     */
    public function __construct(AuthenticationProviderInterface $authProvider, $message, $alias = null, $previous = null, RequestInterface $psr7Request = null, ResponseInterface $psr7Response = null)
    {
        parent::__construct($authProvider, $message, $alias, $previous);
        $this->request = $psr7Request;
        $this->response = $psr7Response;
    }
    
    /**
     *
     * {@inheritDoc}
     * @see \exface\Core\Interfaces\Exceptions\AuthenticationExceptionInterface::getAuthenticationProvider()
     */
    public function getAuthenticationProvider() : AuthenticationProviderInterface
    {
        return $this->provider;
    }
    
    /**
     * 
     * @return RequestInterface|NULL
     */
    public function getRequest() : ?RequestInterface
    {
        return $this->request;
    }
    
    /**
     * 
     * @return ResponseInterface|NULL
     */
    public function getResponse() : ?ResponseInterface
    {
        return $this->response;
    }
    
    /**
     *
     * {@inheritDoc}
     * @see \exface\Core\CommonLogic\DataQueries\AbstractDataQuery::createDebugWidget()
     */
    public function createDebugWidget(DebugMessage $debug_widget)
    {
        if (null !== $request = $this->getRequest()) {
            $renderer = new HttpMessageDebugWidgetRenderer($request, $this->getResponse(), 'OAuth2 request', 'OAuth2 response');
            $debug_widget = $renderer->createDebugWidget($debug_widget);
        }
        
        return $debug_widget;
    }
}