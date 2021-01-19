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

/**
 * 
 * @author Andrej Kabachnik
 *
 */
class OAuth2ClientFacade extends AbstractHttpFacade
{
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
        $authProvider = $this->getAuthenticationProvider($request);
        $requestToken = new OAuth2RequestToken($request, $this);
        $authProvider->authenticate($requestToken);
        return new Response();
    }
    
    protected function getAuthenticationProvider(ServerRequestInterface $request)
    {
        if ($connection = $this->getDataConnection($request)) {
            return $connection;
        } else {
            // TODO
        }
    }
    
    protected function getDataConnection(ServerRequestInterface $request) : ?DataConnectionInterface
    {
        $uri = $request->getUri()->__toString();
        $path = trim(StringDataType::substringAfter($uri, $this->buildUrlToFacade()), "/");
        if ($path) {
            return DataConnectionFactory::createFromModel($this->getWorkbench(), $path);
        }
        return null;
    }
}