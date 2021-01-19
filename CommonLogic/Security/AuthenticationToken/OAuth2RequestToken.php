<?php
namespace axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken;

use exface\Core\Interfaces\Facades\FacadeInterface;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;
use exface\Core\Interfaces\Facades\HttpFacadeInterface;
use Psr\Http\Message\ServerRequestInterface;

class OAuth2RequestToken implements AuthenticationTokenInterface
{
    private $facade = null;
    
    private $request = null;
    
    /**
     * 
     * @param HttpFacadeInterface $facade
     */
    public function __construct(ServerRequestInterface $request, HttpFacadeInterface $facade = null)
    {
        $this->facade = $facade;
        $this->request = $request;
    }
    
    public function isAnonymous(): bool
    {
        return true;
    }

    public function getFacade(): ?FacadeInterface
    {
        return $this->facade;
    }

    public function getUsername(): ?string
    {
        return null;
    }
    
    public function getRequest() : ServerRequestInterface
    {
        return $this->request;
    }
}