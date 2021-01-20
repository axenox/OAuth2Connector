<?php
namespace axenox\OAuth2Connector\Interfaces;

use exface\Core\Interfaces\Facades\HttpFacadeInterface;

/**
 * 
 * @author Andrej Kabachnik
 *
 */
interface OAuth2ClientFacadeInterface extends HttpFacadeInterface
{
    /**
     * 
     * @param object $initiator
     * @param string $redirect
     * @param array $vars
     * @return OAuth2ClientFacadeInterface
     */
    public function startOAuthSession(object $initiator, string $redirect, array $vars = []) : OAuth2ClientFacadeInterface;
    
    /**
     * 
     * @return OAuth2ClientFacadeInterface
     */
    public function stopOAuthSession() : OAuth2ClientFacadeInterface;
    
    /**
     * 
     * @return array
     */
    public function getOAuthSessionVars() : array;
}