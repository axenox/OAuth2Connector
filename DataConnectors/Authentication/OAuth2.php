<?php
namespace axenox\OAuth2Connector\DataConnectors\Authentication;

use exface\Core\CommonLogic\UxonObject;
use exface\UrlDataConnector\Interfaces\UrlConnectionInterface;
use exface\Core\CommonLogic\Traits\ImportUxonObjectTrait;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;
use exface\Core\Interfaces\Widgets\iContainOtherWidgets;
use exface\UrlDataConnector\Facades\OAuth2ClientFacade;
use exface\Core\Factories\FacadeFactory;
use exface\UrlDataConnector\Interfaces\HttpAuthenticationProviderInterface;

class OAuth2 implements HttpAuthenticationProviderInterface
{
    use ImportUxonObjectTrait;
    
    private $connection = null;
    
    private $clientId = null;
    
    private $clientSecret = null;
    
    private $scope = null;
    
    private $authorizationPageUrl = null;
    
    private $clientFacade = null;
    
    /**
     * 
     * @param UrlConnectionInterface $dataConnection
     * @param UxonObject $uxon
     */
    public function __construct(UrlConnectionInterface $dataConnection, UxonObject $uxon = null)
    {
        $this->connection = $dataConnection;
        if ($uxon !== null) {
            $this->importUxonObject($uxon, ['class']);
        }
    }
    
    /**
     * 
     * {@inheritDoc}
     * @see \exface\Core\Interfaces\iCanBeConvertedToUxon::exportUxonObject()
     */
    public function exportUxonObject()
    {
        return new UxonObject();
    }
    
    /**
     * 
     * {@inheritDoc}
     * @see \exface\Core\Interfaces\Security\AuthenticationProviderInterface::authenticate()
     */
    public function authenticate(AuthenticationTokenInterface $token) : AuthenticationTokenInterface
    {
        // TODO
        return $token;
    }
    
    /**
     * 
     * {@inheritDoc}
     * @see \exface\Core\Interfaces\Security\AuthenticationProviderInterface::createLoginWidget()
     */
    public function createLoginWidget(iContainOtherWidgets $container) : iContainOtherWidgets
    {
        $container->setWidgets(new UxonObject([
            [
                'widget_type' => 'browser',
                'url' => $this->getAuthorizationPageUrl(),
                'height' => '400px',
                'width' => '400px'
            ]
        ]));
        return $container;
    }
    
    /**
     * 
     * @return string
     */
    protected function getAuthorizationPageUrl() : string
    {
        return $this->authorizationPageUrl . (strpos($this->authorizationPageUrl, '?') === false ? '?' : '') . '&client_id=' . $this->getClientId() . '&state=' . $this->getState() . '&redirect_uri=' . urlencode($this->getRedirectUrl());
    }
    
    /**
     * URL to send the user to for authorization
     * 
     * @uxon-property authorization_page_url
     * @uxon-type uri
     * @uxon-required true
     * 
     * @param string $value
     * @return OAuth2
     */
    public function setAuthorizationPageUrl(string $value) : OAuth2
    {
        $this->authorizationPageUrl = $value;
        return $this;
    }
    
    /**
     * 
     * @return string
     */
    protected function getClientId() : string
    {
        return $this->clientId;
    }
    
    /**
     * OAuth client ID
     * 
     * @uxon-property client_id
     * @uxon-type string
     * @uxon-required true
     * 
     * @param string $value
     * @return OAuth2
     */
    public function setClientId(string $value) : OAuth2
    {
        $this->clientId = $value;
        return $this;
    }
    
    protected function getClientSecret() : string
    {
        return $this->clientSecret;
    }
    
    /**
     * OAuth client secret
     *
     * @uxon-property client_secret
     * @uxon-type string
     * @uxon-required true
     *
     * @param string $value
     * @return OAuth2
     */
    public function setClientSecret(string $value) : OAuth2
    {
        $this->clientSecret = $value;
        return $this;
    }
    
    /**
     * 
     * @return string
     */
    protected function getState() : string
    {
        return uniqid(null, true);
    }
    
    /**
     * 
     * @return UrlConnectionInterface
     */
    protected function getConnection() : UrlConnectionInterface
    {
        return $this->connection;
    }
    
    /**
     * 
     * @return OAuth2ClientFacade
     */
    protected function getClientFacade() : OAuth2ClientFacade
    {
        if ($this->clientFacade === null) {
            $this->clientFacade = FacadeFactory::createFromString(OAuth2ClientFacade::class, $this->getConnection()->getWorkbench());;
        }
        return $this->clientFacade;
    }
    
    /**
     * 
     * @return string
     */
    protected function getRedirectUrl() : string
    {
        return $this->getClientFacade()->buildUrlToFacade(false);
    }
    
    /**
     * 
     * {@inheritDoc}
     * @see \exface\Core\Interfaces\WorkbenchDependantInterface::getWorkbench()
     */
    public function getWorkbench()
    {
        return $this->connection->getWorkbench();
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
     * @see \exface\UrlDataConnector\Interfaces\HttpAuthenticationProviderInterface::getCredentialsUxon()
     */
    public function getCredentialsUxon(AuthenticationTokenInterface $authenticatedToken): UxonObject
    {
        return new UxonObject([
            'authentication' => [
                'class' => '\\' . get_class($this)
            ]
        ]);
    }

}