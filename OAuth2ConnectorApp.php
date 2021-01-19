<?php
namespace axenox\OAuth2Connector;

use exface\Core\Interfaces\InstallerInterface;
use exface\Core\CommonLogic\Model\App;
use exface\Core\Facades\AbstractHttpFacade\HttpFacadeInstaller;
use exface\Core\Factories\FacadeFactory;
use axenox\OAuth2Connector\Facades\OAuth2ClientFacade;

class OAuth2ConnectorApp extends App
{
    /**
     * 
     * {@inheritDoc}
     * @see \exface\Core\CommonLogic\Model\App::getInstaller()
     */
    public function getInstaller(InstallerInterface $injected_installer = null)
    {
        $installer = parent::getInstaller($injected_installer);
        
        $tplInstaller = new HttpFacadeInstaller($this->getSelector());
        $tplInstaller->setFacade(FacadeFactory::createFromString(OAuth2ClientFacade::class, $this->getWorkbench()));
        $installer->addInstaller($tplInstaller);
        
        return $installer;
    }
}