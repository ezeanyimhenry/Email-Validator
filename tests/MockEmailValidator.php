<?php

namespace EzeanyimHenry\EmailValidator\Tests;

use EzeanyimHenry\EmailValidator\EmailValidator;

class MockEmailValidator extends EmailValidator
{
    protected $mockResponses = [];
    protected $mockDomainResponses = [];

    /**
     * Set a mock response for a specific method
     *
     * @param string $method The method name to mock
     * @param mixed $value The value to return
     * @return void
     */
    public function setMockResponse(string $method, $value): void
    {
        $this->mockResponses[$method] = $value;
    }

    /**
     * Set a mock response for a specific method and domain
     *
     * @param string $domain The domain to mock for
     * @param string $method The method name to mock
     * @param mixed $value The value to return
     * @return void
     */
    public function setMockResponseForDomain(string $domain, string $method, $value): void
    {
        if (!isset($this->mockDomainResponses[$domain])) {
            $this->mockDomainResponses[$domain] = [];
        }
        $this->mockDomainResponses[$domain][$method] = $value;
    }

    /**
     * Set banned email domains for testing
     *
     * @param array $domains List of banned domains
     * @return void
     */
    public function setBannedEmailDomains(array $domains): void
    {
        $this->bannedEmailDomains = $domains;
    }

    /**
     * Set disposable email domains for testing
     *
     * @param array $domains List of disposable domains
     * @return void
     */
    public function setDisposableEmailDomains(array $domains): void
    {
        $this->disposableEmailDomains = $domains;
    }

    /**
     * Set free email domains for testing
     *
     * @param array $domains List of free email domains
     * @return void
     */
    public function setFreeEmailDomains(array $domains): void
    {
        $this->freeEmailDomains = $domains;
    }

    /**
     * Extract domain from email address
     *
     * @param string $email The email address
     * @return string The domain part
     */
    protected function getDomain(string $email): string
    {
        $parts = explode('@', $email);
        return $parts[1] ?? '';
    }

    /**
     * Get mock response for a specific domain and method
     *
     * @param string $email The email address
     * @param string $method The method name
     * @return mixed|null The mock response or null if not set
     */
    protected function getDomainMockResponse(string $email, string $method)
    {
        $domain = $this->getDomain($email);
        if (isset($this->mockDomainResponses[$domain]) && array_key_exists($method, $this->mockDomainResponses[$domain])) {
            return $this->mockDomainResponses[$domain][$method];
        }
        return null;
    }

    /**
     * Override parent method to use mock responses
     */
    protected function checkEmailExistence($email, $smtpConnection = null)
    {
        $domainResponse = $this->getDomainMockResponse($email, 'checkEmailExistence');
        if ($domainResponse !== null) {
            return $domainResponse;
        }
        if (array_key_exists('checkEmailExistence', $this->mockResponses)) {
            return $this->mockResponses['checkEmailExistence'];
        }
        return parent::checkEmailExistence($email, $smtpConnection);
    }

    /**
     * Override parent method to use mock responses
     */
    protected function checkMxRecords($email)
    {
        $domainResponse = $this->getDomainMockResponse($email, 'checkMxRecords');
        if ($domainResponse !== null) {
            return $domainResponse;
        }
        if (array_key_exists('checkMxRecords', $this->mockResponses)) {
            return $this->mockResponses['checkMxRecords'];
        }
        return parent::checkMxRecords($email);
    }

    /**
     * Override parent method to use mock responses
     */
    protected function isMailServerResponsive($email)
    {
        $domainResponse = $this->getDomainMockResponse($email, 'isMailServerResponsive');
        if ($domainResponse !== null) {
            return $domainResponse;
        }
        if (array_key_exists('isMailServerResponsive', $this->mockResponses)) {
            return $this->mockResponses['isMailServerResponsive'];
        }
        return parent::isMailServerResponsive($email);
    }

    /**
     * Override parent method to use mock responses
     */
    protected function isGreylisted($email)
    {
        $domainResponse = $this->getDomainMockResponse($email, 'isGreylisted');
        if ($domainResponse !== null) {
            return $domainResponse;
        }
        if (array_key_exists('isGreylisted', $this->mockResponses)) {
            return $this->mockResponses['isGreylisted'];
        }
        return parent::isGreylisted($email);
    }

    /**
     * Override parent method to use mock responses
     */
    protected function isCatchAllDomain($smtpConnection, $domain)
    {
        // Check for domain-specific mock first
        if (
            isset($this->mockDomainResponses[$domain]) &&
            array_key_exists('isCatchAllDomain', $this->mockDomainResponses[$domain])
        ) {
            return $this->mockDomainResponses[$domain]['isCatchAllDomain'];
        }

        // Then check for general mock
        if (array_key_exists('isCatchAllDomain', $this->mockResponses)) {
            return $this->mockResponses['isCatchAllDomain'];
        }

        return parent::isCatchAllDomain($smtpConnection, $domain);
    }

    /**
     * Override validateSingle to correctly handle catch-all domain testing
     */
    protected function validateSingle($email, $smtpConnection = null, $isCatchAll = null)
    {
        $domain = substr(strrchr($email, "@"), 1);

        // Handle domain-specific catch-all mock if available
        if ($this->config['checkCatchAll'] && $isCatchAll === null) {
            if (
                isset($this->mockDomainResponses[$domain]) &&
                array_key_exists('isCatchAllDomain', $this->mockDomainResponses[$domain])
            ) {
                $isCatchAll = $this->mockDomainResponses[$domain]['isCatchAllDomain'];
            } elseif (array_key_exists('isCatchAllDomain', $this->mockResponses)) {
                $isCatchAll = $this->mockResponses['isCatchAllDomain'];
            }
        }

        return parent::validateSingle($email, $smtpConnection, $isCatchAll);
    }

    /**
     * Override validateMultiple to use domain-specific mock responses for catch-all checks
     */
    protected function validateMultiple(array $emails)
    {
        $results = [];

        // Group emails by domain
        $grouped = [];
        foreach ($emails as $email) {
            if (!strpos($email, '@')) {
                // Handle invalid email format
                $results[$email] = $this->validateSingle($email);
                continue;
            }

            $domain = substr(strrchr($email, "@"), 1);
            $grouped[$domain][] = $email;
        }

        foreach ($grouped as $domain => $emailList) {
            $mxHosts = $this->getMxHosts($domain);
            $smtpResource = null;

            // Use domain-specific mock for catch-all if available
            $catchAll = null;
            if ($this->config['checkCatchAll']) {
                if (
                    isset($this->mockDomainResponses[$domain]) &&
                    array_key_exists('isCatchAllDomain', $this->mockDomainResponses[$domain])
                ) {
                    $catchAll = $this->mockDomainResponses[$domain]['isCatchAllDomain'];
                } elseif (array_key_exists('isCatchAllDomain', $this->mockResponses)) {
                    $catchAll = $this->mockResponses['isCatchAllDomain'];
                } elseif (!empty($mxHosts) && ($smtpResource = $this->smtpConnect($mxHosts))) {
                    $catchAll = $this->isCatchAllDomain($smtpResource, $domain);
                }
            }

            foreach ($emailList as $email) {
                $results[$email] = $this->validateSingle($email, $smtpResource, $catchAll);
            }

            if ($smtpResource && is_resource($smtpResource)) {
                fwrite($smtpResource, "QUIT\r\n");
                fclose($smtpResource);
            }
        }

        return $results;
    }
}