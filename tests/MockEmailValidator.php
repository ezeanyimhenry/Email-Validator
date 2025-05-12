<?php

namespace EzeanyimHenry\EmailValidator\Tests;

use EzeanyimHenry\EmailValidator\EmailValidator;

class MockEmailValidator extends EmailValidator
{
    protected $mockResponses = [];

    public function setMockResponse(string $method, $value): void
    {
        $this->mockResponses[$method] = $value;
    }

    public function setBannedEmailDomains(array $domains): void
    {
        $this->bannedEmailDomains = $domains;
    }

    public function setDisposableEmailDomains(array $domains): void
    {
        $this->disposableEmailDomains = $domains;
    }

    public function setFreeEmailDomains(array $domains): void
    {
        $this->freeEmailDomains = $domains;
    }

    protected function checkEmailExistence($email)
    {
        return $this->mockResponses['checkEmailExistence'] ?? parent::checkEmailExistence($email);
    }

    protected function checkMxRecords($email)
    {
        return $this->mockResponses['checkMxRecords'] ?? parent::checkMxRecords($email);
    }

    protected function isMailServerResponsive($email)
    {
        return $this->mockResponses['isMailServerResponsive'] ?? parent::isMailServerResponsive($email);
    }

    protected function isGreylisted($email)
    {
        return $this->mockResponses['isGreylisted'] ?? parent::isGreylisted($email);
    }
}