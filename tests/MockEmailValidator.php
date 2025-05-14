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
        return array_key_exists('checkEmailExistence', $this->mockResponses)
            ? $this->mockResponses['checkEmailExistence']
            : parent::checkEmailExistence($email);
    }

    protected function checkMxRecords($email)
    {
        return array_key_exists('checkMxRecords', $this->mockResponses)
            ? $this->mockResponses['checkMxRecords']
            : parent::checkMxRecords($email);
    }

    protected function isMailServerResponsive($email)
    {
        return array_key_exists('isMailServerResponsive', $this->mockResponses)
            ? $this->mockResponses['isMailServerResponsive']
            : parent::isMailServerResponsive($email);
    }

    protected function isGreylisted($email)
    {
        return array_key_exists('isGreylisted', $this->mockResponses)
            ? $this->mockResponses['isGreylisted']
            : parent::isGreylisted($email);
    }
}