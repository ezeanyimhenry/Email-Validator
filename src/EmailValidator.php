<?php

namespace EzeanyimHenry\EmailValidator;

use InvalidArgumentException;

class EmailValidator
{
    protected $config;

    public function __construct(array $config = [])
    {
        // Default settings, can be overridden by the config array
        $this->config = array_merge([
            'checkMxRecords' => true,
            'checkBannedListedEmail' => true,
            'checkDisposableEmail' => true,
            'checkFreeEmail' => false,
        ], $config);
    }

    // Validate single or multiple emails
    public function validate($emails)
    {
        if (is_array($emails)) {
            return $this->validateMultiple($emails);
        }

        return $this->validateSingle($emails);
    }

    // Validate multiple emails and return results as an array
    protected function validateMultiple(array $emails)
    {
        $results = [];
        foreach ($emails as $email) {
            $results[$email] = $this->validateSingle($email);
        }
        return $results;
    }

    // Validate a single email
    protected function validateSingle($email)
    {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return false; // Invalid email format
        }

        if ($this->config['checkMxRecords'] && !$this->checkMxRecords($email)) {
            return false; // Invalid MX records
        }

        if ($this->config['checkBannedListedEmail'] && $this->isBannedEmail($email)) {
            return false; // Email is on a banned list
        }

        if ($this->config['checkDisposableEmail'] && $this->isDisposableEmail($email)) {
            return false; // Disposable email detected
        }

        if ($this->config['checkFreeEmail'] && $this->isFreeEmail($email)) {
            return false; // Free email detected
        }

        return true; // Valid email
    }

    // Check if email domain has valid MX records
    protected function checkMxRecords($email)
    {
        $domain = substr(strrchr($email, "@"), 1);
        return checkdnsrr($domain, 'MX');
    }

    // Example: check against banned domains or emails
    protected function isBannedEmail($email)
    {
        $bannedDomains = ['banned.com', 'spamdomain.com'];
        $domain = substr(strrchr($email, "@"), 1);
        return in_array($domain, $bannedDomains);
    }

    // Example: check if the email is from a disposable email provider
    protected function isDisposableEmail($email)
    {
        $disposableDomains = ['mailinator.com', '10minutemail.com'];
        $domain = substr(strrchr($email, "@"), 1);
        return in_array($domain, $disposableDomains);
    }

    // Example: check if the email is a free email provider (like Gmail, Yahoo)
    protected function isFreeEmail($email)
    {
        $freeEmailDomains = ['gmail.com', 'yahoo.com', 'hotmail.com'];
        $domain = substr(strrchr($email, "@"), 1);
        return in_array($domain, $freeEmailDomains);
    }
}
