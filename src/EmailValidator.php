<?php

namespace EzeanyimHenry\EmailValidator;

use InvalidArgumentException;

class EmailValidator
{
    protected $config;
    protected $freeEmailDomains;
    protected $disposableEmailDomains;
    protected $bannedEmailDomains;

    public function __construct(array $config = [])
    {
        // Load email domain lists
        $this->freeEmailDomains = include __DIR__ . '/../config/free_email_domains.php';
        $this->disposableEmailDomains = include __DIR__ . '/../config/disposable_email_domains.php';
        $this->bannedEmailDomains = include __DIR__ . '/../config/banned_email_domains.php';
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

    // Validate a single email and return a detailed result with messages
    protected function validateSingle($email)
    {
        // Check if email format is valid
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return [
                'isValid' => false,
                'message' => 'Invalid email format.'
            ];
        }

        // Check MX records
        if ($this->config['checkMxRecords'] && !$this->checkMxRecords($email)) {
            return [
                'isValid' => false,
                'message' => 'MX records do not exist for this email domain.'
            ];
        }

        // Check if email is on a banned list
        if ($this->config['checkBannedListedEmail'] && $this->isBannedEmail($email)) {
            return [
                'isValid' => false,
                'message' => 'The email domain is on the banned list.'
            ];
        }

        // Check if email is from a disposable email provider
        if ($this->config['checkDisposableEmail'] && $this->isDisposableEmail($email)) {
            return [
                'isValid' => false,
                'message' => 'Disposable email detected.'
            ];
        }

        // Check if email is from a free email provider (e.g., Gmail)
        if ($this->config['checkFreeEmail'] && $this->isFreeEmail($email)) {
            return [
                'isValid' => false,
                'message' => 'Email belongs to a free email provider.'
            ];
        }

        // Return success if all checks pass
        return [
            'isValid' => true,
            'message' => 'The email is valid.'
        ];
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
        $domain = substr(strrchr($email, "@"), 1);
        return in_array($domain, $this->bannedEmailDomains);
    }

    // Example: check if the email is from a disposable email provider
    protected function isDisposableEmail($email)
    {
        $domain = substr(strrchr($email, "@"), 1);
        return in_array($domain, $this->disposableEmailDomains);
    }

    // Example: check if the email is a free email provider (like Gmail, Yahoo)
    protected function isFreeEmail($email)
    {
        $domain = substr(strrchr($email, "@"), 1);
        return in_array($domain, $this->freeEmailDomains);
    }
}
