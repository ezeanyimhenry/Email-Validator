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
            'checkEmailExistence' => true,
            'checkMailServerResponsive' => true,
            'checkGreylisting' => true,
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

        // Check if email exists on the mail server
        if ($this->config['checkEmailExistence'] && !$this->checkEmailExistence($email)) {
            return [
                'isValid' => false,
                'message' => 'Email address does not exist.'
            ];
        }

        // Check if mail server is responsive
        if ($this->config['checkMailServerResponsive'] && !$this->isMailServerResponsive($email)) {
            return [
                'isValid' => false,
                'message' => 'Mail server is not responsive.'
            ];
        }

        // Check for greylisting
        if ($this->config['checkGreylisting'] && $this->isGreylisted($email)) {
            return [
                'isValid' => false,
                'message' => 'Email server is using greylisting.'
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

    // Check if the email exists by performing an SMTP RCPT TO check
    protected function checkEmailExistence($email)
    {
        $domain = substr(strrchr($email, "@"), 1);

        if (!checkdnsrr($domain, 'MX')) {
            return null; // Cannot check — no MX record
        }

        getmxrr($domain, $mxHosts);
        if (empty($mxHosts)) {
            return null;
        }

        $emailLocalPart = substr($email, 0, strpos($email, '@'));

        $smtpPorts = [25, 465, 587];
        $connected = false;
        $response = '';

        foreach ($mxHosts as $host) {
            foreach ($smtpPorts as $port) {
                $connection = @fsockopen($host, $port, $errno, $errstr, 5);

                if ($connection) {
                    $connected = true;
                    stream_set_timeout($connection, 5);
                    $this->smtpSend($connection, "HELO " . $domain);
                    $this->smtpSend($connection, "MAIL FROM:<check@" . $domain . ">");
                    $response = $this->smtpSend($connection, "RCPT TO:<$email>");
                    $this->smtpSend($connection, "QUIT");
                    fclose($connection);
                    break 2; // Stop if successful
                }
            }
        }

        if (!$connected) {
            return null; // Mail server is unreachable
        }

        // Interpret response
        if (preg_match('/^250|^220/', $response)) {
            return true; // Server accepted the address
        }

        if (preg_match('/^550/', $response)) {
            return false; // Address does not exist
        }

        return null; // Indeterminate
    }

    protected function smtpSend($connection, $cmd)
    {
        if (!is_resource($connection) || feof($connection)) {
            throw new \RuntimeException("SMTP connection is not valid or has been closed.");
        }

        $writeResult = @fwrite($connection, $cmd . "\r\n");

        if ($writeResult === false) {
            throw new \RuntimeException("Failed to write command to SMTP server (possibly broken pipe).");
        }

        $response = fgets($connection, 1024);

        if ($response === false) {
            throw new \RuntimeException("No response from SMTP server after sending command: $cmd");
        }

        return $response;
    }


    // Check if the mail server is responsive
    protected function isMailServerResponsive($email)
    {
        $domain = substr(strrchr($email, "@"), 1);
        $mxRecords = dns_get_record($domain, DNS_MX);

        if (empty($mxRecords)) {
            return false;  // No MX records, mail server unresponsive
        }

        $mxServer = $mxRecords[0]['target'];
        $port = 25;

        $connection = @fsockopen($mxServer, $port, $errno, $errstr, 10);

        return $connection ? true : false;
    }

    // Check for greylisting by analyzing the SMTP response
    protected function isGreylisted($email)
    {
        $domain = substr(strrchr($email, "@"), 1);
        $mxRecords = dns_get_record($domain, DNS_MX);

        if (empty($mxRecords)) {
            return false;  // No MX records, cannot verify greylisting
        }

        $mxServer = $mxRecords[0]['target'];
        $port = 25;

        $connection = fsockopen($mxServer, $port, $errno, $errstr, 10);

        if (!$connection) {
            return false;  // Unable to connect to the mail server
        }

        // Send EHLO command and RCPT TO command
        fwrite($connection, "EHLO " . $mxServer . "\r\n");
        fgets($connection, 1024);

        fwrite($connection, "MAIL FROM:<test@example.com>\r\n");
        fgets($connection, 1024);

        fwrite($connection, "RCPT TO:<$email>\r\n");
        $response = fgets($connection, 1024);

        fclose($connection);

        // Greylisting is usually indicated by a 450 temporary error code
        return strpos($response, '450') !== false;
    }
}