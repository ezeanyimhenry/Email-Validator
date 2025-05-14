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
            'checkEmailExistence' => false,
            'checkMailServerResponsive' => false,
            'checkGreylisting' => false,
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
        $report = [];

        // Format check
        $isValidFormat = filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
        $report['format'] = [
            'status' => $isValidFormat,
            'message' => $isValidFormat ? 'Valid email format.' : 'Invalid email format.'
        ];

        // If the format is invalid, we can't continue with other checks
        if (!$isValidFormat) {
            return [
                'isValid' => false,
                'message' => 'Invalid email format.',
                'report' => $report
            ];
        }

        $domain = substr(strrchr($email, "@"), 1);

        // MX Records check
        if ($this->config['checkMxRecords']) {
            $mx = $this->checkMxRecords($email);
            $report['mxRecords'] = [
                'status' => $mx,
                'message' => $mx ? 'MX records found.' : 'MX records not found.'
            ];
        } else {
            $report['mxRecords'] = [
                'status' => true,
                'message' => 'MX records check disabled.'
            ];
        }

        // Banned domain check
        if ($this->config['checkBannedListedEmail']) {
            $isBanned = $this->isBannedEmail($email);
            $report['bannedList'] = [
                'status' => !$isBanned,
                'message' => !$isBanned ? 'Not on banned list.' : 'The email domain is on the banned list.'
            ];
        } else {
            $report['bannedList'] = [
                'status' => true,
                'message' => 'Banned list check disabled.'
            ];
        }

        // Disposable email check
        if ($this->config['checkDisposableEmail']) {
            $isDisposable = $this->isDisposableEmail($email);
            $report['disposable'] = [
                'status' => !$isDisposable,
                'message' => !$isDisposable ? 'Not a disposable email.' : 'Disposable email detected.'
            ];
        } else {
            $report['disposable'] = [
                'status' => true,
                'message' => 'Disposable email check disabled.'
            ];
        }

        // Free email check
        if ($this->config['checkFreeEmail']) {
            $isFree = $this->isFreeEmail($email);
            $report['freeProvider'] = [
                'status' => !$isFree,
                'message' => !$isFree ? 'Not a free email provider.' : 'Email belongs to a free email provider.'
            ];
        } else {
            $report['freeProvider'] = [
                'status' => true,
                'message' => 'Free email check disabled.'
            ];
        }

        // Email existence check
        if ($this->config['checkEmailExistence']) {
            $existence = $this->checkEmailExistence($email);
            $report['emailExistence'] = [
                'status' => $existence === true,
                'message' => $existence === true ? 'Email exists on mail server.' :
                    ($existence === false ? 'Email address does not exist.' : 'Could not verify email existence.')
            ];
        } else {
            $report['emailExistence'] = [
                'status' => true,
                'message' => 'Email existence check disabled.'
            ];
        }

        // Mail server responsiveness
        if ($this->config['checkMailServerResponsive']) {
            $responsive = $this->isMailServerResponsive($email);
            $report['mailServerResponsive'] = [
                'status' => $responsive,
                'message' => $responsive ? 'Mail server is responsive.' : 'Mail server is not responsive.'
            ];
        } else {
            $report['mailServerResponsive'] = [
                'status' => true,
                'message' => 'Mail server responsiveness check disabled.'
            ];
        }

        // Greylisting
        if ($this->config['checkGreylisting']) {
            $greylisted = $this->isGreylisted($email);
            $report['greylisting'] = [
                'status' => !$greylisted,
                'message' => !$greylisted ? 'No greylisting detected.' : 'Email server is using greylisting.'
            ];
        } else {
            $report['greylisting'] = [
                'status' => true,
                'message' => 'Greylisting check disabled.'
            ];
        }

        // Determine overall validity by checking if any check failed
        $isValid = true;
        $failedCheck = null;

        foreach ($report as $checkName => $checkResult) {
            if ($checkResult['status'] === false) {
                $isValid = false;
                $failedCheck = $checkName;
                break;
            }
        }

        // Build the message
        $message = 'The email is valid.';
        if (!$isValid) {
            $messages = [
                'format' => 'Invalid email format.',
                'bannedList' => 'The email domain is on the banned list.',
                'disposable' => 'Disposable email detected.',
                'freeProvider' => 'Email belongs to a free email provider.',
                'mxRecords' => 'MX records do not exist for this email domain.',
                'emailExistence' => 'Email address does not exist.',
                'mailServerResponsive' => 'Mail server is not responsive.',
                'greylisting' => 'Email server is using greylisting.',
            ];
            $message = $messages[$failedCheck] ?? 'One or more checks failed.';
        }

        return [
            'isValid' => $isValid,
            'message' => $message,
            'report' => $report
        ];
    }

    // Check if email domain has valid MX records
    protected function checkMxRecords($email)
    {
        $domain = substr(strrchr($email, "@"), 1);
        return checkdnsrr($domain, 'MX');
    }

    // Check against banned domains or emails
    protected function isBannedEmail($email)
    {
        $domain = substr(strrchr($email, "@"), 1);
        return in_array($domain, $this->bannedEmailDomains);
    }

    // Check if the email is from a disposable email provider
    protected function isDisposableEmail($email)
    {
        $domain = substr(strrchr($email, "@"), 1);
        return in_array($domain, $this->disposableEmailDomains);
    }

    // Check if the email is a free email provider (like Gmail, Yahoo)
    protected function isFreeEmail($email)
    {
        $domain = substr(strrchr($email, "@"), 1);
        return in_array($domain, $this->freeEmailDomains);
    }

    // Check if the email exists by performing an SMTP RCPT TO check
    protected function checkEmailExistence($email)
    {
        $domain = substr(strrchr($email, "@"), 1);

        $start = microtime(true);
        $timeoutLimit = $this->config['timeoutLimit'] ?? 10;

        if (!checkdnsrr($domain, 'MX') || !getmxrr($domain, $mxHosts) || empty($mxHosts)) {
            return null; // Cannot check — no MX record
        }

        getmxrr($domain, $mxHosts);
        if (empty($mxHosts)) {
            return null;
        }

        $mxHosts = array_slice($mxHosts, 0, 1);
        $smtpPorts = [25];

        $emailLocalPart = substr($email, 0, strpos($email, '@'));


        foreach ($mxHosts as $host) {
            foreach ($smtpPorts as $port) {
                if ((microtime(true) - $start) > $timeoutLimit) {
                    return null; // Timeout exceeded
                }

                $connection = @fsockopen($host, $port, $errno, $errstr, 5);

                if ($connection) {
                    stream_set_timeout($connection, 5);

                    try {
                        $this->smtpSend($connection, "HELO $domain");
                        $this->smtpSend($connection, "MAIL FROM:<check@$domain>");
                        $response = $this->smtpSend($connection, "RCPT TO:<$email>");
                        $this->smtpSend($connection, "QUIT");

                        fclose($connection);

                        if (preg_match('/^250|^220/', $response)) {
                            return true;
                        }

                        if (preg_match('/^550/', $response)) {
                            return false;
                        }

                        return null;
                    } catch (\RuntimeException $e) {
                        fclose($connection);
                        return null;
                    }
                }
            }
        }

        return null; // Indeterminate
    }

    protected function smtpSend($connection, $cmd)
    {
        if (!is_resource($connection) || feof($connection)) {
            throw new \RuntimeException("SMTP connection is invalid or closed.");
        }

        $writeResult = @fwrite($connection, $cmd . "\r\n");
        if ($writeResult === false) {
            throw new \RuntimeException("Failed to send command: $cmd");
        }

        $response = fgets($connection, 1024);

        $meta = stream_get_meta_data($connection);
        if ($meta['timed_out'] || $response === false) {
            throw new \RuntimeException("SMTP server timed out after command: $cmd");
        }

        return $response;
    }


    protected function isMailServerResponsive($email)
    {
        $domain = substr(strrchr($email, "@"), 1);
        $mxRecords = dns_get_record($domain, DNS_MX);
        if (empty($mxRecords))
            return false;

        $mxServer = $mxRecords[0]['target'];
        $port = 25;

        $connection = @fsockopen($mxServer, $port, $errno, $errstr, 5);
        return $connection ? true : false;
    }

    protected function isGreylisted($email)
    {
        $domain = substr(strrchr($email, "@"), 1);
        $mxRecords = dns_get_record($domain, DNS_MX);
        if (empty($mxRecords))
            return false;

        $mxServer = $mxRecords[0]['target'];
        $port = 25;

        $connection = @fsockopen($mxServer, $port, $errno, $errstr, 5);
        if (!$connection)
            return false;

        stream_set_timeout($connection, 5);

        fwrite($connection, "EHLO $mxServer\r\n");
        fgets($connection, 1024);

        fwrite($connection, "MAIL FROM:<test@example.com>\r\n");
        fgets($connection, 1024);

        fwrite($connection, "RCPT TO:<$email>\r\n");
        $response = fgets($connection, 1024);

        fclose($connection);
        return strpos($response, '450') !== false;
    }

}