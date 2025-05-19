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
        $this->freeEmailDomains = include __DIR__ . '/../config/free_email_domains.php';
        $this->disposableEmailDomains = include __DIR__ . '/../config/disposable_email_domains.php';
        $this->bannedEmailDomains = include __DIR__ . '/../config/banned_email_domains.php';

        $this->config = array_merge([
            'checkMxRecords' => true,
            'checkBannedListedEmail' => true,
            'checkDisposableEmail' => true,
            'checkFreeEmail' => false,
            'checkEmailExistence' => false,
            'checkMailServerResponsive' => false,
            'checkGreylisting' => false,
            'checkCatchAll' => false,
        ], $config);
    }

    public function validate($emails)
    {
        if (is_array($emails)) {
            return $this->validateMultiple($emails);
        }

        return $this->validateSingle($emails);
    }

    protected function validateMultiple(array $emails)
    {
        $results = [];

        // Group emails by domain
        $grouped = [];
        foreach ($emails as $email) {
            $domain = substr(strrchr($email, "@"), 1);
            $grouped[$domain][] = $email;
        }

        foreach ($grouped as $domain => $emailList) {
            $mxHosts = $this->getMxHosts($domain);
            $smtpResource = null;
            $catchAll = null;

            if (!empty($mxHosts)) {
                $smtpResource = $this->smtpConnect($mxHosts);
                if ($this->config['checkCatchAll'] && $smtpResource) {
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

    protected function validateSingle($email, $smtpConnection = null, $isCatchAll = null)
    {
        $report = [];

        $isValidFormat = filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
        $report['format'] = [
            'status' => $isValidFormat,
            'message' => $isValidFormat ? 'Valid email format.' : 'Invalid email format.'
        ];

        if (!$isValidFormat) {
            return [
                'isValid' => false,
                'message' => 'Invalid email format.',
                'report' => $report
            ];
        }

        $domain = substr(strrchr($email, "@"), 1);

        $report['mxRecords'] = $this->config['checkMxRecords'] ? [
            'status' => $this->checkMxRecords($email),
            'message' => $this->checkMxRecords($email) ? 'MX records found.' : 'MX records not found.'
        ] : ['status' => true, 'message' => 'MX records check disabled.'];

        $report['bannedList'] = $this->config['checkBannedListedEmail'] ? [
            'status' => !$this->isBannedEmail($email),
            'message' => !$this->isBannedEmail($email) ? 'Not on banned list.' : 'The email domain is on the banned list.'
        ] : ['status' => true, 'message' => 'Banned list check disabled.'];

        $report['disposable'] = $this->config['checkDisposableEmail'] ? [
            'status' => !$this->isDisposableEmail($email),
            'message' => !$this->isDisposableEmail($email) ? 'Not a disposable email.' : 'Disposable email detected.'
        ] : ['status' => true, 'message' => 'Disposable email check disabled.'];

        $report['freeProvider'] = $this->config['checkFreeEmail'] ? [
            'status' => !$this->isFreeEmail($email),
            'message' => !$this->isFreeEmail($email) ? 'Not a free email provider.' : 'Email belongs to a free email provider.'
        ] : ['status' => true, 'message' => 'Free email check disabled.'];

        $report['emailExistence'] = $this->config['checkEmailExistence'] ? [
            'status' => ($exist = $this->checkEmailExistence($email, $smtpConnection)) === true,
            'message' => $exist === true ? 'Email exists on mail server.' :
                ($exist === false ? 'Email address does not exist.' : 'Could not verify email existence.')
        ] : ['status' => true, 'message' => 'Email existence check disabled.'];

        $report['mailServerResponsive'] = $this->config['checkMailServerResponsive'] ? [
            'status' => $this->isMailServerResponsive($email),
            'message' => $this->isMailServerResponsive($email) ? 'Mail server is responsive.' : 'Mail server is not responsive.'
        ] : ['status' => true, 'message' => 'Mail server responsiveness check disabled.'];

        $report['greylisting'] = $this->config['checkGreylisting'] ? [
            'status' => !$this->isGreylisted($email),
            'message' => !$this->isGreylisted($email) ? 'No greylisting detected.' : 'Email server is using greylisting.'
        ] : ['status' => true, 'message' => 'Greylisting check disabled.'];

        $report['catchAll'] = $this->config['checkCatchAll'] ? [
            'status' => $isCatchAll === false,
            'message' => $isCatchAll === null ? 'Could not determine catch-all status.' :
                ($isCatchAll ? 'Catch-all domain detected.' : 'Not a catch-all domain.')
        ] : ['status' => true, 'message' => 'Catch-all check disabled.'];

        $isValid = true;
        $failedCheck = null;

        foreach ($report as $checkName => $checkResult) {
            if ($checkResult['status'] === false) {
                $isValid = false;
                $failedCheck = $checkName;
                break;
            }
        }

        $messages = [
            'format' => 'Invalid email format.',
            'bannedList' => 'The email domain is on the banned list.',
            'disposable' => 'Disposable email detected.',
            'freeProvider' => 'Email belongs to a free email provider.',
            'mxRecords' => 'MX records do not exist for this email domain.',
            'emailExistence' => 'Email address does not exist.',
            'mailServerResponsive' => 'Mail server is not responsive.',
            'greylisting' => 'Email server is using greylisting.',
            'catchAll' => 'Catch-all domain detected.',
        ];

        return [
            'isValid' => $isValid,
            'message' => $isValid ? 'The email is valid.' : ($messages[$failedCheck] ?? 'One or more checks failed.'),
            'report' => $report
        ];
    }

    protected function getMxHosts($domain)
    {
        if (getmxrr($domain, $mxHosts, $weights)) {
            array_multisort($weights, $mxHosts);
            return $mxHosts;
        }
        return [];
    }

    protected function smtpConnect($mxHosts)
    {
        foreach ($mxHosts as $host) {
            $connection = @fsockopen($host, 25, $errno, $errstr, 10);
            if ($connection) {
                stream_set_timeout($connection, 10);
                $this->readResponse($connection);
                $hostname = gethostname() ?: 'validator.example.com';
                fwrite($connection, "EHLO $hostname\r\n");
                $this->readResponse($connection);
                return $connection;
            }
        }
        return null;
    }

    protected function isCatchAllDomain($smtpConnection, $domain)
    {
        $random = uniqid('user_', true) . '@' . $domain;
        $sender = 'verifier@' . (gethostname() ?: 'validator.example.com');

        fwrite($smtpConnection, "MAIL FROM:<$sender>\r\n");
        $this->readResponse($smtpConnection);

        fwrite($smtpConnection, "RCPT TO:<$random>\r\n");
        $response = $this->readResponse($smtpConnection);

        return (strpos($response, '250') !== false || strpos($response, '251') !== false);
    }

    protected function checkMxRecords($email)
    {
        $domain = substr(strrchr($email, "@"), 1);
        return checkdnsrr($domain, 'MX');
    }

    protected function isBannedEmail($email)
    {
        $domain = substr(strrchr($email, "@"), 1);
        return in_array($domain, $this->bannedEmailDomains);
    }

    protected function isDisposableEmail($email)
    {
        $domain = substr(strrchr($email, "@"), 1);
        return in_array($domain, $this->disposableEmailDomains);
    }

    protected function isFreeEmail($email)
    {
        $domain = substr(strrchr($email, "@"), 1);
        return in_array($domain, $this->freeEmailDomains);
    }

    protected function checkEmailExistence($email, $smtpConnection = null)
    {
        if ($smtpConnection === null) {
            $domain = substr(strrchr($email, "@"), 1);
            $mxHosts = $this->getMxHosts($domain);
            $smtpConnection = $this->smtpConnect($mxHosts);
            if (!$smtpConnection)
                return null;
            $external = true;
        } else {
            $external = false;
        }

        $sender = 'verifier@' . (gethostname() ?: 'validator.example.com');

        fwrite($smtpConnection, "MAIL FROM:<$sender>\r\n");
        $this->readResponse($smtpConnection);

        fwrite($smtpConnection, "RCPT TO:<$email>\r\n");
        $response = $this->readResponse($smtpConnection);

        if ($external) {
            fwrite($smtpConnection, "QUIT\r\n");
            fclose($smtpConnection);
        }

        if (strpos($response, '250') !== false || strpos($response, '251') !== false)
            return true;
        if (preg_match('/5[0-5][0-9]/', $response))
            return false;

        return null;
    }

    protected function isMailServerResponsive($email)
    {
        $domain = substr(strrchr($email, "@"), 1);
        if (!getmxrr($domain, $mxHosts))
            return false;

        foreach ($mxHosts as $host) {
            if (@fsockopen($host, 25, $errno, $errstr, 5))
                return true;
        }

        return false;
    }

    protected function isGreylisted($email)
    {
        $domain = substr(strrchr($email, "@"), 1);
        if (!getmxrr($domain, $mxHosts))
            return false;

        foreach ($mxHosts as $host) {
            $conn = @fsockopen($host, 25, $errno, $errstr, 5);
            if (!$conn)
                continue;
            $this->readResponse($conn);

            $hostname = gethostname() ?: 'validator.example.com';
            fwrite($conn, "EHLO $hostname\r\n");
            $this->readResponse($conn);

            $sender = 'verifier@' . $hostname;
            fwrite($conn, "MAIL FROM:<$sender>\r\n");
            $this->readResponse($conn);

            fwrite($conn, "RCPT TO:<$email>\r\n");
            $response = $this->readResponse($conn);

            fwrite($conn, "QUIT\r\n");
            fclose($conn);

            if (preg_match('/45[0-9]|421/', $response))
                return true;
        }

        return false;
    }

    protected function readResponse($connection)
    {
        $response = '';
        while (is_resource($connection) && ($line = fgets($connection, 1024))) {
            $response .= $line;
            if (strlen($line) < 4 || (substr($line, 3, 1) === ' '))
                break;
        }
        return $response;
    }
}