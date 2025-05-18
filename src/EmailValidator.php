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
        $sender = "verifier@" . (gethostname() ?: 'validator.example.com');

        if (!getmxrr($domain, $mxHosts, $mxWeights)) {
            return null; // Cannot check - no MX records
        }

        if (empty($mxHosts)) {
            return null;
        }

        // Sort MX hosts by priority (lower weight = higher priority)
        $mxRecords = [];
        foreach ($mxHosts as $index => $host) {
            $mxRecords[] = [
                'host' => $host,
                'priority' => $mxWeights[$index] ?? 0
            ];
        }
        usort($mxRecords, function ($a, $b) {
            return $a['priority'] - $b['priority'];
        });

        $mxHosts = array_column($mxRecords, 'host');

        $connectionTimeout = 10; // seconds
        $responseTimeout = 15; // seconds

        // Try each MX host in order of priority
        foreach ($mxHosts as $mxHost) {
            $port = 25;

            // Connect to the mail server
            $connection = @fsockopen($mxHost, $port, $errno, $errstr, $connectionTimeout);
            if (!$connection) {
                continue; // Try the next host if this one fails
            }

            stream_set_timeout($connection, $responseTimeout);

            try {
                $response = $this->readResponse($connection);
                if (!$response || strpos($response, '220') === false) {
                    fclose($connection);
                    continue; // Try the next host
                }

                // Send EHLO command first (RFC 5321 compliant)
                $hostname = gethostname() ?: 'validator.example.com';
                fwrite($connection, "EHLO $hostname\r\n");
                $response = $this->readResponse($connection);

                // If EHLO fails, try HELO
                if (strpos($response, '250') === false) {
                    fwrite($connection, "HELO $hostname\r\n");
                    $response = $this->readResponse($connection);

                    if (strpos($response, '250') === false) {
                        fclose($connection);
                        continue; // Try the next host
                    }
                }

                fwrite($connection, "MAIL FROM:<$sender>\r\n");
                $response = $this->readResponse($connection);
                if (strpos($response, '250') === false) {
                    fclose($connection);
                    continue; // Try the next host
                }

                // Check if the recipient exists
                fwrite($connection, "RCPT TO:<$email>\r\n");
                $response = $this->readResponse($connection);

                fwrite($connection, "QUIT\r\n");
                $this->readResponse($connection);
                fclose($connection);

                // Process the response for the RCPT TO command
                if (strpos($response, '250') !== false || strpos($response, '251') !== false) {
                    return true; // Email exists (accepted)
                }

                if (
                    strpos($response, '550') !== false ||
                    strpos($response, '553') !== false ||
                    strpos($response, '554') !== false
                ) {
                    return false; // Email definitely does not exist (rejected)
                }

                if (
                    strpos($response, '450') !== false ||
                    strpos($response, '451') !== false ||
                    strpos($response, '452') !== false
                ) {
                    continue; // Temporary failure or greylisting, try next server
                }

                // Any other response - try next server
                continue;
            } catch (\Exception $e) {
                if (is_resource($connection)) {
                    fclose($connection);
                }
                continue; // Try the next host
            }
        }

        return null; // Indeterminate result
    }

    // Helper function to properly read SMTP responses (handling multi-line responses)
    protected function readResponse($connection)
    {
        if (!is_resource($connection)) {
            return false;
        }

        $response = '';
        while (true) {
            $line = fgets($connection, 1024);
            if ($line === false) {
                return $response ?: false;
            }

            $response .= $line;

            // Check if this is the last line of the response
            // SMTP response format: 3-digit code followed by a space for the last line,
            // or a hyphen for continuation lines
            if (strlen($line) < 4 || (substr($line, 3, 1) === ' ')) {
                break;
            }
        }

        return $response;
    }

    protected function isMailServerResponsive($email)
    {
        $domain = substr(strrchr($email, "@"), 1);

        if (!getmxrr($domain, $mxHosts, $mxWeights)) {
            $aRecords = dns_get_record($domain, DNS_A);
            if (empty($aRecords)) {
                return false; // No mail servers found
            }

            $mxHosts = [$domain];
        }

        foreach ($mxHosts as $mxHost) {
            $port = 25;
            $connection = @fsockopen($mxHost, $port, $errno, $errstr, 5);

            if ($connection) {
                fclose($connection);
                return true; // Successfully connected
            }
        }

        return false; // Could not connect to any mail server
    }

    protected function isGreylisted($email)
    {
        $domain = substr(strrchr($email, "@"), 1);

        // Get MX records
        if (!getmxrr($domain, $mxHosts, $mxWeights)) {
            return false; // No MX records
        }

        // Try each mail server
        foreach ($mxHosts as $mxHost) {
            $port = 25;
            $connection = @fsockopen($mxHost, $port, $errno, $errstr, 5);

            if (!$connection) {
                continue; // Try next server
            }

            stream_set_timeout($connection, 5);

            try {
                // Read greeting
                $response = fgets($connection, 1024);
                if (!$response || strpos($response, '220') === false) {
                    fclose($connection);
                    continue;
                }

                // Send EHLO
                $hostname = gethostname() ?: 'validator.example.com';
                fwrite($connection, "EHLO $hostname\r\n");
                $response = $this->readResponse($connection);

                if (strpos($response, '250') === false) {
                    // Try HELO if EHLO fails
                    fwrite($connection, "HELO $hostname\r\n");
                    $response = $this->readResponse($connection);

                    if (strpos($response, '250') === false) {
                        fclose($connection);
                        continue;
                    }
                }

                // Set sender
                $sender = "verifier@" . (gethostname() ?: 'validator.example.com');
                fwrite($connection, "MAIL FROM:<$sender>\r\n");
                $response = $this->readResponse($connection);

                if (strpos($response, '250') === false) {
                    fclose($connection);
                    continue;
                }

                // Check recipient
                fwrite($connection, "RCPT TO:<$email>\r\n");
                $response = $this->readResponse($connection);

                // Clean up
                fwrite($connection, "QUIT\r\n");
                fclose($connection);

                // Check for greylisting responses (temporary failures)
                return (strpos($response, '450') !== false ||
                    strpos($response, '451') !== false ||
                    strpos($response, '452') !== false ||
                    strpos($response, '421') !== false);
            } catch (\Exception $e) {
                if (is_resource($connection)) {
                    fclose($connection);
                }
                continue;
            }
        }

        return false; // No greylisting detected
    }

}