<?php

use PHPUnit\Framework\TestCase;
use EzeanyimHenry\EmailValidator\EmailValidator;

class EmailValidatorTest extends TestCase
{
    protected $validator;

    protected function setUp(): void
    {
        // Default config for the validator
        $this->validator = new EmailValidator([
            'checkMxRecords' => false,
            'checkBannedListedEmail' => true,
            'checkDisposableEmail' => true,
            'checkFreeEmail' => false,
        ]);
    }

    public function testValidEmail()
    {
        $result = $this->validator->validate('valid.email@example.com');
        $this->assertTrue($result['isValid']);
        $this->assertEquals('The email is valid.', $result['message']);
    }

    public function testInvalidEmailFormat()
    {
        $result = $this->validator->validate('invalid-email');
        $this->assertFalse($result['isValid']);
        $this->assertEquals('Invalid email format.', $result['message']);
    }

    public function testBannedEmailDomain()
    {
        $bannedValidator = new EmailValidator([
            'checkBannedListedEmail' => true,
        ]);

        $result = $bannedValidator->validate('user@banned.com');
        $this->assertFalse($result['isValid']);
        $this->assertEquals('The email domain is on the banned list.', $result['message']);
    }

    public function testDisposableEmail()
    {
        $result = $this->validator->validate('test@mailinator.com');
        $this->assertFalse($result['isValid']);
        $this->assertEquals('Disposable email detected.', $result['message']);
    }

    public function testFreeEmail()
    {
        $freeEmailValidator = new EmailValidator([
            'checkFreeEmail' => true, // Enable free email detection
        ]);

        $result = $freeEmailValidator->validate('user@gmail.com');
        $this->assertFalse($result['isValid']);
        $this->assertEquals('Email belongs to a free email provider.', $result['message']);
    }

    public function testMxRecordCheck()
    {
        $mxValidator = new EmailValidator([
            'checkMxRecords' => true, // Enable MX record checking for the test
        ]);

        $result = $mxValidator->validate('user@nonexistent-domain.example');
        $this->assertFalse($result['isValid']);
        $this->assertEquals('MX records do not exist for this email domain.', $result['message']);
    }

    public function testMultipleEmails()
    {
        $emails = [
            'valid.email@example.com',
            'user@gmail.com',
            'invalid-email',
            'test@mailinator.com',
        ];

        $results = $this->validator->validate($emails);

        // Test first email: valid
        $this->assertTrue($results['valid.email@example.com']['isValid']);
        $this->assertEquals('The email is valid.', $results['valid.email@example.com']['message']);

        // Test second email: free provider, checkFreeEmail is false so it's valid
        $this->assertTrue($results['user@gmail.com']['isValid']);
        $this->assertEquals('The email is valid.', $results['user@gmail.com']['message']);

        // Test third email: invalid format
        $this->assertFalse($results['invalid-email']['isValid']);
        $this->assertEquals('Invalid email format.', $results['invalid-email']['message']);

        // Test fourth email: disposable
        $this->assertFalse($results['test@mailinator.com']['isValid']);
        $this->assertEquals('Disposable email detected.', $results['test@mailinator.com']['message']);
    }
}
