<?php

use PHPUnit\Framework\TestCase;
use EzeanyimHenry\EmailValidator\Tests\MockEmailValidator;

class EmailValidatorTest extends TestCase
{
    protected function createValidator(array $config = []): MockEmailValidator
    {
        return new MockEmailValidator(array_merge([
            'checkMxRecords' => false,
            'checkBannedListedEmail' => false,
            'checkDisposableEmail' => false,
            'checkFreeEmail' => false,
            'checkEmailExistence' => false,
            'checkMailServerResponsive' => false,
            'checkGreylisting' => false,
            'checkCatchAll' => false,
        ], $config));
    }

    public function testValidEmail()
    {
        $validator = $this->createValidator();
        $result = $validator->validate('valid.email@email.com');
        $this->assertTrue($result['isValid']);
        $this->assertEquals('The email is valid.', $result['message']);
        $this->assertTrue($result['report']['format']['status']);

    }

    public function testInvalidEmailFormat()
    {
        $validator = $this->createValidator();
        $result = $validator->validate('invalid-email');
        $this->assertFalse($result['isValid']);
        $this->assertEquals('Invalid email format.', $result['message']);
        $this->assertFalse($result['report']['format']['status']);

    }

    public function testBannedEmailDomain()
    {
        $validator = $this->createValidator(['checkBannedListedEmail' => true]);
        $validator->setBannedEmailDomains(['banned.com']);

        $result = $validator->validate('user@banned.com');
        $this->assertFalse($result['isValid']);
        $this->assertEquals('The email domain is on the banned list.', $result['message']);
        $this->assertFalse($result['report']['bannedList']['status']);
    }

    public function testDisposableEmail()
    {
        $validator = $this->createValidator(['checkDisposableEmail' => true]);
        $validator->setDisposableEmailDomains(['mailinator.com']);

        $result = $validator->validate('test@mailinator.com');
        $this->assertFalse($result['isValid']);
        $this->assertEquals('Disposable email detected.', $result['message']);
        $this->assertFalse($result['report']['disposable']['status']);
    }

    public function testFreeEmail()
    {
        $validator = $this->createValidator(['checkFreeEmail' => true]);
        $validator->setFreeEmailDomains(['gmail.com']);

        $result = $validator->validate('user@gmail.com');
        $this->assertFalse($result['isValid']);
        $this->assertEquals('Email belongs to a free email provider.', $result['message']);
        $this->assertFalse($result['report']['freeProvider']['status']);
    }

    public function testMxRecordCheck()
    {
        $validator = $this->createValidator(['checkMxRecords' => true]);
        $validator->setMockResponse('checkMxRecords', false);

        $result = $validator->validate('user@nonexistent-domain.example');
        $this->assertFalse($result['isValid']);
        $this->assertEquals('MX records do not exist for this email domain.', $result['message']);
        $this->assertFalse($result['report']['mxRecords']['status']);
    }

    public function testEmailExistence()
    {
        $validator = $this->createValidator(['checkEmailExistence' => true]);
        $validator->setMockResponse('checkEmailExistence', true);

        $result = $validator->validate('valid.email@email.com');
        $this->assertTrue($result['isValid']);
        $this->assertEquals('The email is valid.', $result['message']);
        $this->assertTrue($result['report']['emailExistence']['status']);
    }

    public function testEmailNonExistence()
    {
        $validator = $this->createValidator(['checkEmailExistence' => true]);
        $validator->setMockResponse('checkEmailExistence', false);

        $result = $validator->validate('nonexistentemail@email.com');
        $this->assertFalse($result['isValid']);
        $this->assertEquals('Email address does not exist.', $result['message']);
        $this->assertFalse($result['report']['emailExistence']['status']);
    }

    public function testMailServerResponsiveness()
    {
        $validator = $this->createValidator(['checkMailServerResponsive' => true]);
        $validator->setMockResponse('isMailServerResponsive', true);

        $result = $validator->validate('valid.email@email.com');
        $this->assertTrue($result['isValid']);
        $this->assertEquals('The email is valid.', $result['message']);
        $this->assertTrue($result['report']['mailServerResponsive']['status']);
    }

    public function testMailServerUnresponsiveness()
    {
        $validator = $this->createValidator(['checkMailServerResponsive' => true]);
        $validator->setMockResponse('isMailServerResponsive', false);

        $result = $validator->validate('user@unresponsive-domain.com');
        $this->assertFalse($result['isValid']);
        $this->assertEquals('Mail server is not responsive.', $result['message']);
        $this->assertFalse($result['report']['mailServerResponsive']['status']);
    }

    public function testGreylisting()
    {
        $validator = $this->createValidator(['checkGreylisting' => true]);
        $validator->setMockResponse('isGreylisted', true);

        $result = $validator->validate('test@greylisted-domain.com');
        $this->assertFalse($result['isValid']);
        $this->assertEquals('Email server is using greylisting.', $result['message']);
        $this->assertFalse($result['report']['greylisting']['status']);
    }

    public function testMultipleEmails()
    {
        $validator = $this->createValidator(['checkDisposableEmail' => true]);
        $validator->setDisposableEmailDomains(['mailinator.com']);

        $emails = [
            'valid.email@email.com',
            'user@gmail.com',
            'invalid-email',
            'test@mailinator.com',
        ];

        $results = $validator->validate($emails);

        $this->assertTrue($results['valid.email@email.com']['isValid']);
        $this->assertEquals('The email is valid.', $results['valid.email@email.com']['message']);
        $this->assertTrue($results['valid.email@email.com']['report']['format']['status']);

        $this->assertTrue($results['user@gmail.com']['isValid']);
        $this->assertEquals('The email is valid.', $results['user@gmail.com']['message']);
        $this->assertTrue($results['user@gmail.com']['report']['format']['status']);

        $this->assertFalse($results['invalid-email']['isValid']);
        $this->assertEquals('Invalid email format.', $results['invalid-email']['message']);
        $this->assertFalse($results['invalid-email']['report']['format']['status']);

        $this->assertFalse($results['test@mailinator.com']['isValid']);
        $this->assertEquals('Disposable email detected.', $results['test@mailinator.com']['message']);
        $this->assertFalse($results['test@mailinator.com']['report']['disposable']['status']);

    }

    public function testCatchAllDomainDetected()
    {
        $validator = $this->createValidator(['checkCatchAll' => true]);
        $validator->setMockResponse('isCatchAllDomain', true);

        $result = $validator->validate('user@catchalldomain.com');

        $this->assertFalse($result['isValid']);
        $this->assertEquals('Catch-all domain detected.', $result['message']);
        $this->assertFalse($result['report']['catchAll']['status']);
    }

    public function testCatchAllDomainNotDetected()
    {
        $validator = $this->createValidator(['checkCatchAll' => true]);
        $validator->setMockResponse('isCatchAllDomain', false);

        $result = $validator->validate('user@normaldomain.com');

        $this->assertTrue($result['isValid']);
        $this->assertEquals('The email is valid.', $result['message']);
        $this->assertTrue($result['report']['catchAll']['status']);
    }

    public function testMultipleEmailsWithCatchAll()
    {
        $validator = $this->createValidator([
            'checkDisposableEmail' => true,
            'checkCatchAll' => true,
        ]);
        $validator->setDisposableEmailDomains(['mailinator.com']);
        $validator->setMockResponse('isCatchAllDomain', false);

        $emails = [
            'valid.email@email.com',
            'user@gmail.com',
            'invalid-email',
            'test@mailinator.com',
            'someone@catchalldomain.com'
        ];

        // Override catch-all response for catchalldomain.com to true
        $validator->setMockResponseForDomain('catchalldomain.com', 'isCatchAllDomain', true);

        $results = $validator->validate($emails);

        $this->assertTrue($results['valid.email@email.com']['isValid']);
        $this->assertFalse($results['invalid-email']['isValid']);
        $this->assertFalse($results['test@mailinator.com']['isValid']);
        $this->assertFalse($results['someone@catchalldomain.com']['isValid']);
        $this->assertTrue($results['user@gmail.com']['isValid']);
    }
}