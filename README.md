# Email Validator

A PHP package for validating email addresses with various checks such as MX records, disposable email detection, and banned email lists.

## Features

- Validate email format
- Check MX records for domain validity
- Detect disposable email addresses
- Check against banned email lists
- Check for free email provider addresses

## Installation

You can install the package via Composer. Run the following command:

```bash
composer require ezeanyimhenry/email-validator
```

## Usage

Here’s how to use the `EmailValidator` class:

### Basic Validation

You can validate a single email address as follows:

```php
<?php

require 'vendor/autoload.php'; // Autoload files using Composer

use EzeanyimHenry\EmailValidator\EmailValidator;

// Create a new instance of the EmailValidator
$emailValidator = new EmailValidator();

// Validate a single email address
$result = $emailValidator->validate('test@example.com');

if ($result['isValid']) {
    echo "The email is valid.";
} else {
    echo "Error: " . $result['message'];
}
```

## Validating Multiple Email Addresses

To validate multiple email addresses at once, simply pass an array:

```php
<?php

require 'vendor/autoload.php'; // Autoload files using Composer

use EzeanyimHenry\EmailValidator\EmailValidator;

// Create a new instance of the EmailValidator
$emailValidator = new EmailValidator();

// Validate multiple email addresses
$emails = [
    'test@example.com',
    'invalid-email',
    'user@mailinator.com',
];

$results = $emailValidator->validate($emails);
foreach ($results as $email => $result) {
    echo "$email: " . ($result['isValid'] ? "Valid" : "Invalid - " . $result['message']) . "\n";
}
```

## Configuration Options

You can customize the validator's behavior by passing configuration options when creating the instance:

```php
<?php

require 'vendor/autoload.php'; // Autoload files using Composer

use EzeanyimHenry\EmailValidator\EmailValidator;

// Create a new instance with custom configuration
$emailValidator = new EmailValidator([
    'checkMxRecords' => true,
    'checkBannedListedEmail' => true,
    'checkDisposableEmail' => true,
    'checkFreeEmail' => false,
]);

// Validate an email
$result = $emailValidator->validate('test@example.com');
```


### Error Handling

The `validate()` method returns an associative array containing the validation result and a message. You can check if the email is valid by accessing the `isValid` key, and you can get the error message from the `message` key.

```php
if (!$result['isValid']) {
    echo "Validation failed: " . $result['message'];
}
```

### Testing

To run the tests, ensure you have PHPUnit installed. You can run the tests with the following command:

### Contributing

Contributions are welcome! Please follow these steps to contribute:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a pull request

### License

This package is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
