# Pangea PHP Client

<div align="center">
<a href="https://t.me/+7jfbiGKhn55iODlk">Join Telegram</a>
<a href="https://twitter.com/manomitehq" ><img src="https://img.shields.io/twitter/follow/manomitehq.svg?style=social" /> </a>
<br>

<i>Incorporate security into your PHP Applications using the Pangea API services</i>

<a href="https://github.com/mitmelon/pangea/stargazers"><img src="https://img.shields.io/github/stars/mitmelon/pangea" alt="Stars Badge"/></a>
<a href="https://github.com/mitmelon/pangea/network/members"><img src="https://img.shields.io/github/forks/mitmelon/pangea" alt="Forks Badge"/></a>
<a href="https://github.com/mitmelon/pangea/pulls"><img src="https://img.shields.io/github/issues-pr/mitmelon/pangea" alt="Pull Requests Badge"/></a>
<a href="https://github.com/mitmelon/pangea/issues"><img src="https://img.shields.io/github/issues/mitmelon/pangea" alt="Issues Badge"/></a>
<a href="https://github.com/mitmelon/pangea/graphs/contributors"><img alt="GitHub contributors" src="https://img.shields.io/github/contributors/mitmelon/pangea?color=2b9348"></a>
<a href="https://github.com/mitmelon/pangea/blob/master/LICENSE"><img src="https://img.shields.io/github/license/mitmelon/pangea?color=2b9348" alt="License Badge"/></a> [![Total Downloads](http://poser.pugx.org/mitmelon/pangea/downloads)](https://packagist.org/packages/mitmelon/pangea)

<i>If you love my project and wish to assist me to keep working on this project. Please follow this link <a href="https://flutterwave.com/donate/oq61dyrjk9xh">https://flutterwave.com/donate/oq61dyrjk9xh</a> to donate.</i>

</div>

### Todo Features:

  - [ x ] Add vault [Provides secure storage of secrets, cryptographic keys, and Pangea API Tokens tokens as Vault items]
  - [ ] Add IP Intel [Malicious behavior check on IP]
  - [ ] Add Domain Intel [Allows you to retrieve intelligence about domain names]
  - [ ] Add URL Intel [Malicious behavior check on URL]
  - [ ] Add User Intel [Discover if information was disclosed in a breach]
  - [ ] Add File Intel [Enables you to submit a file's hash to retrieve its reputation]
  - [ ] Add File Scan [Enables you to upload files to be scanned for malicious content]
  - [ ] Add audit log [A managed audit log store that offers transparent, unalterable, and cryptographically]
  - [ ] Add redact [Remove sensitive information from free-from text and structured data]
  - [ ] Add Embargo [Determine if there is a trade embargo against the country of origin for an IP address]
  - [ ] Add AuthN [A fully managed service to deliver secure user registration and authentication flows, integrated into your application]


## Install:

Use composer to install

```php
composer require mitmelon/pangea
```

## Usage :

To use this project, [create an account](https://pangea.cloud) and plug your credentials into the options below. Account creation is free. 

```php
require_once __DIR__."/vendor/autoload.php";

// Initialize library class
$pangeaVaultClient = new Pangea\Vault($token, $service, $csp, $region);

$pangeaVaultClient->generateKey(string $type, string $purpose = "signing", string $keyName = null, string $folderName = null, array $metadata = array(), string | array $tags = null, string $rotation_frequency = '10d', string $rotation_state = 'inherited', string $expiration = null)


```

More documentation and implementations coming soon.

# Changelog

All notable changes to this project will be documented here.

# License

Released under the MIT license.

@Pangea
