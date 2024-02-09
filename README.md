<h1 align="center">Pangea PHP Client
<a href="https://pangea.cloud/docs/api" target="_blank"><svg class="MuiSvgIcon-root MuiSvgIcon-fontSizeLarge css-1hqdodo" focusable="false" aria-hidden="true" viewBox="-4 -2 30 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M25.6013 5.8018L17.8888 0.150718C17.796 0.0831412 17.737 0.0578003 17.6104 0.0578003H15.4671C14.9861 0.0578003 14.4883 0.446365 14.3533 0.936294L8.66594 22.1806C8.54781 22.6368 8.81783 23 9.26505 23H11.9231C12.3787 23 12.8428 22.6283 12.9694 22.1806L13.2985 20.9558L14.6908 15.7524L15.7877 11.6641L17.5598 5.02467C17.6019 4.85573 17.8045 4.78815 17.9395 4.88952L22.3779 8.14163C22.5383 8.25989 22.5383 8.49641 22.3779 8.61466L17.5851 12.1286C17.3657 12.2891 17.2307 12.5932 17.2307 12.9311V16.2424C17.2307 16.8168 17.7032 16.7407 18.0829 16.462L25.5929 10.9545C25.7701 10.8278 25.8798 10.5828 25.8798 10.3125V6.43532C25.8798 6.17347 25.7701 5.9285 25.6013 5.8018Z" fill="currentColor"></path><path d="M8.64911 0.353448V3.81674C8.64911 4.15462 8.50566 4.46716 8.28626 4.6361L3.50183 8.15008C3.34995 8.25989 3.34995 8.50485 3.50183 8.62311L8.2947 12.1371C8.51409 12.2976 8.64911 12.6101 8.64911 12.9396V16.2508C8.64911 16.8252 8.17657 16.7492 7.79685 16.4704L0.286897 10.9629C0.109696 10.8362 0 10.5913 0 10.321V6.43533C0 6.17347 0.109696 5.9285 0.278459 5.8018L7.99093 0.150718C8.28626 -0.0689054 8.64911 -0.0857989 8.64911 0.353448Z" fill="#29ADEB"></path></svg></a></h1>

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

  - [x] Add vault [Provides secure storage of secrets, cryptographic keys, and Pangea API Tokens tokens as Vault items]
  - [x] Add IP Intel [Malicious behavior check on IP]
  - [x] Add Domain Intel [Allows you to retrieve intelligence about domain names]
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
$pangea = new Pangea\Vault($token, $service, $csp, $region);

//Registers all services or select the one you need
$pangea->registerService(
    $pangea->available_service()
    //or like this 'vault', 'ip-intel'
); 

print_r($pangea->generateKey('symmetric_key', 'AES-GCM-256'));

```

More documentation and implementations coming soon.

# Changelog

All notable changes to this project will be documented here.

# License

Released under the MIT license.

@Pangea
