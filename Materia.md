# Formaçao OWASP
iniciado em 07/02/2022

terminado em 28/02/2022

[certificate]() 

Table of contents
- [Formaçao OWASP](#formaçao-owasp)
  - [OWASP](#owasp)
  - [OWASP: Padrão de verificação de segurança de aplicações(Application Security Verification Standard)](#owasp-padrão-de-verificação-de-segurança-de-aplicaçõesapplication-security-verification-standard)
    - [what is the ASVS?](#what-is-the-asvs)
    - [application security verification levels](#application-security-verification-levels)
    - [Authentication verification requirements](#authentication-verification-requirements)
    - [NIST 800-63 - modern, evidence-based authentication standard](#nist-800-63---modern-evidence-based-authentication-standard)
    - [Password Security Requirements](#password-security-requirements)
      - [requirements](#requirements)
    - [General Authenticator Requirements](#general-authenticator-requirements)
      - [Requirements](#requirements-1)
      - [Requirements for level 3](#requirements-for-level-3)
      - [o que aprendemos?](#o-que-aprendemos)
    - [Authenticator Lifecycle Requirements](#authenticator-lifecycle-requirements)
      - [Requirements](#requirements-2)
      - [Requirements for level 2 and 3](#requirements-for-level-2-and-3)
    - [Credential Storage Requirements](#credential-storage-requirements)
      - [Requirements for level 2 and 3](#requirements-for-level-2-and-3-1)
    - [Credential Recovery Requirements](#credential-recovery-requirements)
      - [Requirements](#requirements-3)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3)
    - [Look-up Secret Verifier](#look-up-secret-verifier)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-1)
    - [o que aprendemos?](#o-que-aprendemos-1)
    - [Out of Band Verifier](#out-of-band-verifier)
      - [Requirements](#requirements-4)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-2)
    - [Single or multi factor one time verifier](#single-or-multi-factor-one-time-verifier)
      - [Requirements](#requirements-5)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-3)
      - [Requirements for level 3](#requirements-for-level-3-1)
    - [Cryptographic software and Devices Verifier](#cryptographic-software-and-devices-verifier)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-4)
    - [Service Authentication](#service-authentication)
      - [Requirements for level 2 (OS assisted) and level 3 (HSM)](#requirements-for-level-2-os-assisted-and-level-3-hsm)
    - [Additional US Agency Requirements](#additional-us-agency-requirements)
    - [o que aprendemos?](#o-que-aprendemos-2)
    - [Session Management Verification](#session-management-verification)
    - [Fundamental Session Management Requirements](#fundamental-session-management-requirements)
    - [Session Binding](#session-binding)
      - [Requirements](#requirements-6)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-5)
    - [Session logout and timeout](#session-logout-and-timeout)
      - [Requirements](#requirements-7)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-6)
    - [Cookie-based Session Management](#cookie-based-session-management)
      - [Requirements](#requirements-8)
    - [Token-based Session Management](#token-based-session-management)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-7)
    - [Re-authentication from a Federation or Assertion](#re-authentication-from-a-federation-or-assertion)
      - [Requirements for level 3](#requirements-for-level-3-2)
    - [Defenses Against Session Management Exploits](#defenses-against-session-management-exploits)
      - [description of the half-open attack](#description-of-the-half-open-attack)
      - [Requirements](#requirements-9)
    - [o que aprendemos?](#o-que-aprendemos-3)
    - [Access Control Verification](#access-control-verification)
    - [General Access Control Design](#general-access-control-design)
      - [Requirements](#requirements-10)
    - [Operation Level Access Control](#operation-level-access-control)
      - [Requirements](#requirements-11)
    - [Other Access Control Considerations](#other-access-control-considerations)
      - [Requirements](#requirements-12)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-8)
    - [o que aprendemos?](#o-que-aprendemos-4)
    - [Validation, Sanitization and Encoding Verification](#validation-sanitization-and-encoding-verification)
    - [Input Validation](#input-validation)
      - [Requirements](#requirements-13)
    - [Sanitization and Sandboxing](#sanitization-and-sandboxing)
      - [Requirements](#requirements-14)
    - [o que aprendemos?](#o-que-aprendemos-5)
    - [Output Encoding and Injection Prevention](#output-encoding-and-injection-prevention)
      - [Requirements](#requirements-15)
    - [Memory, String and Unmanaged Code](#memory-string-and-unmanaged-code)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-9)
    - [Deserialization Prevention](#deserialization-prevention)
      - [Requirements](#requirements-16)
    - [o que aprendemos?](#o-que-aprendemos-6)
    - [Stored Cryptography Verification](#stored-cryptography-verification)
    - [data classification](#data-classification)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-10)
    - [Algorithms](#algorithms)
      - [Requirements](#requirements-17)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-11)
      - [Requirements for level 3](#requirements-for-level-3-3)
    - [Random values](#random-values)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-12)
      - [Requirements for level 3](#requirements-for-level-3-4)
    - [Secret Management](#secret-management)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-13)
    - [o que aprendemos?](#o-que-aprendemos-7)
    - [Error Handling and logging Verification Requirements](#error-handling-and-logging-verification-requirements)
    - [Log Content](#log-content)
      - [Requirements](#requirements-18)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-14)
    - [Log Processing](#log-processing)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-15)
    - [Log Protection](#log-protection)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-16)
    - [Error Handling](#error-handling)
      - [Requirements](#requirements-19)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-17)
    - [o que aprendemos?](#o-que-aprendemos-8)
    - [Data Protection Verification](#data-protection-verification)
    - [General data protection](#general-data-protection)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-18)
      - [Requirements for level 3](#requirements-for-level-3-5)
    - [Client-side Data Protection](#client-side-data-protection)
      - [Requirements](#requirements-20)
    - [Sensitive Private Data](#sensitive-private-data)
      - [Requirements](#requirements-21)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-19)
    - [o que aprendemos?](#o-que-aprendemos-9)
    - [Communications Verification](#communications-verification)
    - [Communications Security](#communications-security)
      - [Requirements](#requirements-22)
    - [Server Comunication Security](#server-comunication-security)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-20)
    - [o que aprendemos?](#o-que-aprendemos-10)
    - [Malicious Code Verification](#malicious-code-verification)
    - [Code integrity Controls](#code-integrity-controls)
      - [Requirements for level 3](#requirements-for-level-3-6)
    - [Malicious Code Search](#malicious-code-search)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-21)
      - [Requirements for level 3](#requirements-for-level-3-7)
    - [Deployed Application Integrity Controls](#deployed-application-integrity-controls)
      - [Requirements](#requirements-23)
    - [o que aprendemos?](#o-que-aprendemos-11)
    - [Business Logic Verification](#business-logic-verification)
    - [Business Logic Security](#business-logic-security)
      - [Requirements](#requirements-24)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-22)
    - [o que aprendemos?](#o-que-aprendemos-12)
    - [File and Resources Verification](#file-and-resources-verification)
    - [File Upload](#file-upload)
      - [Requirements](#requirements-25)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-23)
    - [File Integrity](#file-integrity)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-24)
    - [File Execution](#file-execution)
    - [Requirements](#requirements-26)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-25)
    - [File Storage](#file-storage)
      - [Requirements](#requirements-27)
    - [File Download](#file-download)
      - [Requirements](#requirements-28)
    - [SSRF Protection](#ssrf-protection)
      - [Requirements](#requirements-29)
    - [o que aprendemos?](#o-que-aprendemos-13)
    - [API and Web Service Verification](#api-and-web-service-verification)
    - [Generic Web Service Security Verification](#generic-web-service-security-verification)
      - [Requirements](#requirements-30)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-26)
    - [RESTful Web Service Verification](#restful-web-service-verification)
      - [Requirements](#requirements-31)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-27)
    - [SOAP Web Service Verification](#soap-web-service-verification)
      - [Requirements](#requirements-32)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-28)
    - [GraphQL and other Web Service Data Layer Security](#graphql-and-other-web-service-data-layer-security)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-29)
    - [o que aprendemos?](#o-que-aprendemos-14)
    - [Configuration Verification](#configuration-verification)
    - [Build](#build)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-30)
      - [Requirements for level 3](#requirements-for-level-3-8)
    - [Dependency](#dependency)
      - [Requirements](#requirements-33)
      - [Requirements for level 2 and level 3](#requirements-for-level-2-and-level-3-31)
    - [Unintended Security Disclosure](#unintended-security-disclosure)
      - [Requirements](#requirements-34)
    - [HTTP Security Headers](#http-security-headers)
      - [Requirements](#requirements-35)
    - [Validate HTTP Request Header](#validate-http-request-header)
      - [Requirements](#requirements-36)
    - [o que aprendemos?](#o-que-aprendemos-15)

## OWASP

* entenda a importancia de ter um checklist como guia e metrica de segurança
* aprenda os itens de segurança da OWASP que sao automatizaveis para as vulnerabilidades do OWASP top 10
* aprenda exemplos de defesa e ataque relativos as principais vulnerabilidades
* utilize o padrao da OWASP para aumentar a segurança de suas aplicaçoes (part1)

[link](https://cursos.alura.com.br/formacao-owasp)

## OWASP: Padrão de verificação de segurança de aplicações(Application Security Verification Standard)
vamos ver um checklist contendo um padrao minimo de segurança das aplicaçoes.

o relatorio da propria OWASP nos fornece uma lista de requerimentos diversos relacionados a tudo que esta ligado ao processo de autenticaçao, autorizaçao e segurança em geral da aplicaçao.

nos proximos topicos vamos ver cada um dos itens ligados ao nivel 1.

existem 3 niveis de segurança.

o nivel 1 atende às necessidades da OWASP top 10
o nivel 2 atende outras aplicaçoes e a maior parte dos problemas de segurança em geral.
o nivel 3 sao para high value, high assurance or high safety applications

### what is the ASVS?
the OWASP application Security Verification Standart (ASVS) project provides a basis for testing web application technical security controls and also provides developers with a list of requirements for secure development.

the primary aim of the ASVS is to normalize the range in the coverage and level of rigor available in the market when it comes to performing web applications security verification using a commercially-workable open standard. the starndard provides a basis for testing application technical security controls, as well as any technical security controls in the enviroment, that are relied on to protect against vulnerabilities such as Cross-Site Scripting (XSS) and SQL injection. this standard can be used to establish a level of confidence in the security of Web Applications. the requirements were developed with the following objectives in mind:

* use as a metric - provide application developers and application owners with a yardstick with which to assess the degree of trust that can be placed in their Web Applications.
* use as guidance - Provide guidance to security control developers as to what to build into security controls in order to satisfy application security requirements and
* use during procurement - provide a basis for specifiyng application security verification requirements in contracts


### application security verification levels
the application security verification standard defines three security verification levels, with each level increasing in depth.

* ASVS level 1 is for low assurance levels and is completely penetration testable
* ASVS level 2 is for applications that contain sensitive data, which requires protection and is the recommended level for most apps
* ASVS level 3 is for the most critical applications - applications that perform high value transactions, contain sensitive medical data, or any applications that requires the highest level of trust.

level 1 is the only level that is completely penetration testable using humans. all others require access to documentation, source code, configuration, and the people involved in the development process. however, even if L1 allows 'black box' (no documentation and no source) testing to occur, it is not effective assurance and must stop. malicious attackers have a great deal of time, most penetration tests are over within a couple of weeks. defenders need to build in security controls, protect, find and resolve all weakness, and detect and respond to malicious actors in a reasonable time. malicious actors have essentially infinite time and only require a single porous defense, a single weakness, or missing detection to succeed. black box testing, often performed at the end of development, quickly or not at all, is completely unable to cope with that asymetry.

an application achieves ASVS Level 1 if it adquately defends agaist application security vulnerabilities that are easy to discover, and included in the OWASP top 10 and other similar checklists.

level 1 is the bare minimum that all applications should strive for. it is also useful as a first step in a multi-phase effort or when applications do no store or handle sensitive data and therefore do not need the more rigorous controls of level 2 or 3. level 1 controls can be checked either automatically by tools or simply manually without access to source code. we consider level 1 the minimum required for all apllications.

threats to the application will most likely be from attackers who are using simple and low effort techniques to identify easy-to-find and easy-to-exploit vulnerabilities. this is in contrast to a determined attacker who will spend focused energy to specifically target the application. if data processed by your application has high value, you would rarely wanto to stop at a level 1 review.

### Authentication verification requirements
control objective

authentication is the act of establishing, or confirming someone (or something) as authentic and that claims made by a person or about a device are correct, resistant to impersonation and prevent recovery or interception of passwords.

when the ASVS was first released, username+password was the most common form of authentication outisde of high security systems. multi-factor authentication (MFA) was commonly accepted in security circles but rarely required elsewhere. as the number of passwords breaches increased, the ideia that usernames are somehow confidential and passwords unknown, rendered many security controls untenable. for example, NIST 800-63 considers usernames and knoledge based authentication (KBA) as public information, SMS and email notifications as "restricted" authentication types, and password as pre-breached. this reality renders knoledge based authenticators, SMS and email recovery, password history, complexity and rotation controles useless. these controls always have been less than helpful, often forcing users to come up with weak passwords every few months, but with the release of over 5 billion usernames and password breaches, it´s time to move on.

of all the sections in the ASVS, the authentication and session management chapters have changed the most. 

adoption of effective, evidence-based leading practice will be challenging for many, and that´s perfectly okay. we have to start the transition to a post-password future now.

### NIST 800-63 - modern, evidence-based authentication standard
NIST 800-63b is a modern, evidence-based standard, and represents the best advice, regardless of applicability. the starndard is helpful for all organizations all over the world but is particulaly relevant ot US agencies and those dealing with US agencies.

NIST 800-63 terminology can be a little confusing at first, especially if you´re only used to username+password authentication. Advancements in modern authentication are necessary, so we have to introduce terminology that will become commonplace in the future, but we do understand the difficulty in understanding until the industry settles on these new terms. 

### Password Security Requirements
Passwords, called "Memorized Secrets" by NIST 800-63, includes passwords, PINs, unlock patterns, pick the correct kitten or another image element, and passphrases. they are generally considered "somthing you know", and often used as single factor authenticators. there are significant challenges to the continued use of single-factor authentication, including billions of valid usernames and passwords disclosed on the internet, default or weak passwords, rainbow tables and ordered dictionarys of the most common passwords.

applications should strongly encourage users to enrol in multi-factor authentication, and should allow users to re-use tokens they already possess, such as FIDO or U2F tokens, or link to a credential service provider that provides multi-factor authentication.

Credential service providers (CSP) provide federated identity for users. Users will often have more than one identity with multiple CSPs, such as an enterprise identity using Azure AD, Okta, Ping Indentity or google, or consumer identity using facebook, twitter, google or weChat, to name just a few common alternatives. this list is not an endorsement of these companies or services, but simply an encouragement for developers to consider the reality that many users have many established identities. organizations should consider integrating with existing user identities, as per the risk of the CSP´s strength of identity proofing. for example, it is unlikely a government organization would accept a social media identity as a login for sensitive systems, as it is easy to create a fake or throw away identities, whereas a mobile game company may well need to integrate with major social media platforms to grow their active player base.


#### requirements
* verify that user set password are at least 12 characters in length
* verify that passwords 64 characters or longer are permitted
* verify that passwords can contain spaces and truncation is not performed. consecutive multiple spaces MAY optionally be coalesced
* verify that Unicode characters are permitted in passwords. a single Unicode code point is considered a character, so 12 emoji or 64 kanji characters should be valid and permitted
* verify users can change their passwords
* verify that passwords change functionality requires the user´s current and new passwords
* verify that passwords submitted during account registration, login and password change are checked agaist a set of breached passwords either locally (such as the top 1000 or 10000 most common passwords which match the system´s password policy) or using an external API. if using an API a zero knoledge proof or other mechanism should be used to ensure that the plain text password is no sent or used in verifying the breach status of the password. if the password is breached, the application must require the user to set a new non-breached password
* verify that a password strength meter is provided to help users set a stronger password
* verify that there are no password composition rules limiting the type of characters permitted. there should be no requirements for upper or lower case or numbers or special characters
* verify that there are no periodic credential rotation or password history requirements
* verify that "paste" functionality, browser password helpers, and external password managers are permitted.
* verify that the user can choose to either temporarily view the entire masked password, or temporarily view the last typed character of the password on platforms that do not have this as native functionality.

NOTE: the goal of allowing the user to view their password or see the last character temporarily is to improve the usability of credential entry, particularly around the use of longer passwords, passphrases, and password managers. another reason for including the requirement is to deter or prevent test reports unnecessarily requiring organizations to override native platform password field behaviour to remove this modern user-friendly security experience.

### General Authenticator Requirements
Authenticator agility is essential to future-proof applications. Refactor applications verifiers to allow additional authenticators as per user preferences, as well as allowing retiring deprecated or unsafe authenticators in an orderly fashion.

```diff
- NIST considers email and SMS as "restricted" authenticator types, and they are likely to be removed from NIST 800-63 and this the ASVS at some point the future. applications should plan a roadmap that does not require the use of email or SMS.
```
#### Requirements
* verify that anti-automation controls are effective at mitigating breached credential testing, brute force, and account lockout attacks. such controls include blocking the most common breached passwords, soft lockouts, rate limiting, CAPTCHA, ever increasing delays between attempts, IP address restrictions, or risk-based restrictions such as location, fist login on a device, recent attempts to unlock the account, or similar. verify that no more than 100 failed attempts per hour is possible on a single account.
* verify that the use of weak authenticators (such as SMS and email) is limeted to secondary verification and transaction approval and not as a replacement for more secure authentication methods. verify that stronger methods are offered before weak methods, users are aware of the risks, or that proper measures are in place to limit the risk of account compromise.
* verify that secure notifications are sent to users after updates to authentication details, such as credential resets, email or address changes, loggin in from unknown or risky locations. the use of push notifications - rather than SMS or email - is preferred, but in the absense of push notifications, SMS or email is acceptable as long as no sensitive information is disclosed in the notification.

#### Requirements for level 3
* verify impersonation resistance agaist phishing, such as the use of multi-factor authentication, cryptographic devices with intent (such as connected keys with a push to authenticate), or at higher AAL levels, client-side certificates
* verify that where a credential service provider (CSP) and the application verifiyng authentication are separated, muttually authenticated TLS is in place between the two endpoints.
* verify replay resistance through the mandated use of OTP devices, cryptographic authenticators or lookup codes.
* verify intent to authenticate by requiring the entry of an OTP token or user-initiated action such as button press on a FIDO hardware key.


#### o que aprendemos?
* password security requirements
* general authenticator requirements

### Authenticator Lifecycle Requirements
authenticators are passwords, soft tokens, hardware tokens, and biometric devices. the lifecycle of authenticators is critical to the security of an application - if anyone can self-register an account with no evidence of identity, there can be little thrust on the identity assertion. for social media sites like reddit, that´s perfectly okay. for banking systems, a greater focus on the registration and issuance of credentials and devices is critical to the security of the application.

```diff
+ NOTE: passwords are not to have a maximum lifetime or be subject to password rotation. passwords should be checked for being breached, not regularly replaced.
```

#### Requirements
* verify system generated initial passwords or activation codes SHOULD be securely randomly generated, SHOULD be at least 6 characters long, and MAY contain letters and numbers, and expire after a short period of time. these initial secrets must not be permitted to become the long term password.

#### Requirements for level 2 and 3
* verify that enrollment and use of subscriber-provided authentication devices are supported, such as a U2F or FIDO tokens.
* verify that renewal instructions are sent with sufficient time to renew time bound authenticators

### Credential Storage Requirements
architects and developers should adhere to this section when building or refactoring code. this section can only be fully verified using source code review or through secure unit or integration tests. 
```diff
- penetration testing cannot identify any of these issues.
```
the list of approved one-way key derivation functions is datailed in NIST 800-63 B section 5.1.1.2 and in BSI Kryptographische verfahren: Empfehlungen und schlussellangen (2018). the latest national or regional algorithm and key length standards can be chosen in place of these choices.

this section cannot be penetration tested, so controls are not marked as L1. however, this section is of vital importance to the security of credentials if they are stolen, so if forking the ASVS for an archtecture or coding guideline or source code review checklist, please place these controls back to L1 in your private version.

#### Requirements for level 2 and 3
* verify that passwords are stored in a form that is resistant to offline attacks. passwords SHALL be salted and hashed using an approved one-way key derivation or password hashing function. key derivation and password hashing functions take a password, a salt and a cost factor as inputs when generating a password hash.
* verify that the salt is at least 32 bits in length and be chosen arbitrarily to minimize salt value collisions among stored hashes. for each credential, a unique salt value and the resulting hash SHALL be stored.
* verify that PBKDF2 is used, the iteration count SHOULD be as large as verification server performance will allow, tipically at least 100000 iterations
* verifify that if bcrypt is used, the work factor SHOULD be as large as verification server performance will allow, typically at least 13
* verify that an additional iteration of a key derivation function is performed, using a salt value that is secret and known only to the verifier. generate the salt value using an approved random bit generator [SP 800-90Ar1] and provide at least the minimum security strength specified in the latest revision of SP 800-131A. the secret salt value SHALL be stored separately from the hashed passwords (e.g. in a specialized device like a hardware securecity module)

where US standards are mentioned, a regional or local standard can be used in place of or in addition to the US standard as required.

### Credential Recovery Requirements

#### Requirements
* verify that a system generated intial activation or recovery secret is not sent in clear text to the user.
* verify passwords hints or knowledge-based authentication (so-called "secret questions") are not present
* verify password credential recovery does not reveal the current password in any way.
* verify shared or default accounts are not present (e.g. "root", "admin" or "sa")
* verify that if an authentication factor is changed or replaced, that the user is notified of this event
* verify forgotten password and other recovery paths use a secure recovery mechanism, such as TOTP or other soft token, mobile push or another offline recovery mechanism

#### Requirements for level 2 and level 3
* verify that if OTP or multi-factor authentication factors are lost, that evidence of identity proofing is performed at the same level as during enrollment.

### Look-up Secret Verifier
Look up secrets are pre-generated lists of secret codes, similar to Transaction Authorization Numbers (TAN), social media recovery codes, or a grid containing a set of random values. These are distributed securely to users. these lookup codes are used once, and once all used, the lookup secret is discarded. this type of authenticator is considered "something that you have"

#### Requirements for level 2 and level 3
* verify that lookup secrets can be used only once
* verify that lookup secrets have sufficient randomness (112 bits of entropy), or if less than 112 bits of entropy, salted with a unique and random 32-bit salt and hashed with an approved one-way hash.
* verify that lookup secrets are resistant to offline attacks, such as predictable values


### o que aprendemos?
* authenticator lifecycle requirements
* credential recovery requirements
* look-up secret verifier requirements

### Out of Band Verifier
in the past, a common out of band verifier would have been an email or SMS containing a password reset link. attackers use this weak mechanism to reset accounts they don´t yet control, such as taking over a person´s email account and re-using any discovered reset links. there are better ways to handle out of band verification.

secure out of band authenticators are physical devices that can communicate with the verifier over a secure secondary channel. examples include push notifications to mobile devices. this type of authenticator is considered "something you have". when a user wishes to authenticate, the verifying application sends a message to the out of band authenticator via a connection to the authenticator directly or indirectly through a third party service. the message contains an authentication code (typically a random six digit number or a modal approval dialog). the verifying application waits to receive the authentication code through the primary channel and compares the hash of the received valueto the hash of the original code. if they match, the out of band verifier can assume that the user has authenticated.

the ASVS assumes that only a few developers will be developing new out of band authenticators, such as push notifications, and thus the following ASVS controls apply to verifiers, such as authentication API, applications and single sign-on implementations. if developing a new out of band authenticator, please refer to NIST 800-63b $5.1.3.1

unsafe out of band authenticators such as e-mail and VOIP are not permitted. PSTN and SMS authentication are currently "restricted" by NIST and should be deprecated in favor of push notifications or similar. if you need to use telephone or SMS out of band authentication, please see $5.1.3.3

#### Requirements
* verify that clear text out of band (NIST "restricted") authenticators, such as SMS or PSTN, are not offered by default, and stronger alternatives such as push notifications are offered first.
* verify that the out of band verifier expires out of band authentication requests, codes, or yokens after 10 minutes
* verify that the out of band verifier authentication requests, codes or tokens are usable once, and only for the original authentication request.
* verify that the out of band authenticator and verifier communicates over a secure independent channel

#### Requirements for level 2 and level 3
* verify that the out of band verifier retains only a hashed version of the authentication code
* verify that the initial authentication code is generated by a secure random number generator, containing at least 20 bits of entropy (typically a six digit random number is sufficient)

### Single or multi factor one time verifier 
single factor one time passwords (OTP) are physical or soft tokens that display a continually changing pseudo-random one time challenge. these devices make phishing (impersonation) difficult, but not impossible. this type of authenticator is considered "something you have". multi-factor tokens are similar to single factor OTPs, but require a valid PIN code, biometric unlocking, USB insertion or NFC pairing or some additiona value (such as transaction signing calculators) to be entered to create the final OTP.

#### Requirements
* verify that time-based OTP have a defined lifetime before expiring

#### Requirements for level 2 and level 3
* verify that summetric keys used to verify submitted OTPs are highly protected, such as by using a hardware security module or secure operating system based key storage
* verify that approved cryptographic algoritms are used in the generation, seeding and verification
* verify that time-based OTP can be used only once within the validity period
* verify that if a time-based multi factor OTP token is re-used during the validity period, it is logged and rejected with secure notifications being sent to the holder of the device.
* verify physical single factor OTP generator can be revoked in case of theft or other loss. ensure that revocation is immediately effective across loggeg in sessions, regardless of location

#### Requirements for level 3
* verify that biometric authenticators are limited to use only as secondary factors in conjunction with either something you have and something you know

### Cryptographic software and Devices Verifier
Cryptographic security keys are smart cards or FIDO keys, where the user thas to plug in or pair the cryptographic device to the computer to complete authentication. verifiers send a challenge nonce to the cryptographic devices or software, and the device or software calculates a response based upon a securely stored cryptographic key.

the requirements for single factor cryptographic devices and software, and multi-factor cryptographic devices and software are the same, as verification of the cryptographic authenticator proves possession of the authentication factor.

#### Requirements for level 2 and level 3
* verify that cryptographic keys used in verification are stored securely and protected agains disclosure, such as using a TPM or HSM or an OS service that can use this secure storage.
* verify that the challenge nonce is at least 64 bits in length, and statistically unique or unique over the lifetime of the cryptographic device
* verify that approved cryptographic algorithms are used in the generation, seeding and verification

### Service Authentication 
this sections is not penetration testable, so does not have L1 requirements. however, if used in an architecture, coding or secure code review, please assume that software (just as Java Key Store) is the minimum requirement at L1. clear text storage of secrets is not acceptable under any circumstances.

#### Requirements for level 2 (OS assisted) and level 3 (HSM)
* verify that integration secrets do not rely on unchanging passwords, such as API keys or shared privileged accounts
* verify that if passwords are required, the credential are not a default account
* verify that passwords are stored with sufficient protection to prevent offline recovery attacks, including local system access
* verify passwords, integrations with databases and third-party systems, seeds and internal secrets and API keys are managed securely and not included int he source code or stored within source code repositories. such storage SHOULD resist offline attacks. the use of a secure software key store (L1), hardware trusted platform module (TPM) or a hardware security module (L3) is recommended for password storage.

### Additional US Agency Requirements
US Agencies have mandatory requirements concerning NIST 800-63. the Application Security Verification Standard has always been about 80% of controls that apply to nearly 100% of apps, and not the last 20% of advanced controls or those that have limited applicability. as such, the ASVS is a strict subset of NIST 800-63, specially for IAL1/2 and AAL1/2 classifications, but is not sufficiently comprehensive, particularly concerning IAL3/AAL3 classifications.

we strongly urge US governement agencies to review and implement NIST 800-63 in its entirety.

### o que aprendemos?
* out of Band verifier requirements
* single or multi factor one time verifier requirements
* cryptographic software and devices verifier requirements
* sevice authentication requirements

### Session Management Verification
control objective

One of the core components of any web based application or stateful API is the mechanism by which it controls and maintains the state for a user or device interacting with it. session management changes a stateless protocol to stateful, which is critical for differentiating different users or devices.

ensure that a verified application satisfies the following high-level session menagement requirements:
* sessions are unique to each individual and cannot be guessed or shared
* sessions are invalidated when no longuer required and timed out during periods of inactivity

as previously noted, these requirements have been adapted to be a compliant subset of selected NIST 800-63b controls, focused around common threats and commonly exploited authentication weaknesses. previous verification requirements have been retired, de-duped, or in most cases adapted to be strongly aligned with the intent of mandatory NIST 800-63b requirements.

### Fundamental Session Management Requirements
* verify that application never reveals session tokens in URL parameters or error messages

### Session Binding 
#### Requirements
* verify that application generates a new session token on user authentication
* verify that session tokens possess at least 64 bits of entropy
* verify the application only stores session tokens in the browser using secure methods such as appropriately secured cookies (more informations on next chapters) or HTML 5 session storage.

#### Requirements for level 2 and level 3
* verify that session token are generated using approved criptographic algoritms

TLS or another secure transport channel is mandatory for session management. this is covered off in the Communications Security chapter.

### Session logout and timeout 
sessions timeouts have been aligned with NIST 800-63, which permits much longer sessions timeouts than traditionally permitted by security standards. organizations should review the table below, and if a longer timeout is desirable based around the application´s risk, the NIST value should be the upper bounds of sessions idle timeouts.
L1 in this context is IAL1/AAL1, L2 is IAL2/AAL3, L3 is IAL3/AAL3. for IAL2/AAL2 and IAL3/AAL3, the shorter idle timeout is, the lower bound of idle times for being logged out or re-authenticated ro resume the session.

#### Requirements
* verify that logout and expiration invalidate the session token, such that the back button or a downstream relying party does not resume an authenticated session, including across relying parties.
* if authenticators permit users to remain logged in, verify that re-authentication occurs periodically both when actively used or after an idle period. for level 1 it should be 30 days, for level 2 it should be 12 hours or 30 minutes of inactivity, 2FA optional and for level 3 it should be 12 hours or 15 minutes of inactivity with 2FA
  
#### Requirements for level 2 and level 3
* verify that the application terminates all other active sessions after a successfull password change, and that this is effective across the application, federated login (if present) and any relying parties
* verify that users are able to view and log out of any or all currently active sessions and devices

### Cookie-based Session Management
#### Requirements
* verify that cookie-based session tokens have the 'Secure' attribute set
* verify that cookie-based session tokens have the 'HttpOnly' attribute set
* verify that cookie-based session tokens utilize the 'SameSite' attribute to limit exposure to cross-site request forgery attacks
* verify that cookie-based session tokens use "__Host-" prefix (see report references) to provide session cookie confidentiality
* verify that if the application is published under a domain name with other applications that set or use session cookies that might override or disclose the session cookies, set tha path attribute in cookie-based sessions tokens using the most precise path possible

### Token-based Session Management
token-based session management includes JWT, OAuth, SAML and API Keys. of these, API keys are known to be weak and should not be used in new code.

#### Requirements for level 2 and level 3
* verify the application does not treat OAuth and refresh tokens - on their own - as the presence of the subscriber and allows users to terminate thrust relantionships with linked applications.
* verify the application uses sessions tokens rather than static API secrets and keys, except with legacy implementations
* verify that stateless session tokens use digital signatures, encryption and other countermeasures to protect agaist tampering, enveloping, replay, null cypher and key substitution attacks

### Re-authentication from a Federation or Assertion
this section relates to those writing relying party (RP) or credential service provider (CSP) code. if relying on code implementing these features, ensure that these issues are handled correctly.

#### Requirements for level 3
* verify that relying parties specify the maximum authentication time to CSPs and that CSPs re-authenticate the subscriber if they haven´t used a session within that period
* verify that CSPs inform relying parties of the last authentication event, to allow RPs to determine if theu need to re-authenticate the user.

### Defenses Against Session Management Exploits
there are a small number of session management attacks, some related to the user experience (UX) of sessions. previously, based on ISO 27002 requirements, the ASVS has required blocking multiple simultaneous sessions. blocking simultaneous sessions is no longer appropriate, not only as modern users have many devices or the app is an API without a browser session, but in most of these implementations, the last authenticator wins, which is often the attacker. this section provides leading guidance on deterring, delaying and detecting session management attacks using code.

#### description of the half-open attack
in early 2018, several financial institutions were compromised using what the attackers called "half-open attacks". this term has stuck in the industry. the attackers struck multiple institutions with different proprietary code bases, and indeed it seems different code bases within the same institutions. the half-open attack is exploiting a design pattarn flaw commonly found in many existing application, session management and access control systems.

attackers start a half-open attack by attempting to lock, reset or recover a credential. a popular session management design pattern re-uses user profile session objects/models between unauthenticated, half-authenticated (passwords resets, forgot username) and fully authenticated code. this design pattern populates a valid session object ot token containing the victim´s profile, including password hashes and roles. if access control checks in controllers or routers does not correctly verify that the user is fully logged in, the attacker will be able to act as the user. attacks could include changing the users password to a know value, update the email address to perform a valid password reset, disable multi-factor authentication or enroll a new MFA device, reveal or change API Keys, and so on.

#### Requirements
* verify the application ensures a valid login session or requires re-authentication or secondary verification before allowing any sensitive transactions or account modifications.

### o que aprendemos?
* fundamental session management requirements
* session binding requirements
* session logout and timeout requirements
* cookie-based session management
* token-based session management
* defenses against session management exploits

### Access Control Verification
control objective
authorization is the concept of allowing access to resources only to those permitted to use them. ensure that a verified application satisfies the following high level requirements:
* persons accessing resources hold valid credentials to do so
* users are associated with a well-defined set of roles and privileges
* role and permission metadata is protected from replay or tampering

### General Access Control Design
#### Requirements
* verify that the application enforces access control rules on a trusted service layer, especially if client-side access control is present and could be bypassed
* verify that all user dan data attributes and policy information used by access controls cannot be manipulated by end users unless specifically authorized
* verify that the principle of least privilege exists - users should only be able to access functions, data files, URLs, controllers, services and other resources, for which they possess specific authorization. this implies protection agaist spoofing and elevation of privilege
* verify that the principle of deny by default exists whereby new users/roles start with minimal or no permissions and users/roles do no receive access to new features until access is explicittly assigned
* verify that access control fail securely including when an exception occurs

### Operation Level Access Control
#### Requirements
* verify that sensitive data and APIs are protected agaist direct object attacks targetting creation, reading, updating and deletion of records, such as creating or updating someone else´s record, viewing everyone´s records or deleting all records
* verify that the application or framework enforces a strong anti-CSRF mechanism to protect authenticated functionality, and effective anti-automation or anti-CSRF protects unauthenticated functionality

### Other Access Control Considerations
#### Requirements
* verify admnistrative interfaces use appropriate multi-factor authentication to prevent unauthorized use
* verify that directory browsing is disabled unless deliberately desired. additionally, applications should not allow discovery or disclosure of file directory metadata, such as Thumbs.db, .DS_Store, .git or .snv folders

#### Requirements for level 2 and level 3
* verify the application has additional authorization (such as step up or adaptive authentication) for lower value systems, and / or segregation of duties for high value applications to enforce ant-fraud controls as per the risk of application and past fraud.

### o que aprendemos?
* general access control design
* operation level access control
* other access control considerations

### Validation, Sanitization and Encoding Verification
control objectives
the most common web applications security weakness is the failure to properly validate input coming from the client or the enviroment before directly using it without any output encoding. this weakness leads to almost all of the signficant vulnerabilities in web applications, such as Cross-site Scripting (XSS), SQL injection, interpreter injection, locale/unicode attacks, file system attacks and buffer overflows.

ensure that a verified application satisfies the following high-level requirements:
* input validation and output encoding archtecture have an agreed pipeline to prevent injections attacks
* input data is strongly typed, validated, range or length checked or at worst, sanitized or filtered
* output data is encoded or escaped as per the context of the data as close to the interpreter as possible.

with moder web applications actchtecture, output encoding is more important than ever. it is difficult to provide robust input validation in certains scenarios, so the use of API such as parameterized queries, auto-escaping templating frameworks, or carefully chosen output encoding is critical to the security of the application

### Input Validation 
Properly implemented input validations controls, using positive whitelisting and strong data typing, can eliminate more than 90% of all injections attacks. length and range checks can reduce this further. building in secure input validation is required during application architecture, design sprints, codign and unit and integration testing. although many of these items cannot be found in penetration tests, the result of not implementing them are usually found in Output encoding and Injection Prevention requirements. developers and secure code reviwers are recommendend to treat this section as if L1 is required for all items to prevent injections.

#### Requirements
* verify that the applications has defenses against HTTP parameter pollution attacks, particularly if the applications framework makes no distinction about the source of request parameters (GET, POST, cookies, headers or enviroment variables)
* verify that frameworks protects agaist mass parameter assignment attacks, or that the applications has countermeasures to protec against unsage parameter assignment, such as marking fields private or similar
* verify that all input (HTML form fields, REST requests, URL parameters, HTTP headers, cookies, batch files, RSS feeds, etc) is validated using positive validation (whitelisting)
* verify that structured data is strongly typed and validated agaist a defined schema including allowed characters, length and pattern (e.g. credit card numbers or telephone, or validationg that two related fields are reasonable, such as checking that suburb and zip/postcode match)
* verify that URL redirects and forwards only allown whitelisted destinations of show a warning when redirecting to potentially untrusted content

### Sanitization and Sandboxing
#### Requirements
* verify that all untrusted HTML input from WYSIWYG editors or similar is properly sanitized with an HTML sanitizer library or framework feature
* verify that unstructured data is sanitized to enforce safety maesures such as allowed characters and length
* verify that the application sanitizes user input before passing to mail systems to protect agaist SMTP or IMAP injection
* verify that the application avoids the use of eval() or other dynamic code execution features. where there is no alternative, any user input being included must be sanitized or sandboxed before being executed
* verify that the application protects agaist template injection attacks by ensuring that any user input being included is sanitized or sandboxed
* verify that the application protects agaist SSRF attacks, by validationg or sanitizing untrusted data or HTTP file metadata, such as filenames and URL input fields, use whitelisting of protocols, domains, paths and ports
* verify that the application sanitizes, disables or sandboxes user-supplied SVG scriptable content, specially as they relate to XSS resulting from inline scripts, and foreignObject
* verify that the application sanitizes, disables, or sandboxes user-supplied scriptable or expression template language content, such as Markdown, CSS or XSL stylesheets, BBCode or similar.

### o que aprendemos?
* input validation requirements
* sanitization and sandboxing requirements
* como pode ser feito um ataque de SSRF misturando conceitos na pratica

### Output Encoding and Injection Prevention
output encoding close or adjacent to the interpreter in use is critical to the security of any application. typically, output encoding is not persisted, but used to render the output safe in the appropriate output context for immediate use. failing to output encode will result in an insecure, injectable and unsafe application.

#### Requirements
* verify that output encoding is relevant for the interpreter and context required. for example, use encoders specifically for HTML values, HTML attributes, javascript, URL parameter, HTTP headers, SMTP and others as the context requires, specially from untrusted inputs (e.g. names qith unicode or apostrophes)
* verify that output encoding preserves the user´s chosen character set and locale, such that any unicode character point is valid and safely handled
* verify that context-aware, preferably automated - or at worst manual - output escaping protects agaist reflected, stored and DOM based XSS
* verify that data selection or database queries (e.g. SQL, HQL, ORM, NoSQL) use parameterized queries, ORMs, entity frameworks or are otherwise protected from database injection attacks
* verify that where parameterized or safer mechanisms are not present, context-specific output encoding is used to protect against injection attacks, such as the use of SQL escaping to protect against SQL injection
* verify that the application projects agaist javascript or JSON injection attacks, including for eval attacks, remote JavaScript includes, CSP bypasses, DOM XSS and javascript expression evaluation
* verify that the application protects agais LDAP injection vulnerabilities, or that specific security controls to prevent LDAP injection have been implemented
* verify that the application protects agaisnt OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding
* verify that the application protects against Local File Inclusion (LFI) or Remote File Inclusion (RFI) attacks
* verify that the application protects agaisnt XPath injection or XML injection attacks

```diff
- NOTE: using parameterized queries or escaping SQL is not always sufficient; table and column names, ORDER BY and so on cannot be escaped. the inclusion of escaped user-supplied data in these fields results in failed queries or SQL injections.
```

```diff
- NOTE: the SVG format explicitly allows ECMA script in almost all contexts, so it may not be possible to block all SVG XSS vectors completely. if SVG upload is required, we strongly recommend either serving these uploaded files as text/plain or using a separate user supplied content domain to prevent successful XSS from taking over the application.
```

### Memory, String and Unmanaged Code 
the following requirements will only apply when the application uses a systems language or unmanaged code
#### Requirements for level 2 and level 3
* verify that the application uses memory-safe string, safer memory copy and pointer arithmetic to detect or prevent stack, buffer or heap overflows
* verify that format strings do no take potentially hostile input and are constant
* verify that sign, range, and input validation techniques are used to prevent integer overflows

### Deserialization Prevention
#### Requirements
* verify that serialized objects use integrity checks or are encrypted to prevent hostile object  creation or data tampering
* verify that the application correctly restricts XML parsers to only use the most restrictive configuration possible and to ensure that unsafe features such as resolving external entities are disabled to prevent XXE
* verify that deserialization of untrusted data is avoidded or is protected in both custom code and third-party libraries (such as JSON, XML and YAML parsers)
* verify that when parsing JSON in browsers or javascript-based backends, JSON.parse is used to parse the JSON document. DO NOT USE eval() TO PARSE JSON.
  
### o que aprendemos?
* output encoding and injection prevention
* deserialization prevention techniques

### Stored Cryptography Verification
control objective
ensure that a verifified application satisfies the following high level requirements:
* all cryptographic modules fail in a secure manner and that errors are handled correctly
* a suitable random number generator is used
* access to keys is securely managed

### data classification
the most important asset is the data processed, stored or transmitted by an application. always perform a privacy impact assessment to classify the data protection needs of any stored data correctly

#### Requirements for level 2 and level 3
* verify that regulated private data is stored encrypted while at rest, such as personally identifiable information (PII), sensitive personal information or data assessed likely to be subject to EU´s GDPR
* verify that regulated health data is stored encrypted while at rest, such as medical records, medical device details or de-anonymized research records.
* verify that regulated financial data is sotred encrypted while at rest, such as financial accounts, defaults or credit history, tax records, pay history, beneficiaries, or de-anonymized market or research records

### Algorithms
recent advances in cryptography mean that previously safe algorithms and key lengths are no longer safe or sufficient to protect data. therefore, it should be possible to change algorithms.

although this section is not easily penetration tested, developers should consider this entire section as mandatory even though L1 is missing from most of the items.

#### Requirements
* verify that all cryptographic modules fail securely, and errors are handled in a way that does not enable Padding Oracle attacks.

#### Requirements for level 2 and level 3
* verify that industry proven or government approved cryptographic algorithms, modes, and libraries are used, instead of custom coded cryptography
* verify that encryption initialization vector, cipher configuration, and block modes are configured securely using the latest advice.
* verify that random number, encryption or hashing algorithms, key lenghts, rounds, ciphers or modes, can be reconfigured, upgraded or swapped at any time, to protect agains cryptographic breaks
* verify that known insecure block modes (i.e. ECB etc), padding modes (i.e. PKCS#1 v1.5, etc), ciphers with small block size (i.e. Triple-DES, Blowfish, etc), and weak hashing algorithms (i.e MD5, SHA1, etc) are not used unless required for backwards compatability
* verify that nonces, initialization vectors, and other single use numbers must not be used more than once with given encryption key. the method of generation must be appropriate for the algorithm being used

#### Requirements for level 3
* verify that encrypted data is authenticated via signatures, authenticated cipher modes or HMAC to ensure that ciphertext is not altered by unauthorized party
* verify that all cryptographic operations are constant-time, with no 'short-circuit' operations in comparisons, calculations or returns to avoid leaking information.

### Random values
true pseudo-random number generation (PRNG) is incredbly difficult to get rigth. generally, good sources of entropy within a system will be quickly depleted if over-used, but sources with less randomness can lead to predictable keys and secrets.

#### Requirements for level 2 and level 3
* verify that all random numbers, random file names, random GUIDs, and random strings are generated using the cryptographic module´s approved cryptographically secure random number generator when these random values are intended to be not guessable by an attacker
* verify that random GUIDs are created using the GUID v4 algorithm and a cryptographically-secure pseudo-random number generators may be predictable
  
#### Requirements for level 3
* verify that random numbers are created with proper entropy even when the application is under heavy load, or that the application degrades gracefully in such circumstances

### Secret Management
although this section is not easily penetration tested, developers should consider this entire section as mandatory even though L1 is missing from most of the items

#### Requirements for level 2 and level 3
* verify that a secrets management solution such as a key vault is used to securely create, store, control access to and destroy secrets
* verify that key material is not exposed to the application but instead uses an isolated security module like a vault for cryptographic operations

### o que aprendemos?
* Stored Cryptoghraphy Verification Requirements

### Error Handling and logging Verification Requirements
control objective
the primary objective of error handling and logging is to provide useful information for the user, administrators, and incident response teams. the objective is not to create massive ammounts of logs, but high quality logs, with more signal than discarded noise.

high quality logs will often contain sensitive data, and must be protected as per local data privacy laws or directives. this should include:

* not collecting or logging sensitive information unless specifically required
* ensuring all logged information is handled securely and protected as per its data classification
* ensuring that logs are not stored forever, but have an absolute lifetime that is as short as possible

if logs contain private or sensitive data, the definition of which varies from country to country, the logs become some of the most sensitive information held by the application and thus very attractive to attackers in their own right
it is also important to ensure that the application fails securely and that errors do not disclose unnecessary information.

### Log Content
Logging sensitive information is dangerous - the logs become classified themselves, which means they need to be encrypted, become subject to retention policies and must be disclosed in security audits. ensure only necessary information is kept in logs, and certainly no payment, credentials (including session tokens), sensitive or personally identifiable information.

this section covers OWASP Top 10 2017:A10. as 2017:A10 and this section are not penetration testable, it´s important for:
* developers to ensure full compliance with this section, as if all items were marked as L1
* penetration testers to validate full compliance of all items in this section via interview, screenshots or assertions

#### Requirements
* verify that the application does not log credentials or payment details. session tokens should only be stored in logs in an irreversible, hash form
* verify that the application does not log other sensitive data as defined under local privacy laws or relevant security policy

#### Requirements for level 2 and level 3
* verify that the application logs security relevant events including successful and failed authentication events, access control failures, deserialization failures and input validation failures
* verify that each log event includes necessary information that would allow for a detailed investigation of the timeline when an event happens

### Log Processing
timely logging is critical for audit events, triage and escalation. ensure that the application´s logs are clear and can be easily monitored and analyzed either locally or log shippedt to a remote monitoring system.

this section covers OWASP top 10 2017:A10. as 2017:A10 and this section are not penetration testable, it´s important for:
* developers to ensure full compliance with this section, as if all items were marked as L1
* penetration testers to validate full compliance of all items in this section via interview, screenshots or assertions

#### Requirements for level 2 and level 3
* verify that all authentication decisions are logged, without storing sensitive session identifiers or passwords. this should include requests with relevant metadata needed for security investigations
* verify that all access control decisions can be logged and all failed decisions are logged. this should include requests with relevant metadata needed for security investigations.

### Log Protection
logs that can be trivially modified or deleted are useless for investigations and prossecutions. disclosure of logs can expose inner details about the application or the data it contains. care must be taken when protecting logs from unautorized disclosure, modification or deletion.

#### Requirements for level 2 and level 3
* verify that the application appropriately encodes user-supplied data to prevent log injection
* verify that all events are protected from injection when viewed in log viewing software
* verify that security logs are protected from unauthorized access and modification
* verify that time sources are synchronized to the correct time and time zone. strongly consider logging only in UTC if systems are global to assist with post-incident forensic analysis

```diff
+ NOTE: Log encoding is difficult to test and review using automated dynamic tools and penetration tests, but architects, developers and source code reviewers should consider it an L1 requirement.
```

### Error Handling
the purpose of error handling is to allow the application to provide security relevant events for monitoring, triage and escalation. the purpose is not to create logs. when logging security related events, ensure that ther is a purpose to the log, and that it can be distinguished by SIEM or analysis software

#### Requirements
* verify that a generic message is shown when an unexpected or security sensitive error occurs, potentially with a unique ID which support personnel can use to investigate.
  
#### Requirements for level 2 and level 3
* verify that exception handling (or a functional equivalent) is used acress the codebase to account for expected and unexpected error conditions
* verify that a "last resort" error handler is defined which will catch all unhandled exceptions

NOTE: certain languages, such as Swift and Go - and though common design practice - many functional languages, do not support exceptions or last resort event handlers. in this case, architects and developers should use a pattern, language or framework friendly way to ensure that applications can securely handle exceptional, unexpected or security-related events.

### o que aprendemos?
* Log Content Requirements
* Log Processing Requirements
* Log Protection Requirements
* Error Handling

### Data Protection Verification
control objective
there are three key elements to sound data protection: Confidentiality, integrity and availability (CIA). this standard assumes that data protection is enforced on a trusted system, such as a server, which has been hardened and has sufficient protections.

applications have to assume that all users devices are compromised in some way. where an application transmits or stores sensitive information on insecure devices, such as shared computers, phones and tablets, the application is responsible for ensuring data stored on these devices is encrypted and cannot be easily illicitly obtained, altered or disclosed.

ensure that a verified application satisfies the following high level data protection requirements:
* confidentiality: data should be protected from unauthorized observation or disclosure both in transit and when stored
* integrity: data should be protected from being maliciously created, altered or deleted by unauthorized attackers.
* availability: data should be available to authorized users as required

### General data protection
#### Requirements for level 2 and level 3
* verify that application protects sensitive data from being cached in server components such as load balancers and application caches.
* verify that all cached or temporary copies of sensitive data stored on the server are protected from unauthorized access or purged/invalidated after the authorized user accesses the sensitive data
* verify the application minimizes the number of parameters in a request, such as hidden fields, Ajax variables, cookies and header values
* verify the application can detect and alert on abnormal numbers of requests, such as by IP, user, total per hour or day, or whatever makes sense for the application

#### Requirements for level 3
* verify htat regular backups of important data are performed and that test restoration of data is performed
* verify that backups are stored securely to prevent data from being stolen or corrupted

### Client-side Data Protection
#### Requirements
* verify the application sets sufficient anti-caching headers so that sensitive data is not cached in modern browsers
* verify that data stored in client side storage (such as HTML5 local storage, session storage, IndexedDB, regular cookies or Flash cookies) does not contain sensitive data or PII
* verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated.

### Sensitive Private Data
this section helps protect sensitive data from being created, read, updted or deleted without authorization, particularly in bulk quantities.

compliance with this section implies compliance with V4 Access Control and in partivular V4.2. for example, to protect against unauthorized updates or disclosure of sensitive personal information requires adherence to V4.2.1.

please comply with this section and V4 for full coverage.

NOTE: privacy regulations and laws, such as the Australian Privacy Principles APP-11 or GDPR, directly affect how applications must approach the implementation of storage, use, and transmition of sensitive personal information. this ranges from severe penalties to simple advice. please consult your local laws and regulations, and consult a qualified privacy specialist or lawyer as required.

#### Requirements
* verify that sensitive data is sent to the server in the HTTP message body or headers, and that query string parameters from any HTTP verb do not contain sensitive data
* verify that users have a method to remove or export their data on demand
* verify that users are provided clear language regarding collection and use of supplied personal information and that users have provided opt-in consent for the use of that data before it is used in any way
* verify that all sensitive data created and processed by the application has been identified, and ensure that a policy is in place on how to deal with sensitive data

#### Requirements for level 2 and level 3
* verify accessing sensitive data is audited (without logging the sensitive data itself), if the data is collected under relevant data protection directives or where logging of access is required
* verify that sensitive information contained in memory is overwritten as soon as it is no longer required to mitigate memory dumping attacks, using zeroes or random data
* verify that sensitive or private information that is required to be encrypted, is encrypted using approved algorithms that provide both confidentiality and integrity
* verify that sensitive personal information is subject to data retention classification, such that old or out of date data is deleted automatically, on a schedule, or as the situation requires

when considering data protection, a primary consideration should be around bulk extraction or modification or excessive usage. for example, many social media systems only allow users to add 100 new friends per day, but which system these requests came from is not important. a banking platform might wish to block more than 5 transactions per hour transferring more than 1000 euro of funds to external institutions. each system´s requirements are likely to be very different, so deciding on "abnormal" must consider the threat model and business risk. important criteria are the ability to detect, deter or preferably block such abnormal bulk actions.

### o que aprendemos?
* General Data Protection
* Client-side Data Protection
* Sensitive Private Data

### Communications Verification
control objective
ensure that a verified application satisfies the following high level requirements:
* TLS or strong encryption is always used, regardless of the sensitivity of the data being transmitted
* the most recent, leading configuration advice is used to enable and order preferred algorithms and ciphers
* weak or soon to be deprecated algorithms and ciphers are ordered as a last resort
* deprecated or known insecure algorithms and ciphers are disabled

leading industry advice on secure TLS configuration changes frequently, often due to catastrophic breaks in existing algorithms and ciphers. always use the most recent versions of TLS configuration review tools (such as a SSLyze or other TLS scanners) to configure the preferred order and algorithm selection. configuration should be periodically checked to ensure that secure communications configuration is always present and effective.

### Communications Security 
all client communications should only take place over encrypted communication paths. in particular, the use of TLS 1.2 or later is essentially all but required by modern browsers and search engines. configuration should be regurlaly reviewed using online tools to ensure that the latest leading practices are in place.

#### Requirements
* verify that secured TLS is used for all client connectivity, and does not fall back to insecure or unencrypted protocols
* verify using online or up to date TLS testing tools that only strong algorithms, ciphers and protocols are enabled, with the strongest algorithms and ciphers set as preferred
* verify that old versions of SSL and TLS protocols, algorithms, ciphers and configuration are disabled, such as SSLv2, or TLS 1.0 and TLS 1.1. the latest version of TLS should be the preferred cipher suite.

### Server Comunication Security
Server communications are more than just HTTP. Secure connections to and from other systems, such as monitoring systems, management tools, remote access and ssh, middleware, database, mainframes, partner or external source systems -- must be in place. all of these must be encrypted to prevent "hard on the outside, trivially easy to intercept on the inside"

#### Requirements for level 2 and level 3
* verify that connections to and from the server use trusted TLS certificates. where internally generated or self-signed certificates are used, the server must be configured to only trust specific internal CAs and specific self-signed certificates. all others should be rejected
* verify that encrypted communications such as TLS is used for all inbound and outbound connections, including for management ports, monitoring, authentication, API or web services calls, database, cloud, serverless, mainframe, external, and partner connections. the server must not fall back to insecure or unencrypted protocols
* verify that all encrypted connections to external systems that involve sensitive information or functions are authenticated
* verify that proper certification revogation, such as Online Certificate Status Protocol (OCSP) Stapling, is enabled and configured
* verify that backend TLS connection failures are logged

### o que aprendemos?
* Communications Verification Requirements
* Communications Security Requirements
* Server Communications Security Requirements

### Malicious Code Verification
control objective
ensure that code satisfies the following high level requirements:
* malicious activity is handled securely and properly to not affect the rest of the application
* does not have time bombs or other time based attacks
* does not "phone home" to malicious or unauthorized destinations
* does not have back dors, Easter Eggs, salami attacks, rootkits, or unauthorized code that can be controlled by an attacker

findind malicious code is proof of the negative, which is impossible to completely validate. best efforts should be undertaken to ensure that the code has no inherent malicious code or unwanted functionality

### Code integrity Controls
the best defense against malicious code is "trust, but verify". introducing unauthorized or malicious code into code is often a criminal offence in many jurisdictions. policies and procedures should make sanctions regarding malicious code clear.
lead developers should regularly review code check-ins, particularly those that might access time, I/O, or network functions.

#### Requirements for level 3
* verify that a code analisys tool is in use that can detect potentially malicious code, such as time functions, unsage file operations and network connections.
  
### Malicious Code Search
malicious code is extremely rare and is difficult to detect. manual line by line code review can assist looking for logic bombs, but even the most experienced code reviewer will struggle to find malicious code even if they know it exists.
complying with this section is not possible without complete access to source code, including third-party libraries

#### Requirements for level 2 and level 3
* verify that the application source code and third party libraries do not contain unauthorized phone home or data collection capabilities. where such functionality exists, obtain the user´s permission for it to operate before collecting any data
* verify that the application does not ask for unnecessary or excessive permissions to privacy related features or sensors, such as contacts, cameras, microphones, or location

#### Requirements for level 3
* verify that the application source code and third party libraries do not contain back doors, such as hard-coded or additional undocumented accounts or keys, code obfuscation, undocumented binary blobs, rootkits, or anti-debugging, insecure debugging features or otherwise out of date, insecure or hidden functionality that could be used maliciously if discovered
* verify taht the application source code and third party libraries does not contain time bombs by searching for date and time related functions
* verify that the application source code and third party libraries does not contain malicious code, such as salami attacks, logic bypasses or logic bombs
* verify that the application source code and third party libraries do not contain Easter Eggs or any other potentially unwanted functionality

### Deployed Application Integrity Controls
once an application is deployed, malicious code can still be inserted. Applications need to protect themselves agaist common attacks, such as executing unsigned code from untrusted sources and sub-domain takeovers.

complying with this section os likely to be operational and continuos

#### Requirements
* Verify that if the application has a client or server auto-update, updates should be obtained over secure channels and digitally signed. the update code must validate the digital signature of the update before installing or executing the update
* verify that the application employs integrity protections, such as code signing or sub-resource integrity. the application must not load or execute code from untrusted sources, such as loading includes, modules, plugins, code or libraries from untrusted sources or the internet
* verify that the application has protection from sub-domain takeovers if the application relies upon DNS entries or DNS sub-domains, such as expired domain names, out of date DNS pointers or CNAMEs, expired projects at public source code repos or transient cloud APIs, serverless functions or storage buckets (autogen-bucket-id.cloud.example.com) or similar. protections can include ensuring that DNS names used by applications are regurlarly checked for expiry or change.

### o que aprendemos?
* Malicious Code Verification Requirements
* Deployed Application Integrity Controls

### Business Logic Verification
control objective
ensure that a verified application satisfies the following high level requirements:
* the business logic flow is sequential, processed in order and cannot be bypassed
* business logic includes limits to detect and prevent automated attacks, such as continuous small funds transfers or adding a million friends one at a time, and so on
* high value business logic flows have considered abuse cases and malicious actors, and have protections against spoofing, tampering, repudiation, information disclosure and elevation of privilege attacks

### Business Logic Security
business logic security is so individual to every application that no one checklist will ever apply. business logic security must be designed in to protect agaist likely external threats - it cannot be added using web application firewalls or secure communications. we recommend the use of threat modeling during design sprints, for example, using the OWASP Cornucopia or similar tools

#### Requirements
* verify that application will only process business logic flows for the same user in sequential step order and without skipping steps
* verify the application will only process business logic flows with all steps being processed in realistic human time, i.e. transactions are not submitted too quickly
* verify the application has appropriate limits for specific business actions or transactions which are correctly enforced on a per user basis
* verify the application has sufficient anti-automation controls to detect and protect agaist data exfiltration, excessive business logic requests, excessive file uploads or denial of service attacks
* verify the application has business logic limits or validation to protect against likely business risks or threats, identified using threat modeling or similar methodologies

#### Requirements for level 2 and level 3
* verify the application does not suffer from "time of check to time of use" (TOCTOU) issues or other race conditions for sensitive operations
* verify the application monitors for unusual events or activity from a business logic perspective. for example, attempts to perform actions out of order or actions which a normal user would never attempt
* verify the application has configurable alerting when automated attacks or unusual activity is detected

### o que aprendemos?
* Business Logic Security Requirements
* Business Logic Verification Requirements

### File and Resources Verification
control objective
ensure that a verified application satisfies the following high level requirements:
* untrusted file data should be handled accordingly and in a secure manner
* untrusted file data obtained from untrusted sources are stored outside the web root and with limited permissions

### File Upload
although zip bombs are eminently testable using penetration testing techniques, they are considered L2 and above to encourage design and development consideration with careful manual testing, and to avoid automated or unskilled manual penetration testing of a denial of service condition.

#### Requirements
* verify that the application will not accept large files that could fill up storage or cause a denial of service attack

#### Requirements for level 2 and level 3
* verify that compressed files are checked for "zip bombs" - smaill input files that will decompress into huge files thus exhausting file storage limits
* verify that a file size quota and maximum number of files per user is enforced to ensure that a single user cannot fill up the storage with too many files, or excessively large files

### File Integrity
#### Requirements for level 2 and level 3
* verify that files obtained from untrusted sources are validated to be of expected type based on the file´s content

### File Execution
### Requirements
* verify that user-submitted filename metadata is not used directly with system or framework file and URL API to protect against path traversal
* verify that user-submitted filename metadata is validated or ignored to prevent the disclosure, creation, updating or removal of local files (LFI)
* verify that user-submitted filename metadata is validated or ignored to prevent the disclosure or execution of remote files (RFI), which may also lead to SSRF
* verify that the application protects against reflective file download (RFD) by validating or ignoring user-submitted filenames in a JSON, JSONP, or URL parameter, the response Content-Type header should be set to text/plain, and the Content-Disposition header should have a fixed filename
* verify that untrusted file metadata is not used directly with system API or libraries, to protect agaist OS command injection

#### Requirements for level 2 and level 3
* verify that the application does not include and execute functionality from untrusted sources, such as unverified content distribution networks, javascript libraries, node npm libraries or server-side DLLs

### File Storage
#### Requirements
* verify that files obtained from untrusted sources are stored outside the web root, with limited permissions, preferrably with strong validation
* verify that files obtained from untrusted sources are scanned by anti-virus scanners to prevent upload of known malicious content

### File Download
#### Requirements
* verify that the web tier is configured to serve only files with specific file extensions to prevent unintentional information and source code leakage. for example, backup files (e.g. .bak), temporary working files (e.g. swp), compressed files (.zip, .tar.gz, etc) and other extensions commonly used by editors should be blocked unless required
* verify that direct requests to upload files will never be executed as HTML/Javascript content.

### SSRF Protection
#### Requirements
* Verify that the web or application server is configured with a whitelist of resources or systems to which the server can send requests or load data/files from

### o que aprendemos?
* File and Resource Verification Requirements
* File Upload Requirements
* File Execution Requirements
* File Upload Requirements
* File Download Requirements
* SSRF Protection Requirements

### API and Web Service Verification
control objective
Ensure that a verified application that uses trusted service API (commonly using JSON or XML or GraphQL) has:
* adequate authentication, session management and authorization of all web services
* input validation of all parameters that transit from a lower to higher trust level
* effective security controls for all API types, including cloud and Serverless API

please read this chapter in combination with all other chapters at this same level; we no longer duplicate authentication or API session management concerns

### Generic Web Service Security Verification
#### Requirements
* verify that all application components use the same encodings and parsers to avoid parsing attacks that exploit different URI or file parsing bahaviour that could be used in SSRF and RFI attacks
* verify that access to administration and management functions is limited to authorized administrators
* verify that API URL do no expose sensitive information, such as the API key, session tokens, etc

#### Requirements for level 2 and level 3
* verify that authorization decisions are made at both the URI, enforced by programmatic or declarative security at the controller or router, and at the resource level, enforced by model-based permissions
* verify that requests containing unexpected or missing content types are rejected with appropriate headers (HTTP response status 406 Unacceptable or 415 Unsupported Media Type)

### RESTful Web Service Verification
JSON Schema validation is in a draft stage of standardization. when considering using JSON schema validation, which is best practice for SOAP web services, consider using these additiona data valiation strategies in combination with JSON schema validation
* parsing validation of the JSON object, such as if there are missing or extra elements
* validation of the JSON object values using standatd input validation methods, such as data type, data format, length, etc
* and formal JSON schema validation

once the JSON schema validation standatd is formalized, ASVS will update its advice in this area. carefully monitor any JSON schema validation libraries in use, as they will need to be updated regurlarly until the standard is formalized and bugs are ironed out of reference implementations

#### Requirements
* verify that enabled RESTful HTTP methods are a valid choice for the user or action, such as preventing normal users using DELETE or PUT on protected API or resources
* Verify that JSON schema validation is in place and verified before accepting input
* verify that RESTful web services that utilize cookies are protected from Cross-site Request Forgery via the use of at least one or more of the following: triple or double submit cookie pattern, CSRF nonces, or ORIGIN request header checks

#### Requirements for level 2 and level 3
* verify that REST services have anti-automation controls to protect against excessive calls, specially if the API is unauthenticated
* verify the REST services explicitly check the incoming Content-Type to be the expected one, such as application/xml or application/JSON
* verify that the message headers and payload are trustworthy and not modified in transit. requiring strong encryption for transprot (TLS only) may be sufficient in many cases as it provides both confidentiality and integrity protection. per-messate digital signatures can provide additional assurance on top of the transport protections for high security applications but bring with them additional complexity and risks to weigh against the benefits

### SOAP Web Service Verification
#### Requirements
* verify that XSD schema validation takes place to ensure a properly formed XML document, followed by validation of each input field before any processing of that data takes place

#### Requirements for level 2 and level 3
* verify that the message payload is signed using WS-Security to ensure reliable transport between client and service

```diff
- NOTE: due to issues with XXE attacks against DTDs, DTD validation should not be used, and framework DTD evaluation disabled as per the requirements set ou in the next chapter configuration
```

### GraphQL and other Web Service Data Layer Security
#### Requirements for level 2 and level 3
* verify that query whitelisting or a combination of depth limiting and amount limiting should be used to prevent GraphQL or data layer expression denial of service (DoS) as a result of a expensive, nested queries. for more advanced scenarios, query cost analysis should be used
* verify that GraphQL or other data layer authorization logic should be implemented at the business logic layer instead of GraphQL layer.

### o que aprendemos?
* API and Web Service Verification Requirements
* Generic Web Service Security Verification Requirements
* RESTful Web Service Verification Requirements
* SOAP Web Service Verification Requirements

### Configuration Verification
control objective
ensure that a verified application has:
* A secure, repeatable, automatable build enviroment
* hardened third party library, dependency and configuration management such that out of date or insecure components are not included by the application
* a secure-by-default configuration, such that administrators and users have to weaken the default security posture

configuration of the application out of the box should be safe to be on the internet, which means a safe out of the box configuration

### Build
build pipelines are the basis for repeatable security - every time something insecure is discovered, it can be resolved in the source code, build or deployment scripts, and tested automatically. we are strongly encouraging the use of build pipelines with automatic security and dependency checks that warn or breakthe build to prevent known security issues being deployed into production. manual steps performed irregularly directly leads to avoidable security mistakes.

as the industry moves to a DevSecOps model, it is important to ensure the continued availability and integrity of deployment and configuration to achieve a "known good" state. in the past, if a system was hacked, it whould take days to months to prove that no further intrusions had taken place. today, with the advent of software defined infrastructure, rapid A/B deployments with zero downtime and automated containerized builds, it´s possible to automatically and continuously build, harden, and deploy a "known good" replacement for any compromised system.

if traditional models are still im place, then manual steps must be taken to harden and backup that configuration to allow the compromised systems to be quickly replaced with high integrity, uncompromised systems in a timely fashion.

compliance with this section requires an automated build system, and access to build and deployment scripts

#### Requirements for level 2 and level 3
* verify that the application build and deployment processes are performed in a secure and repeatable way, such as CI / CD automation, automated configuration management, and automated deployment scripts
* verify that compiler flags are configured to enable all available buffer overflow protections and warnings, including stack randomization, data execution prevention, and to break the build if an unsafe pointer, memory, format string, integer or string operations are found
* verify that server configuration is hardened as per the recommendations of the application server and frameworks in use
* verify that the application, configuration, and all dependencies can be re-deployed using automated deployment scripts, built from a documented and tested runbook in a reasonable time, or restored from backups in a timely fashion

#### Requirements for level 3
* verify that authorized administrators can verify the integrity of all security-relevant configurations to detect tampering

### Dependency
dependency management is critical to the safe operation of any application of any type. failure to keep up to date with outdated or insecure dependencies is the root cause of the largest and most expensive attacks to date.

NOTE: at level 1, the first requirement compliance relates to observations or detections of client-side and other libraries and components, rather that the more accurate build-time static code analysis or dependency analysis. these more accurate techniques could be discoverable by interviews as required.

#### Requirements
* verify that all components are up to date, preferably using a dependency checker during build or compile time
* verify that all unneeded features, documentation, samples, configurations are removed, such as sample applications, platform documentation and default or example users
* verify that if application assets, such as javascript libraries, CSS stylesheets or web fonts, are hosted externally on a content delivery network (CDN) or external provider, Subresource integrity (SRI) is used to validate the integrity of the asset

#### Requirements for level 2 and level 3
* verify that third party components come from pre-defined, trusted and continually maintened repositories
* verify that an invetory catalog is mantained of all third party libraries in use
* verify that the attack surface is reduced by sandboxing or encapsulating third party libraries to expose only the required behaviour into the application

### Unintended Security Disclosure
configurations for production should be hardened to protect against common attacks, such as debug consoles, raise the bar for cross-site scripting (XSS) and remote file inclusion (RFI) attacks, and to eliminate trivial information discovery "vulnerabilities" that are the unwelcome hallmark of many penetration testing reports. many of these issues are rarely rated as a significant risk, but they are chained together with other vulnerabilities.

if these issues are not present by default, it raises the bar before most attacks can succeed

#### Requirements
* verify that web or application server and framework error messages are configured to deliver user actionable customized responses to eliminate any unintended security disclosures
* verify that web or application server an application framework debug modes are disabled in production to eliminate debug features, developer consoles, and unintended security disclosures
* verify that HTTP headers or any part of the HTTP response do not expose detailed version information of systems components

###  HTTP Security Headers
#### Requirements
* verify that every HTTP response contains a content type header specifying a safe character set (e.g. UTF-8, ISO 8859-1)
* verify that all API responses contain Content-Disposition: attachment; filename="api.json" (or other appropriate filename for the content type)
* verify that a content security policy (CSPv2) is in place that helps mitigate impact for XSS attacks like HTML, DOM, JSON, and javascript injections vulnerabilities
* verify that all responses contains X-Content-Type-Options: nosniff
* verify that HTTP Strinct Transport Security Headers are included on all responses and for all subdomains, such as Strict-Transport-Security: max-age= 15724800; includeSubdomains
* verify that a suitable "Referrer-Policy" header is included, such as "no-referrer" or "same-origin"
* verify that a suitable X-Frame-options or Content-Security-Policy: frame-ancestors header is in use for sites where content should not be embedded in a third-party site

### Validate HTTP Request Header
#### Requirements
* verify that the application server only accepts the HTTP methods in use by the application or API, including pre-flight OPTIONS
* verify that the supplied Origin header is not used for authentication or access control decisions, as the Origin header can easily be changed by an attacker
* verify that the cross-domain resource sharing (CORS) Access-Control-Allow-Origin header uses a strict whitelist of trusted domains to match against and does not support the 'null' origin
* verify that HTTP headers added by a trusted proxy or SSO devices, such as a bearer token, are authenticated by the application

### o que aprendemos?
* Configuration Verification Requirements
* Dependency
* Unintended Security Disclosure Requirements
* HTTP Security Headers Requirements
* Validate HTTP Request Header Requirements



