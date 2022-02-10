# Formaçao OWASP
iniciado em 07/02/2022

terminado em ANDAMENTO

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



