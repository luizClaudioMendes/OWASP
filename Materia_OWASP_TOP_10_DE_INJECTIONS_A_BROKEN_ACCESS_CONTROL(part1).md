# Formaçao OWASP
iniciado em 20/01/2022

terminado em 03/02/2022

[certificate](https://cursos.alura.com.br/certificate/5f456457-c213-4f3f-b10b-1f8a60d91f3d) 

Table of contents
- [Formaçao OWASP](#formaçao-owasp)
  - [OWASP](#owasp)
    - [sobre OWASP](#sobre-owasp)
    - [OWASP top 10](#owasp-top-10)
  - [OWASP Top 10: de injections a Broken Access Control](#owasp-top-10-de-injections-a-broken-access-control)
    - [OWASP Top Ten e Injection](#owasp-top-ten-e-injection)
    - [A1 Injection](#a1-injection)
    - [prevençao de injeçao](#prevençao-de-injeçao)
    - [onde testar?](#onde-testar)
    - [o que aprendemos?](#o-que-aprendemos)
  - [A2 Broken Authentication](#a2-broken-authentication)
    - [prevençao](#prevençao)
    - [o que aprendemos?](#o-que-aprendemos-1)
  - [A3 sensitive data exposure](#a3-sensitive-data-exposure)
    - [outros ataques](#outros-ataques)
    - [como prevenir?](#como-prevenir)
    - [o que aprendemos?](#o-que-aprendemos-2)
  - [A4 XML external entities](#a4-xml-external-entities)
    - [como prevenir?](#como-prevenir-1)
    - [o que aprendemos?](#o-que-aprendemos-3)
  - [A5 Broken Access Control](#a5-broken-access-control)
    - [example attack scenarios](#example-attack-scenarios)
    - [como previnir?](#como-previnir)
    - [o que aprendemos?](#o-que-aprendemos-4)

## OWASP

aprenda a lidar com o top 10 dos maiores riscos de segurança em uma aplicaçao web e conheça o padrao de verificaçao de segurança de aplicações.

[link](https://cursos.alura.com.br/formacao-owasp)

### sobre OWASP
the Open Web Application Security Project ou OWASP é uma organizaçao que trabalha com objetivo de aprimorar a segurança de software.

### OWASP top 10
um dos trabalhos do grupo é atualizar um relatorio com o top 10 dos maiores riscos de segurança em uma aplicaçao web.

nesta formaçao, vamos conhecer cada item dessa lista, criar padroes de verificaçoes em cima desse relatorio e, por fim, vamos trabalhar com Clojure, resolvendo os itens desse relatorio

<p>&nbsp;</p>
<p>&nbsp;</p>

## OWASP Top 10: de injections a Broken Access Control

OWASP é uma organização que emite um relatorio, e desse ultimo relatorio vamos ver o top 10.

esse relatorio sai de anos em anos. o ultimo relatorio é de 2017 e contem mudanças com relaçao ao anterior, que foi de 4, 5 anos atras.

entao, de tempos em tempos vemos atualizaçoes no relatorio mas isso nao significa que quando sai um novo relatorio o antigo deixa de ter validade.

na verdade, quase tudo do antigo se mantem e basicamente se adicionam coisas novas ou alteram algumas recomendaçoes.

agora vamos ver os 5 primeiros desse top 10, quais sao os principais riscos que uma aplicaçao web sofre, e claro, toda aplicaçao que utiliza web como infraestrutura tambem passa.

entao se nos estamos falando de um aplicativo que utiliza web para se comunicar com servidor, la nos vamos ter esses riscos.

entao nos vamos falar sobre esses riscos, onde eles aparecem, como nos podemos tentar retifica-los, se nos estivermos passando por isso. 

como nos podemos atacar eles de uma maneira estatica, analisando codigo fonte, por exemplo ou de maneira dinamica, testando.

como nos podemos resolver esses problemas e tentar diminuir esses riscos ou as chances de eles ocorrerem conosco.

claro, para voce que é desenvolvedor de uma aplicaçao web ou de serviços web, é muito bom nos aprendermos isso para que nos criemos um habito de boas praticas de segurança.

entao a ideia aqui é nos utilizarmos tecnicas defensivas, para que nos possamos nos prevenir de possiveis riscos e ataques que possam acontecer mundo afora.

### OWASP Top Ten e Injection

### A1 Injection
bom, primeiro vamos entrar no site da [OWASP](https://owasp.org/www-project-top-ten/) que produz a lista de riscos top 10, alem de diversos outros relatorios. mas neste caso nos interessa o top 10.

voce pode ir navegando por cada um desses. a versao atual aqui, a mais recente, é a versao de 2017.

o primeiro deles é o A1-Injection

entao o que é injeçao? No relatorio tem uma parte especifica descrevendo cenarios de injeçao, como funciona.

Description
An application is vulnerable to attack when:

User-supplied data is not validated, filtered, or sanitized by the application.

Dynamic queries or non-parameterized calls without context-aware escaping are used directly in the interpreter.

Hostile data is used within object-relational mapping (ORM) search parameters to extract additional, sensitive records.

Hostile data is directly used or concatenated. The SQL or command contains the structure and malicious data in dynamic queries, commands, or stored procedures.

Some of the more common injections are SQL, NoSQL, OS command, Object Relational Mapping (ORM), LDAP, and Expression Language (EL) or Object Graph Navigation Library (OGNL) injection. The concept is identical among all interpreters. Source code review is the best method of detecting if applications are vulnerable to injections. Automated testing of all parameters, headers, URL, cookies, JSON, SOAP, and XML data inputs is strongly encouraged. Organizations can include static (SAST), dynamic (DAST), and interactive (IAST) application security testing tools into the CI/CD pipeline to identify introduced injection flaws before production deployment.

How to Prevent
Preventing injection requires keeping data separate from commands and queries:

The preferred option is to use a safe API, which avoids using the interpreter entirely, provides a parameterized interface, or migrates to Object Relational Mapping Tools (ORMs).
Note: Even when parameterized, stored procedures can still introduce SQL injection if PL/SQL or T-SQL concatenates queries and data or executes hostile data with EXECUTE IMMEDIATE or exec().

Use positive server-side input validation. This is not a complete defense as many applications require special characters, such as text areas or APIs for mobile applications.

For any residual dynamic queries, escape special characters using the specific escape syntax for that interpreter.
Note: SQL structures such as table names, column names, and so on cannot be escaped, and thus user-supplied structure names are dangerous. This is a common issue in report-writing software.

Use LIMIT and other SQL controls within queries to prevent mass disclosure of records in case of SQL injection.

Example Attack Scenarios
Scenario #1: An application uses untrusted data in the construction of the following vulnerable SQL call:

```
String query = "SELECT \* FROM accounts WHERE custID='" + request.getParameter("id") + "'";

```

Scenario #2: Similarly, an application’s blind trust in frameworks may result in queries that are still vulnerable, (e.g., Hibernate Query Language (HQL)):


```
Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");

```

In both cases, the attacker modifies the ‘id’ parameter value in their browser to send: ‘ or ‘1’=’1. 

For example:


```
http://example.com/app/accountView?id=' or '1'='1

```

This changes the meaning of both queries to return all the records from the accounts table. More dangerous attacks could modify or delete data or even invoke stored procedures.

entao, primeiro, com a injeçao, nos temos que lembrar que quando nos estamos na internet, nos estamos com um servidor longe e nos somos um cliente. entao toda vez que eu estou acessando um site, eu estou no meu cliente, que é o navegador, mandando uma requisiçao para o servidor e o servidor devolvendo uma resposta.

entao nos sempre estamos fazendo isso. entao quando eu estou em um site e clico em entrar, eu estou falando: olha me de o link da pagina de entrar. me de a pagina dessa URL e o servidor devolve essa pagina.

e quando preenchemos o formulario de login, estamos tambem enviando dados e recebendo respostas.

a questao é: isso daqui é a base dos cursos de web que nos aprendemos, entao o que pode ser feito para evitar a injection?

o formulario é uma situaçao diferente.

o formulario é um local especial onde permitimos que o usuario insira dados que vamos utilizar em uma busca, diferente de um request solicitando apenas um link.

nos nao estamos somente pedindo uma pagina, estamos enviando informaçoes extras e provavelmente no outro lado do servidor ele vai fazer alguma coisa com essas informaçoes.

no caso do login, ele ira procurar no banco de dados se existe um usuario com esse email e com essa senha.

entao quando clico em 'entrar', o servidor vai procurar no banco de dados e nos devolver, encontrei ou nao encontrei o que procurava.

os bancos de dados hoje em dia estao em todo lugar em que precisamos ter um comportamento dinamico.

e o banco de dados nao é necessariamente SQL, entao repare que o que estou dizendo é que em requisicoes web é muito comum que uma aplicaçao do outro lado va buscar coisas no banco, ou vá fazer alguma coisa com as informaçoes que o usuario final fornece.

tudo sao informaçoes que o usuario passa para o servidor.

e o servidor nao deve confiar que essa informaçao foi passada de forma adequada, pois nao tem como saber se voce seguiu o link, se a pessoa que digitou realmente sabia o que queria ou se enviou informaçoes maliciosas.

o cliente pode tentar enviar coisas diferentes como comandos, descobrindo assim alguma coisa no seu servidor.

todos os locais que recebem informaçoes providas pelo usuario final nós devemos tomar alguns cuidados.

porque esses locais sao onde o usuario pode injetar coisas no servidor.

exemplo:

```
select * from usuarios where email = 'teste@teste.com' and senha = '1234'
```

se a query para buscar um usuario que tenha esse usuario e essa senha no banco, parece ok, mas existem algumas coisas que podemos fazer a mais.

nos costumamos limitar a um so retorno, para termos a certeza que nos so traremos um usuario, so o primeiro. nos nao precisamos de mais de um se tivermos o mesmo email e senha. ate porque, nos nao esperamos encontrar isso.

eu poderia trazer so o ID do usuario se eu quiser, entao estou colocando restriçoes.

mas de qualquer maneira, isso daqui serviu para validarmos e verificarmos se o usuario esta la ou nao. 

o nome de usuario vem de alguma maneira na nossa requisiçao web, do 'request'.

entao, por exemplo, em java teriamos um 'request.getParameter("email") e entao lemos o email passado no parametro.

a senha seria um 'request.getParameter("senha")'

entao temos esse select bonito e voce pode se questionar: o campo email o usuario tem que colcar um email.

mas existem formas de se burlar isso.

o SQL que usamos nao é estatico como o exemplo, usamos os parametros passados pelo usuario, que ficaria assim:

```
String usuario = request.getParameter("usuario")
String senha = request.getParameter("senha")


String sql = "select * from usuarios where email = '" + usuario + "' and senha = '" + senha + "'

```

essa forma permite o injection!!!

nao estamos validando o usuario e a senha antes de usar no banco.

se o usuario passar no campo usuario, por exemplo:

```
' or admin = true //

```

o que geraria este SQL malicioso:

```
select * from usuarios where email = '' or admin = true // and senha = 1234

```

a injeçao funciona. ele iria procurar por um usuario com email vazio, que nao deve existir ou por um usuario com a coluna de admin como true.

o comentario faria a query ignorar a parte da senha e retornaria todos os usuarios onde o campo admin fosse true.

existem varias formas de se comentar SQL, dependendo do banco utilizado, como por exemplo um #, /* */, //, etc

o usuario sempre esta chutando a arquitetura do banco, nesse caso ele chutou que existe uma coluna booleana chamada admin.

mas isso nao importa. o que importa é que nao validamos o que foi inserido pelo usuario.

a abordagem de concatenar string é muito ruim!

pior ainda, o usuario poderia enviar:

```
'; drop table usuarios 

```

ele iria ficar com dois comandos agora, um select vazio de fachada e logo em seguida um comando para deletar a tabela de usuarios.

de alguma maneira precisamos validar os dados passados pelo usuario.

poderiamos fazer manualmente o escape de todos os caracteres especiais de banco de dados, mas dessa forma estariamos aumentando ainda mais os riscos, pois nunca estariamos protegidos de todas as formas que o usuario poderia executar comandos maliciosos.

teriamos que nos proteger de tanta coisa que nao seria possivel cobrir todos os cenarios.

é importante validar no cliente? sim
é suficiente somente validade no cliente? nao
é importante verificar os dados passados pelo cliente? sim
é importante sanitizar os dados passados pelo cliente? sim

mas para fazermos isso devemos utilizar formas automatizados, com o uso de bibliotecas que farao a sanitizacao, como por exemplo o hibernate ou o jdbc.

nao confie em qualquer coisa que o usuario final passe para o servidor.

### prevençao de injeçao

uma aplicaçao é vulneravel quando usamos qualquer informaçao passada pelo usuario sem nenhum tipo de validaçao.

SQL é só um exemplo, pois existem varias outras formas de vulnerabilidade como por exemplo executar comandos no sistema operacional, etc.

entao como previnir?

a melhor maneira é localizar, verificando o codigo, tanto visualmente, como por ferramentas automatizadas de analise de codigo.

mas como corrigir?

* a maneira preferivel é utilizar um API segura. nao devemos sanitizar na mao, porque deixaremos brechas.

ao inves de concatenar string, essas ferramentas fazem a sanitizacao dessas informaçoes, como por exemplo o prepared statment, onde colocamos:

```
senha = ? and usuario = ? 

```

e o jdbc faz a sanitizaçao usando

```
preparedStatement.setString(1, senha)
preparedStatment.setString(2, usuario)

```

* usar ferramentas ORMs, como o hibernate

tanto o hibernate quanto o jdbc tem formas de sanitizar os parametros.

* limitar o endpoint para somente receber os parametros necessarios ao inves de confiar na URL. ex:

nao usar a URL diretamente, e sim criar os parametros, como no nosso exemplo, o parametros usuario e o parametro senha, dessa forma serao ignorados quaisquer outros parametros inseridos pelo usuario nao URL

* para qualquer query dinamica em que voce nao conseguiu utilizar as ideias acima, faça a sanitizaçao das informaçoes, lembrando que NAO CONFIE EM DADOS PASSADOS PELOS CLIENTES.

* use limit para evitar expor dados desnecessarios.

se a query trara somente um usuario, por exemplo, limite na query a quantidade de resultados, ou na programaçao limite a somente um retorno de objeto e nao um retorno de lista, ou somente as colunas que voce precisa, como por exemplo somente o id ao inves de usar o *. 

se somente precisa do id, somente use o id.

assim previne-se a exposiçao de dados desnecessarios.

o mais importante é:

NAO CONCATENE STRING COM INFORMAÇOES PASSADAS PELOS USUARIOS!

### onde testar?

entao onde podemos testar esses ataques?

posso escolher um site e ficar testando o injection?

NAO!

voce nao pode sair testandos sites aleatoriamente sem permissao, sem saber como funciona.

se o outro lado permite que voce utilize robos, automatizaçoes, etc para descobrir falhas na segurança.

tome cuidado!!!

isso provavelmente será reconhecido como um ataque e nao como forma de ajudar o outro lado.

o trabalho de melhorar a segurança interna é em nossa empresa e em nossos projetos.

entao seja com ferramentas estaticas, dinamicas, etc ou olhando o codigo fonte, nos vamos fazer isso onde nos temos o direito de fazer um teste, explorar, etc.

tome muito cuidado para nao sair executando teste em tudo o que é site porque isso vai ser considerado um ataque e VOCE VAI TER QUE RESPONDER PELO ATAQUE que esta sendo feito.

entao nao faça isso onde voce nao tem o direito de acesso ou direito de fazer testes, faça somente dentro da sua equipe, onde voe tem a permissao de testar o sistema, em um ambiente local.

NAO É PARA CHEGAR EM PRODUÇAO E TESTAR!!!

produçao nao se testa!

se testa no ambiente local.

tome cuidado!

execute local, na sua maquina, isoladamente e sem usuarios e senhas reais, para que voce possa descobrir falhas de segurança na sua maquina!

### o que aprendemos?
* o que é injeçao
* onde ela pode ocorrer
* como corrigir

## A2 Broken Authentication

senhas muito utilizadas tambem sao um fator de segurança.

palavras fixas como 'senha', 'amor', 'senha123' sao senhas muito comuns.

porque as pessoas usam este tipo de senha?

porque é facil de lembrar.

e nós abrimos um buraco, se nos permitimos que o nosso sistema aceite essas senhas, nos temos um buraco extra, que é pessoas usando essas senhas terem facilidade de serem hackeadas por outros usuarios.

lembrando: nao teste isso em sistemas externos, teste isso onde voce tem o direito, onde voce conversou com a equipe e voce pode fazer esse teste localmente.

existem sites que tem as senhas mais comuns, voce pode procurar por most common passwords owasp e voce vai ter la as senhas.

podemos observar que a mais usada é 'password', depois 123456 e depois o que? 12345678. porque?
porque tem site que pede no minimo 8 digitos.

entao um dos problemas é o fato do seu site aceitar senhas comuns.

se voce quer tapar o maximo de buracos possiveis de uma maneira ainda confortavel para os usuarios entao devemos criar uma lista ou algo semelhante como regras, de senhas nao permitidas.

essa é uma forma da sua aplicaçao estar vulneravel.

lembrando: nao faça isso em sites que voce nao tenha o direito!

como é que percebo entao que a aplicaçao esta vulneravel?
* permitir credencial stuffing, que é basicamente voce acreditar que o site é superseguro e que ninguem nunca vai conseguir entrar no servidor.

pode ate ser verdade, mas a autenticaçao quebrada n~çao é só alguem entrar no seu banco e pegar usuario e senha das pessoas, não é só isso.

sempre vemos noticias de vazamento de dados de sites. tem alguns banco de dados de senhas vazadas que sao vendidos por hackers.

embora a senha esteja provavelmente encriptografada, ela esta esposta. 

os hackers conseguem fazer o match e pronto, tem sua senha.

ou seja, nao precisa hackear o site, so precisa tentar as senhas para o usuario que ele conhece.

entao imagine que ele conseguiu a sua senha que voce usou em um site pequeno mas que é a mesma usada naquele marketplace gigante, entao ele vai conseguir entrar usando seu usuario e senha.

Description
Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user's limits. Common access control vulnerabilities include:

Violation of the principle of least privilege or deny by default, where access should only be granted for particular capabilities, roles, or users, but is available to anyone.

Bypassing access control checks by modifying the URL (parameter tampering or force browsing), internal application state, or the HTML page, or by using an attack tool modifying API requests.

Permitting viewing or editing someone else's account, by providing its unique identifier (insecure direct object references)

Accessing API with missing access controls for POST, PUT and DELETE.

Elevation of privilege. Acting as a user without being logged in or acting as an admin when logged in as a user.

Metadata manipulation, such as replaying or tampering with a JSON Web Token (JWT) access control token, or a cookie or hidden field manipulated to elevate privileges or abusing JWT invalidation.

CORS misconfiguration allows API access from unauthorized/untrusted origins.

Force browsing to authenticated pages as an unauthenticated user or to privileged pages as a standard user.

How to Prevent
Access control is only effective in trusted server-side code or server-less API, where the attacker cannot modify the access control check or metadata.

Except for public resources, deny by default.

Implement access control mechanisms once and re-use them throughout the application, including minimizing Cross-Origin Resource Sharing (CORS) usage.

Model access controls should enforce record ownership rather than accepting that the user can create, read, update, or delete any record.

Unique application business limit requirements should be enforced by domain models.

Disable web server directory listing and ensure file metadata (e.g., .git) and backup files are not present within web roots.

Log access control failures, alert admins when appropriate (e.g., repeated failures).

Rate limit API and controller access to minimize the harm from automated attack tooling.

Stateful session identifiers should be invalidated on the server after logout. Stateless JWT tokens should rather be short-lived so that the window of opportunity for an attacker is minimized. For longer lived JWTs it's highy recommended to follow the OAuth standards to revoke access.

Developers and QA staff should include functional access control unit and integration tests.

Example Attack Scenarios
Scenario #1: The application uses unverified data in a SQL call that is accessing account information:


```
 pstmt.setString(1, request.getParameter("acct"));
 ResultSet results = pstmt.executeQuery( );

```

An attacker simply modifies the browser's 'acct' parameter to send whatever account number they want. If not correctly verified, the attacker can access any user's account.


 https://example.com/app/accountInfo?acct=notmyacct

Scenario #2: An attacker simply forces browses to target URLs. Admin rights are required for access to the admin page.


```
 https://example.com/app/getappInfo
 https://example.com/app/admin_getappInfo

```

If an unauthenticated user can access either page, it's a flaw. If a non-admin can access the admin page, this is a flaw.

```diff
- stuffing.
```

se voce tem uma lista de usuarios e de senhas validas ele vai la e tenta.

entao nos tambem vamos ter que, de alguma maneira, incentivar as pessoas a usarem uma senha unica no nosso site, mas nao tem como saber que a pessoa passou uma senha unica, que ele nao usou em outro site. nao temos o controle sobre a pessoa nisso.

entao devemos ter regras para tentarmos facilitar isso para as pessoas mas dificultar para os invasores.

nao devemos permitir ataques de força bruta.

força bruta meio que testa tudo, tentando todas as possibilidades.

exemplo, se o atacante souber o usuario, ele fica testando o usuario com a senha A, B, C, D, E, F, etc, ate conseguir entrar.

de novo, nao faça isso em sites verdadeiros! faça somente no seu proprio site interno, dentro da sua maquina, sem o banco de dados de produçao, etc.

```diff
- permitir senhas padroes
```

entao tem muitos sistemas que voce instala tipo mysql, wordpress, etc e ele ja vem com usuario e senha padrao.

nao pode ter usuario e senha padrao, porque se tiver essas serao as primeiras que serao testadas.

```diff
- senhas muito comuns ou senhas fracas
```

senhas fracas sao um desafio. nao devemos obrigar o usuario a usar 500 caracteres e tal porque se colocar regras de senhas muito complexas, o que a pessoa faz? ela usa a mesma senha dos outros sites. 

porque ela nao vai decorar, entao ela usa a mesma senha em varios sites.

e dessa forma permitimos o stuffing de novo.

entao a regra nao pode ser idiota, nao pode ser so uma regrinha boba, mas voce nao quer tambem uma regra complexa demais e que faça com que a pessoa use copy/paste.

claro, se possivel, nos vamos incentivar as pessoas a usarem gerenciadores de senha que geram senhas complexas ou algo do genero.

```diff
- processos de recuperaçao de senha inefectivos ou fracos
```
por exemplo, aqueles processos de senha que voce por exemplo pergunta alguma coisa, tipo "qual o nome do seu primeiro cachorro?", etc.

perguntas do genero, que nao sao perguntas seguras pois outras pessoas podem saber essas informaçoes sobre voce.

a senha como eu estou descrevendo ate agora é um codigo que voce sabe, é uma coisa que só voce sabe e isso é fundamental.

```diff
- salvar a senha direto no banco sem encriptografar
```

se voce fizer isso, qualquer pessoa que acesse o banco de dados terao acesso claro à senha.

todas as senhas deverao ser encriptografadas

```diff
+ ter multi-factor authentication
```

ter autenticaçao multifator aumenta a segurança.

os fatores sao:
* algo que voce é
* algo que voce tem
* algo que voce sabe

algo que voce é, é por exemplo, sua digital, sua iris

algo que voce tem é, por exemplo, um celular, uma conta de email, etc

algo que voce sabe é, por exemplo, uma senha

se voce usar dois desses fatores voce tem multi-factor authentication, que diminiu muito a chance de alguem se logar se passando por outra pessoa.

```diff
- expor ID de seçao na URL
```

as vezes, quando nos comunicamos com o servidor, ele responde um cookie ou um ID de seçao para nos identificar.

so que é comum aparecer na URL por exemplo o campo JSESSION_ID ou qualquer tipo de id.

isso é errado!

e se alguem pega essa URL e abre em outro pc, para o server essa outra pessoa é a pessoa logada.

cada vez que a pessoa se loga, gera-se um novo session id, fazendo o antigo deixar de valer.

e quando a pessoa se deslogar, deve-se alem de limpar os cookies e etc no cliente, deve-se deletar tambem o session id dela no server, inviabilizando qualquer acesso daquele usuario, mesmo em outras maquinas.

lembre-se: NUNCA CONFIE NO CLIENTE!

```diff
- rotaçao de senha 
```

antigamente era recomendado que tivesse a reciclagem da senha, tipo, depois de uns 2 meses, solicitando a mudança da senha. ai voce era obrigado a mudar a senha.

mas o que realmente acontece com os usuarios?

na terceira vez que ele recebe isso ele nao fica feliz e usa a mesma senha que usa em outro site, porque nao da para ficar decorando senhas complexas toda hora.

antigamente era considerado boa pratica fazer a rotaçao de senha, mas perceberam que encorajava os usuarios a utilizarem senhas fracas e reutilizar senhas em varios sites.

```diff
+ timeout de seçoes
```

a seçao mesmo por padrao, tem que ter um timeout, tipo:

depois de x tempo sem a pessoa acessar, essa pessoa é deslogada do sistema.

aquela forma de identificar que aquela pessoa era ela deixa de ser valida (tipo um cookie ou um session id) e agora ela precisa se logar novamente.

claro que depende do quao perigoso seria uma pessoa acessar aqueles dados que ela esta logada. porque a conveniencia de nos ficarmos logado em um sistema é nao termos que ficar nos logando toda hora.

### prevençao

entao como nos previnir?

* quando possivel, implementar login 'multi-factor'.

porque se é multi-factor e a pessoa recebe um codigo no celular dela atraves de um aplicativo, de um token em um aplicativo, generico ou da sua propria aplicaçao web aumenta a segurança.

ou ela tem que mostrar alguma outra forma de identificaçao, alem de uma senha que ela sabe, isso ja limita muito.

porque isso limita?

porque alem de ter que saber a senha, ela precisa ter acesso àquele dispositivo.

isso inviabiliza o credencial stuffing puro, porque nao adianta so saber a senha, inviabiliza o brutal force puro só da senha.

* nao colocar de maneira alguma usuarios e senhas padroes para usuarios de administraçao. 

* implementar checks de senhas simples, como testar por exemplo, contra a lista dos 10000 senhas mais usadas. se estiver na lista, informe ao usuario que a senha dele é fraca.

a norma NIST 800-63-B é uma boa guideline

o tamanho minimo da senha depende do tamanho do estrago que o roubo de credencial pode ter no sistema. coisas muito importantes devem ter maior nivel de segurança.

na norma esta melhor detalhado do que no OWASP.

* evitar mensagens de ataque de enumeraçao.

entao por exemplo, se eu digo em uma mensagem de tentativa errada de login que o usuario nao existe estou transmitindo uma informaçao sensivel para o atacante que aquele usuario nao existe....

se o usuario existir mas a senha esta incorreta e informo na mensagem que a senha esta incorreta, ja estou confirmando para o atacante que o usuario esta correto e que basta tentar acessar a senha com brutal force por exemplo para conseguir o acesso.

a mensagem de erro de login deve ser o mais vaga possivel, tipo "usuario ou senha invalidos"

isso se aplica tambem ao processo de recuperaçao de senha, de cadastro, etc.

novamente, nao teste isso em sites verdadeiros. somente na sua propria empresa, no seu projeto, onde voce tem permissao para fazer esses testes.

* diminuir o limite de logins falhos

se o usuario tentar 3 milhoes de vezes fazer login e nao consegue provavelmente é um ataque e voce ja poderia ter bloqueado esse IP, por precauçao.

* log na aplicaçao quando alguem tentar se logar como administrador e nao conseguir

* gerencie os ids de sessao de uma forma boa.

os numeros de id de sessao devem ser randomicos. os frameworks que vao ser utilizados vao ser randomicos por padrao.

* os sessions ID nao devem estar na URL e devem ser invalidados no servidor tambem, nos momentos adequados.

### o que aprendemos?

* o problema da força bruta
* o problema de senhas comuns
* credential stuffing
* o que voce tem, quem voce é e o que voce sabe
* a importancia da criptografia
* multi-factor
* session ids
* diversas ideias de como prevenir

## A3 sensitive data exposure
o proximo risco é a parte de exposiçao de dados sensiveis.

entao nessa situaçao, nos temos informaçoes que nos gostariamos de manter escondidas, mas de repente, elas estao abertas para outras pessoas que nao deveriam acessá-las.

um exemplo é a senha do usuario estar gravada de forma aberta no banco de dados. qualquer pessoa com acesso ao banco de dados poderá ve-la.

uma comunicaçao web, passa por muitos lugares, entre o cliente e o servidor. temos o cliente (browser), o roteador, a empresa de internet, os hubs, o load balancer, os servidores, o banco de dados, etc.

cada um desses pontos pode significar uma falha na segurança.

entao do que precisamos?

em formularios com informaçoes sensiveis, como por exemplo um login, precisamos ter HTTPS, e hoje em dia voce vai ver que em 99% dos sites vao ter HTTPS.

o cadeado indica que é uma requisiçao HTTPS com certificado, com os dados encriptografados na ida e na volta.

entao isso nos traz a gatantia que esta sendo criptigrafado em uma ponta e enviado para o outro lado e que o outro lado tem acesso a essa informaçao.

mas ali no meio do caminho, os intermediarios, as pessoas que estao no meio, o 'man in the middle', nao tem acesso à informaçao em si, a essa informaçao descriptografada.

o termo 'man in the middle' aqui nao este sendo usado no sentido de um ataque mas no sentido de que voce tem varias pessoas ali no meio, varios individuos, varios nós para chegar do outro lado.

o ataque de 'man in the middle' é voce se posicionar ali no meio da conversa justamente para escutar a conversa dos dois lados e voce ve a conversa descriptografada e tira as informaçoes sensiveis que voce quer tirar ali do meio. 

esse é o ataque.

entao no momento que voce tem varias camadas, nos temos que tomar esse cuidado de criptografar essa comunicaçao. 

entao aqui na parte de exposiçao de dados sensiveis, nao é so la no banco de dados, de estar gravado, tem que se preocupar em que as informaçoes sensiveis nao trafeguem de maneira aberta.

exemplos de dados sensiveis: senhas, numeros de cartoes de credito, informaçoes de saude, informaçoes pessoais, negocios secretos de outros negocios, etc.

e devemos nos preocupar ainda mais se, os dados trafegados necessitam seguir alguma lei, como a LGPD por exemplo.

entao se os dados estao sendo transmitidos de um lado para o outro, nao importa se é HTTP, SMTP, FTP etc, se estiverem limpos e soltos, entao qualquer pessoa ali no meio consegue interceptar.

como nos nao temos como garantir a rota do nosso servidor ate ao cliente, o que fazemos no servidor é utilizar HTTPS, assim ele encriptografa no cliente e no servidor.

se for SMTP, FTP etc eles vao ter outros protocolos, mas o importante é estar criptografado do cliente ate ao servidor.

mas lembrando, os dados ao serem persistidos, devem ser criptografados tambem.

no log da aplicaçao tambem devera ser tomada atençao para nao logar informaçoes que identifiquem o cliente ou ate mesmo informaçoes sensiveis.

o backup do banco de dados tambem. 

as vezes voce mantem backup antigo do banco de dados, onde essas informaçoes ainda estavam expostas.

utilizar algoritmos de criptografia antigos ou fracos, tambem é uma falha.

com o passar do tempo certos algoritmos vao descobrindo certas falhas e tem que ser atualizados.

nao utilizar os valores padroes nas senhas dos aplicativos ou ferramentas, tipo o banco de dados.

a criptografia deve ser forçada sempre.

nao podemos permitir que existam caminhos que contornem a criptografia, como por exemplo manter uma pagina de login ainda em HTTP em funcionamento, mesmo depois da implementaçao da pagina em HTTPS.

o cliente deve sempre validar o certificado.

se usamos HTTPS, ele é baseado em um certificado, ele possui garantias do certificado e se voce ignorar o certificado ele nao serve para nada.

a validaçao do certificado é no sentido de quem emitiu esse certificado? esta valido?

por exemplo o google chrome conhece a cadeia de certificados e consegue validar o certificado enviado.

nao é porque existe um certificado que ele pode ser confiavel. eles devem ser verificados e validados.

podem existir certificados fake.

### outros ataques
alguns cenarios de ataque:

* scenario 1: an application encrypts credit cart numbers in a database using automatic database encryption. however, this data is automatically decrypted when retrieved, allowing an SQL injection flaw to retrieve credit card numbers in clear text.

* scenario 2: a site doesn´t use or enforce TLS for all pages or supports weak encryption. an attacker monitors network traffic (e.g. at an insecure wireless network), downgrades connections from HTTPS to HTTP, intercepts requests, and steals the user´s session cookie. the attacker then replays this cookie and hijacks the user´s private data, e.g. the recipient of a money transfer.

* scenario 3: the password database uses unsalted or simple hashes to store everyone´s passwords. a file upload flaw allows an attacker to retrieve the password database. all the unsalted hashes can be exposed with a rainbow table of pre-calculated hashes. hashes generated by simple or fast hash functions may be cracked by GPUs, even if they were salted.

quando criptografamos um campo, normalmente nao descriptografamos ele para utilizar.

quando queremos comparar, passamos o que foi inserido pelo usuario, que sera criptografado e em seguida comparamos a criptografia com a criptografia persistida.

mas existem casos que necessitamos descriptografar algo, como por exemplo um numero de cartao de credito.

uma ma escolha para este tipo de criptografia porque se voce tem uma falha de SQL Injection, quando é realizado o select nessa tabela, o proprio banco retira a criptografia e mostra o numero em aberto.

as ameaças sao interligadas, uma influencia na outra.

se voce tem SQL Injection nao adianta ter a criptografia automatica, porque a porta esta aberta, entao tenham cuidado!

Nao usar TLS

TLS é o que vai dar a base para o HTTPS.

ou entao suporta um modelo de criptografia baixo, ou nao suporta TLS para todas as paginas.

Man in the middle

pode ocorrer um ataque de man in the middle, ou seja, uma pessoa fica ali escutando no meio, o caso mais simples é uma rede wireless, em que voce nao tenh senha para se logar nela, os dados estao trafegando sem criptografica.

se voce esta sem HTTPS, tambem, seus dados estao indo sem criptografia. qualquer dispositivo aqui nesse ambiente é capas de escutar o que esta aqui no ar. não é porque eu estou com o meu notebook ou com o meu celular, que o roteador mandou a mensagem somente para o meu celular.

ele enviou para o ar, em todas as direçoes, e o meu celular capturou.

se esses dados que foram no ar nao estao criptografados, qualquer um pode pegar. se voce tem alguem fazendo isso, esse alguem pode pegar dados que nao estao criptografados, pode roubar o teu cookie, pode roubar o teu session ID, pode roubar o que for para fazer sequestro do seu login.

imagine que voce ja esteja logado em um site. como ele viu aqui os dados indo de um lado para outro, ele pega aqui o seu cookie e fala: 'na verdade voce sou eu agora' e ele usa o cookie para fingir que é voce, assumindo o seu papel.

entao tenha como regra: redes wireless sempre criptografadas.

outro ponto é o banco de dados usar modelos de algoritmos de criptografia que sao mais basicos e mais suscetiveis a ataques e falhas.

o importante é sempre utilizar uma biblioteca de terceiros que faça a escolha do algoritmo para voce ou que voce fale: 'olha, eu quero esse algoritmo', porque se voce quiser mudar de algoritmo para outro, voce nao precisa mudar a biblioteca inteira.

todas as linguagens de programação vao ter bibliotecas do genero.

entre outros tipos de ataques esta o de injection de linha de comando.

se a pessoa pode fazer um injection de linha de comando e as senhas estao armazenadas em um arquivo, mesmo que criptografado, ele executa um comando la, por exemplo : 

```
cat/etc/passwd

```

e la estao todas as senhas dos usuarios criptografadas e assim ele consegue acesso a todas as senhas.

se a criptografia é fraca, o atacante consegue ir atras.

se a criptografia nao usar o SALT, ele consegue rodar a força bruta mais facilmente.

o que é o SALT?

o salt é algo que voce adiciona no campo a ser encriptografado, de forma a ter algo mais na encriptaçao, diferenciando ela assim das outras que usaram o mesmo algoritmo.

por exemplo, a senha guilherme171734, depois do algoritmo seria tipo isto aqui:
98oklsjdf0923rlkv09i2rfkASD

isso seria o basico.

so que se esse arquivo vazar com essa senha, alguem pode ter um dicionario de senhas comuns que contenha a senha guilherme171734

o atacante ao pegar o dicionario de senhas comuns e rodar no arquivo vai descobrir que existe la uma senha guilherme171734.

entao o algoritmo mais basico de criptografia tem esse problema.

entao quando voce for criptografar a senha, por exemplo, adicione um SALT a ela.

entao em vez de criptografar guilherme171734, criptografe aluraguilhermer171734, dessa forma, mesmo que ele tenha acesso ao banco e percorra o algoritmo com as senhas mais usadas, nunca vai conseguir encontra um match porque ele nao tem o SALT.

claro que a palavra alura é um pessime exemplo se voce esta fazendo isso para o site da alura, voce deveria usar uma palavra tambem encriptografada ou um hash

### como prevenir?

* primeiro devemos classificar o que é sensivo e o que nao é. 

voce precisa saber no que precisa tomar mais cuidado e no que voce nao precisa tomar tanto cuidado.

esta classificação talvez seja algo so da sua empresa, mas provavelmente existam leis que nos forçam a tomarmos certos caminhos com certos tipos de dados e informaçoes. 

entao cada pais vai ter as suas proprias leis sobre o que voce precisa ficar atento.

* colocar controles de acordo com a classificaçao

se os dados forem sensiveis voce precisa fazer controles de acesso

* nao armazene dados sensiveis

esta é a maior sacada. 

nao armazene!

em vez de armazenar, ter que criptografar e cuidar do transporte de uma lado para o outro, cuidar do armazenamento, cuidar do log, cuidar do backup, simplesmente nao armazene se voce nao precisa da informaçao, nem sequer peça.

dados que nao estao armazenados e que voce nao guardou nao podem ser roubados.

* se precisar armazenar, criptografe

todos os dados sensiveis devem estar encriptografados enquanto estao armazenados.

utilize algoritmos atualizados, protocolos e tudo mais, gerencie as chaves de segurança, etc

mantenha sempre tudo atualizado

* dados em transferencia tem que estar protegidos com TLS e algo do genero, tipo HTTPS.

* desabilite cache para as requisiçoes que tem dados sensiveis

qualquer dado sensivel nao deve ser cacheado

* guarde as senhas utilizando algoritmos decentes, como o bcrypt, script, argon2, etc

tudo isso é importante porque esses dados sao sensiveis e voce nao quer que eles estejam espalhados por ai.

### o que aprendemos?
* dados nao criptografados armazenados
* dados nao criptografados em transito
* o perigo de logs e backups
* atualizacao de algoritmos de criptografia
* forçar o uso de certificados e a validaçao dos mesmos


## A4 XML external entities
entao, como eu descubro se minha aplicaçao esta vulneravel ao problema do XMl external entities?

se sua aplicaçao aceita que o cliente envie para voce XML, ate mesmo por upload, principalmente de fontes nao confiaveis, entao voce esta vulneravel.

entao, no XML temos um problema parecido com o injection, que é o atacante colocar algo no XML que revele ou execute açoes na aplicaçao.

entao, se voce esta trabalhando com processadores de XML, voce tem um risco.

um XML basico é formado por tags que representam os objetos e os parametros dos objetos:

```
<contato> 
  <nome>joao da silva</nome>
  <telefone>12345678</telefone>
</contato>
```

isso é o core do corpo.

entao um corpo de XML tem uma tag raiz, e a partir dessa tag rais, vai tendo as tags internas.

entao nessa situaçao parece similar ao JSON, porque no JSON voce vai ter um objeto rais e dentro dele outros objetos.

voce vai ter certos atributos, como por exemplo telefone pessoal ou residencial e entao voce consegue criar uma estrutura ainda mais complexa.

entao com XML da para fazer muitas coisas.

mas ainda nao estamos representando a estrutura do dado.

entao podemos querer ter um cabeçalho dizendo que é um XML, usando a versao 1.0 e que usa o encoding UTF-8, por exemplo.

alem disso eu posso querer descrever algo sobre essa estrutura, como por exemplo:

'olha, este XML aqui é um documento que segue algumas regras. nas regras que esse XML segue, eu so posso ter um contato, obviamente porque ele é a raiz. mas eu posso ter varios telefones e o tipo so pode ser residencial, comercial ou celular.'

o esquema do XML pode ser descrito aqui em cima. tem varios formatos de esquema de XML, como por exemplo DTD, entre outros.

```
<?xml version="1.0> encoding="UTF-8"?>

<contato> 
  <nome>joao da silva</nome>
  <telefone tipo="residencial">12345678</telefone>
  <telefone tipo="comercial">12345678</telefone>
  <telefone tipo="celular">12345678</telefone>
</contato>
```

entao tem varias coisas que nos podemos fazer aqui no cabeçalho do XML, dentre elas, definir estruturas.

podemos ir muito alem, inclusive pode estar definido no XML a estrutura, refrenciando estruturas externas.

qual é o problema?
em cima, na definiçao da estutura do noss XML, é possivel fazer ataques.

em XML é possivel fazer atalhos, quase como designar uma variavel e utiliza-la dentro do XML.

e nessa designaçao da variavel, podemos injetar codigo malicioso.

o que voce pode fazer no cabeçalho? 

por exemplo pode declarar.

```
<?xml version="1.0> encoding="UTF-8"?>
<!DOCTYPE contato ...
  <!ENTITY meuNome TEXT "Guilherme">
<contato> 
  <nome>&meuNome;</nome>
  <telefone tipo="residencial">12345678</telefone>
  <telefone tipo="comercial">12345678</telefone>
  <telefone tipo="celular">12345678</telefone>
</contato>
```

entao usando o DOCTYPE podemos definir uma entidade, neste caso chamada de contato.

o importante é que em algum momento aqui detrno do mei DOCTYPE contato, ele coloca que existe uma entidae chamada 'meuNome' e que essa entidade poderia ser simplesmente um texto (TEXT) com o valor 'Guilherme'

entao com algo similar a isso, nao exatamente isso, o que eu estaria fazendo seria:

estamos enviando um XML valido.

nao exatamente esse em que eu substitui essa entidade e meu nome por "guilherme".

entao temos criado uma entidade e essa entidade é utilizada por todo o meu XML, para ficar evuitanto um copy e paste enorme.

isso é uma entidade declarada dentro do proprio XML.

e o perigo é uma entidade externa, so que essa entidade nao precisa ser algo interno da aplicaçao, ela pode ser algo do sistema, o 'system'.

e aqui pode ser, como no exemplo da OWASP, um 'file:///etc/passwd' e o que ele esta falando aqui é que a entidade 'meuNome' é o conteúdo deste arquivo.

```
<?xml version="1.0> encoding="UTF-8"?>
<!DOCTYPE contato ...
  <!ENTITY meuNome SYSTEM "file:///etc/passwd">
<contato> 
  <nome>&meuNome;</nome>
  <telefone tipo="residencial">12345678</telefone>
  <telefone tipo="comercial">12345678</telefone>
  <telefone tipo="celular">12345678</telefone>
</contato>
```

entao exemplos de ataques sao:

numerous public XXE issues have been discovered, including attacking embedded devices. XXE occurs in a log of unexpected places, including deeply nested dependencies.
the easiest way is to upload a malicious XML file, if accepted:

* scenario 1: the attacker attempts to extract data from the server:

```
<?xml version="1.0> encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe</foo> 
```

* scenario 2: an attacker probes the server´s private network by changing the above ENTITY line to:

```
<!ENTITY xxe SYSTEM "https://192.168.1.1/private">]>
```

* scenario 3: an attacker attempts a denial of service attack by including a potentially endlesss file:

```
<!ENTITY xxe SYSTEM "file:///dev/random">]>
```
e o que acontece? 

se o parser do XML nao estiver configurado adequadamente para nao ler a entidade externa, ele vai ler a entidade externa e vai pegar todo o conteudo do arquivo e vai colocar dentro do XML, nos atalhos.

e imagine que voce vai cadastrar agora esse contato no seu sistema.

o atacante olha nos contatos dela e la terá todas as passwords e senhas gravadas no local dos contatos, ou qualquer informaçao que ele pegou, no caso do file:///etc/passwd os usuarios e senhas no sistema linux.

entao isto é super perigoso!

a entidade externa permite que um parser de XML carregue as informaçoes de um lugar de fora, mas nao esta limitando um lugar de fora, pode ser inclusive do sistema operacional.

nos carregamos arquivos e abrimos a porta para que esses dados sejam colocados aqui desta maneira.

eu acesso depois em algum outro lugar o resultado desse meu XML e no resultado terá as informaçoes expostas.

entao, o atacante tenta, por exemplo, extrair os dados do 'file:///etc/passwd' colocando aqui no 'foo' este conteudo. ou ele pode fazer outras coisas, nao precisa pegar conteudo de arquivo, pode tentar descobrir a estrutura da rede.

entao ele coloca um "SYSTEM "https://192.168.1.1/private"" e com isso se a aplicaçao aceitar o XML, quer dizer que essa requisiçao HTTP funcionou, entao "192.168.1.1" existe!
e "/private" sera o router

a configuraçao do router esta aberta?

porque a configuraçao do router em geral, so esta aberta para dentro da propria rede se tiver em usuario administrador e senha.

uma requisiçao dessas vai trazer as informaçoes ja e voce consegue trazer as informaçoes e descobrir mais sobre a sua rede.

ou ainda voce faz um denial of service e detonar a rede, porque se ele mandar acessar um arquivo infinito, tipo o "file:///dev/random", que na verdade nao é um arquivo, é uma fonte de numeros aleatorios, e a aplicaçao começa a ler desse arquivo, dessa fonte de numeros aleatorios, continua lendo e recebendo numeros aleatorios, entupindo a CPU, a memoria e o disco, ai voce começa a ter erros de I/O.

percebeu o buraco aqui de um external entity? todo tipo de external entity é perigoso!

nao so no XML, se voce tem outro formato ou qualquer coisa que aceita o seu cliente enviar uma URI para voce e voce acessar essa URI, ou um arquivo local que o seu cliente esta falando para voce o arquivo que é para acessar é perigosissimo!

por padrao, DESATIVADO, com certeza!!!

entao claro a sacada vai estar ligada com desativar isso.

### como prevenir?

developer training is essential to identify and mitigate XXE.

besides that, preventing XXE requires:

* whenever possible, use less complex data formats such as JSON and avoiding serialization of sensitive data
  
* patch or upgrade all XML processors and libraries in use by the application or on the underlying operational system. use dependency checkers. update SOAP to SOAP 1.2 or higher

* disable XML external entity and DTD processing in all XML parsers in the application (you can look at the OWASP cheat sheet XXE Prevention)

* implement positive ("whitelisting") server side validation, filtering or sanitization to prevent hostile within XML documents, headers or nodes

* verify that XML or XSL file uploads functionality validates incoming XML using XSD validation or similar

* SAST tools can help detect XXE in source code, although manual code review is the best alternative in large, complex applications with many integrations.

if these controls are not possible, consider using virtual patching, API Security gateways, or web application firewalls (WAFs) to detect, monitor and block XXE attacks

### o que aprendemos?
* o que sao XML External Entities
* o problema de entidades externas

## A5 Broken Access Control
o quinto risco apresentado na lista do OWASP top 10 de 2017 é o controle de acesso quebrado.

este problema esta relacionado mais em tentar me logar como alguem e pegar usuario e senha de alguem ou acessar algo como se eu fosse alguem.

é relacionado a acessar algo porque nao validamos se a pessoa tem esse acesso.

embora algumas ferramentas consigam detectar isso, existem limites.

em um site, por exemplo, imagine que voce logado tem acesso ao seu perfil e a URL seria a seguinte:

www.meusite.com/perfil/1

sendo o 1 o id do perfil. 

o atacante, vendo que tem acesso ao perfil id 1, pode testar se tem acesso ao perfil id 2, etc.

se o sistema de controle de acesso estiver quebrado, ele nao esta verificando se tem acesso ou nao a este perfil.

se nao tivermos uma validaçao de que essa URI é acessavel pelo usuario, este controle esta quebrado.

entao é importante que nos estejamos sempre validando o controle de acessos.

mas como validamos isso?

existem varias maneiras, em qualquer linguagem voce tera algum tipo de funçao de verificaçao de permissao.

nela voce deve colocar a verificaçao de que aquele usuario logado tem permissao para ver os dados ou nao.

a sacada é: 

devemos ter essa verificaçao explicita, bem clara para que qualquer um olhando o codigo veja, porque se for implicita, podemos esquecer.

a ideia é que o controle tem que garantir que um usuario nao possa fazer algo que nos nao tinhamos a intençao que ele pudesse e que nao teria permissao.

e as falhas costumam ser graves, porque permitem acesso às informaçoes que nao era para terem sido informadas.

modificaçoes, destruiçao e inserçao, para ele executar uma funçao do seu negocio.

todas sao coisas que voce nao quer.

os casos mais comuns nao sao todos de vulnerabilidade.

* bypassing access control checks, modificando a URL

isto acontece se a validaçao foi feita somente na hora de mostrar os links.

se o usuario mudar o link, acessa a pagina errada sem permissao.

* conseguir mais privilegios.

entao o usuario, mesmo sem estar logado, consegue fingir e atuar como se estivesse logado e consegue tambem atuar como se fosse um administrador.

* manipular metadados

todos os metadados que estao ligados às permissoes sao perigosos e nos precisamos estar sempre validando.

* CORS - Cross Origin Resource Sharing, com má configuraçao, permite que pessoas indevidas acessem a API.

* HTTP verb attack

outra maneira classica é tentar em vez do 'GET' fazer um 'POST' ou 'PUT' ou 'DELETE'.

um atacante pode tentar coisas do genero, ou pode forçar a navegaçao em paginas autenticadas como um usuario nao autenticado.

entao é bom ter essas coisas bem separadas.


### example attack scenarios
* scenario 1

the application uses unverified data in a SQL call that is accessing account information:

```
pstm.setString(1, request.getParameter("acct"));
ResultSet results = pstmt.executeQuery();
```

an attacker simply modifies de 'acct' parameter in the browser to send whatever account number they want. if not properly verified, the attacker can access any user´s account.

http://example.com/app/accountinfo?acct=notmyacct

* scenario 2

an attacker simply force browsers to target URLs.
admins rights are required for access to the admin page.

http://example.com/app/getappinfo
http://example.com/app/admin_getappinfo

if an unauthenticated user can access either page, it´s a flaw. if a non-admin can access the admin page, this is a flaw.

### como previnir?
access control is only effective if enforced in trusted server-side code or server-less API, where the attacker cannot modify the access control check or metadata.

* with the exception of public resources, deny by default
* implement access control mechanisms once and re-use them throughout the application, including minimizing CORS usage
* model access controls should enforce record ownership, rather than accepting that the user can create, read, update or delete any record
* unique application business limit requirements should be enforced by domain models
* disable web server directory listing and ensure file metadata (e.g. .git) and backup files are not present within web roots
* log access control failures, alert admins when appropriate (e.g. repeated failues)
* rate limit API and controller access to minimize the harm from automated attacking tooling
* JWT tokens should be invalidated on the server after logout

developers and QA staff should include functional access control unit and integration tests.

### o que aprendemos?
* controle explicito e implicito
* perigo em modificaçoes de URIs
* nao permitir trocas de chaves primarias e controlar chaves estrangeiras

