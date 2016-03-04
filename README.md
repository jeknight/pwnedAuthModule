An example of an OpenAM 13 authentication module (based on "SampleAuth").
-------------------------------------------------------------------------

This module should be used on conjunction with other modules in an authentication chain (see below). The module takes the user's email address and makes a call to the haveibeenpwned.com API to determine whether the email address has been listed in any recorded breaches. If no email address is listed, or no reported breaches are return, authentication succeeds. If breaches are returned, a summary of the report is displayed to the user and authentication fails. With a suitable OpenAM authentication chain this failure can be captured in order to proceed with a stronger auth module (2FA, etc).


How to build and install:
-------------------------

Download or clone the repo.

Build with "mvn install".

Copy the build jar into the OpenAM WEB-INF/lib directory.

Register the module with OpenAM: 

- ssoadm create-svc --adminid amadmin --password-file passwd.txt --xmlfile src/main/resources/amAuthPwnedAuth.xml
- ssoadm register-auth-module --adminid amadmin --password-file passwd.txt --authmodule

Restart the OpenAM container.

Configure an authentication module and authentication chain using the OpenAM admin console, for example,

  PwnedChain = DataStore (REQUISITE) -> PwnedAuth (SUFFICIENT) -> ForgeRockAuthenticator (REQUIRED)
  
Note: the haveibeenpwned.com service must be invoked over SSL and is protected by a StartCom signed certificate. You must install the StartCom CA certificate into your java cacerts keystore, for example:

keytool -importcert -alias startcom -file ca.crt -trustcacerts -keystore cacerts




See also: 
https://haveibeenpwned.com/API/v2#BreachesForAccount
https://backstage.forgerock.com/#!/docs/openam/13/dev-guide#sec-auth-spi

