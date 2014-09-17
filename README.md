Celllife Security Framework
============================

This project provides a wrapper around Spring Security, providing classes required to integrate with a custom Authentication model. It also provides default functionality to change and reset passwords. The basic portal Maven prototype creates a Spring Security setup that only authenticates via the Cell-Life Production LDAP, but if you would like to manage users yourself, then you can use this library.

Please note that this does not allow users to login via the login screen, only allows users to perform REST functionality, so should be used for integration accounts.

To use
------

### Step 1: 

Add the celllife-security dependency in your pom.xml. 

*root pom.xml*:

Notes: 
 * Please check for the latest releases on [Nexus for celllife-security](https://www.cell-life.org/nexus/content/repositories/releases/org/celllife/security/).
 * You will also need the Spring Security and MVC dependencies in your project (but these should already be there).

```xml
<!-- Cell-Life Security -->
<dependency>
    <groupId>org.celllife.security</groupId>
    <artifactId>celllife-security</artifactId>
    <version>1.0.0</version>
</dependency>
```

*webapp pom.xml*:

```xml
<!-- Cell-Life security -->
<dependency>
    <groupId>org.celllife.security</groupId>
    <artifactId>celllife-security</artifactId>
</dependency>
```

### Step 2:

Add two fields (encryptedPassword and salt) to your User entity.

#### A

In your domain model class, you will need to
 1. Create attributes for the two Strings
 2. implement the SecurityUser interface - this defines the interface for retrieving the login (e.g. username or code), encrypted password and password salt.

#### B

In liquibase you can add two fields to your initial createTable changeSet:

```xml
<column name="encrypted_password" type="VARCHAR(64)" />
<column name="salt" type="VARCHAR(64)" />
```

#### C

In your DTO (data transfer object which is used by your REST interface), you will need to add a single String for password. This is so that when creating users you can select a password.

#### D

In your REST (and user) interface, where you are creating users, ensure that you generate an encrypted password and generate a salt with the given password (mentioned in the previous step).

```java
SecurityServiceUtils.setPasswordAndSalt(clinic, clinicDto.getPassword());
```

### Step 3:

Create an implementation of the SecurityUserService by extending AbstractSecurityUserServiceImpl and implementing the two methods used to retrieve a user given their login and to save a user's password and salt. The former is used during login and the latter is used for password update and reset. You would use the appropriate Repository or DAO object already defined in your project to provide the functionality.

### Step 4:

Modify the Spring Security setup (spring-security-core.xml) to include authentication using your own User object. To do this configure a new authentication provider using the library's securityUserDetailsService and encryptedPasswordEncoder. See below for a full excerpt of the file. Note you will need to modify the defaultAuthority.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:security="http://www.springframework.org/schema/security"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd
                           http://www.springframework.org/schema/security http://www.springframework.org/schema/security/spring-security.xsd">

    <security:global-method-security pre-post-annotations="enabled"/>
    
    <bean id="securityUserDetailsService" class="org.celllife.security.spring.SecurityUserDetailsService">
        <property name="defaultAuthority" value="APPOINTMENTREMINDERS" />
    </bean>
    <bean id="encryptedPasswordEncoder" class="org.celllife.security.spring.EncryptedPasswordEncoder"/>

    <security:authentication-manager id="httpBasicAuthenticationManager">
        <security:authentication-provider>
            <security:user-service>
                <security:user name="${internal.username}" authorities="SYSTEM" password="${internal.password}" />
            </security:user-service>
        </security:authentication-provider>
        <security:authentication-provider user-service-ref="securityUserDetailsService">
	        <security:password-encoder ref="encryptedPasswordEncoder">
	            <security:salt-source user-property="salt"/>
	        </security:password-encoder>
        </security:authentication-provider>
        <security:authentication-provider user-service-ref="ldapUserDetailsService">
            <security:password-encoder hash="{ssha}"/>
        </security:authentication-provider>
    </security:authentication-manager>

    <security:authentication-manager id="casAuthenticationManager">
        <security:authentication-provider ref="casAuthenticationProvider"/>
    </security:authentication-manager>

</beans>
```

### Step 5

To provide users the option to update and reset their passwords some basic functionality has been added via REST. Add the following code to the spring-mvc.xml configuration.

```xml
    <!-- Load the security UserController for updating and resetting passwords -->
    <bean id="clinicSecurityUserService" class="org.celllife.appointmentreminders.domain.clinic.ClinicSecurityUserService"/>
    <context:component-scan base-package="org.celllife.security.interfaces.service"/>
```

This provides you with two REST calls detailed below. If you would like to modify the default behaviour of these methods, then override the appropriate methods in SecurityUserService.

#### Update password

Description: Changes a user's password to the specified new password after checking the old password is valid.
PUT <baseUrl>/service/user/password
Content-Type: application/JSON

```json
{
    "login": "0000",
    "oldPassword": "password",
    "newPassword": "password2"
}
```

Responses: 
 * 200 OK
 * 422 Unprocessable Entity - if the oldPassword is not correct or is missing
 * 404 Not Found - if the user cannot be found

#### Reset password


Description: A user with an administrator role can reset a user's password to a randomly generated 6 character alphanumeric string.
PUT <baseUrl>/service/user/reset
Content-Type: application/JSON

```json
{
    "login": "0000"
}
```

Responses
 * 200 OK (with the new password in the response)
 * 404 Not Found - if the user cannot be found
 * 422 Unprocessable Entity - if there is an issue while resetting password for example the user performing the call is not an administrator
