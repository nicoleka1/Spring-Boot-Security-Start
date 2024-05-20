# Classroom Exercise Instructions


## Exercise 1 - Basic Authentication

## Pre-requisites
- Import this repository into your own GitHub account and name it ``BasicAuth``.
- Open the repository in Codespaces.
- Import Java Projects.
- Change the visibility of port 8080 to public after starting the application.

### Step 1 - Add Spring Security

In pom.xml add the spring security dependency.
- Right click and choose “Add Starters…”
    - Search for “spring boot starter security” and choose “Spring Security”
    - Hit Enter to continue

OR copy the following in pom.xml
```XML
<dependency>
<groupId>org.springframework.boot</groupId>
<artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

### Step 2 - Add an Approach for Security

#### Approach 1 - Use Default Username and Password for Authentication

- Start the application and note the generated password in the console
    - Copy the password
    - Open the app in the browser; login page should open
    - Enter username: ``user`` and password:``{copied password}`` to get access to the endpoint

- This approach has some drawbacks. Hence, used only for unit testing purposes.
    - Password is regenerated every time server starts!
    - Accessible only from logs; end users do not have access to logs!

#### Approach 2 - Use Customized Username and Password for Authentication

Let's try a better approach of defining our own username and password.
- Enter the following properties in resources/application.properties
```Properties
spring.security.user.name=${myusername}
spring.security.user.password=${mypassword}
```
- Run the app and enter these details on the login page
- It's not safe to save username and password directly. Let's create environment variables to store the username and password and inject them in the properties:
    - Go to Repository Settings > Secrets and Variables
    - Add New Repository Secrets
        - Name: myusername, Value: ``{your username}``
        - Name: mypassword, Value: ``{your password}``
- The drawback of this approach is that only one user can be created and roles cannot be assigned.

#### Approach 3 - Add Security Config
Let's secure individual endpoints by creating some roles.
- If you tried Approach 2 above, delete the username and password properties from application.properties
- Add the following two GET mappings in the MyController.java:
```Java
@GetMapping("/admin")
public ResponseEntity<String> showAdminContent() {
return new ResponseEntity<>("Only an admin can view this content.", HttpStatus.OK);
}


@GetMapping("/user")
public ResponseEntity<String> showUserContent() {
return new ResponseEntity<>("Only a user can view this content.", HttpStatus.OK);
}
```

OR let AI Copilot generate these suggestions for you 😊

- Create Custom Security Config Class
    - Create a new package ``ch.fhnw.securitytest.security`` and a new class
``SecurityConfig.java``
    - Add the following class-level annotations:
        ``@Configuration``
        ``@EnableWebSecurity``
        ``@EnableMethodSecurity``
- Inside ``SecurityConfig.java``, add a bean that will replace the default implementation of UserDetailsService
    - Create two custom users with roles USER and ADMIN, respectively
    - Use the custom user details to perform in-memory authentication
```Java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public UserDetailsService users() {
        //Create two users with different roles and add them to the in-memory user store

        return new InMemoryUserDetailsManager(
            User.withUsername("myuser")
                .password("{noop}password")
                .authorities("READ","ROLE_USER")
                .build(), 
            User.withUsername("myadmin")
                .password("{noop}password")
                .authorities("READ","ROLE_ADMIN")
                .build());

    }
}
```
Now we need to add a **Security Filter Chain** implementation.
- Add another bean inside ``SecurityConfig.java`` that will customize SecurityFilterChain implementation in Spring Boot
    - Disable csrf. We are not using cookies as we are developing a REST API. Hence, it is safe to disable CSRF.
    - Add role-based access to the ``/securitytest/admin`` and ``/securitytest/user`` endpoints
    - Add a form login to use Spring Security’s default login form
    - Use HTTP Basic Authentication on the two users created: ``myuser`` and ``myadmin``

    ```Java
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests( auth -> auth
                        .requestMatchers("/securitytest/admin").hasRole("ADMIN") //note that the role need not be prefixed with "ROLE_"
                        .requestMatchers("/securitytest/user").hasRole("USER") //note that the role need not be prefixed with "ROLE_"
                        .requestMatchers("/securitytest/**").permitAll()
                        .anyRequest().hasAuthority("SCOPE_READ")            
                )       
                .formLogin(withDefaults()) //need to include a static import for withDefaults, see the imports at the top of the file
                .httpBasic(withDefaults())
                .build(); 
    } 
    ```
- Test the endpoints on a browser or using Postman.

## Exercise 2 - Token-based Authentication
## Pre-requisites
- Import this repository into your own GitHub account and name it ``JWT_OAuth``.
- Open the repository in Codespaces.
- Import Java Projects.
- Change the visibility of port 8080 to public after starting the application.

### Step 1 - Add Spring Security

- In pom.xml add the spring security dependency.
- Right click and choose “Add Starters…”
    - Search for “spring boot starter security” and choose “Spring Security”
    - Hit Enter to continue

OR copy the following in pom.xml
```XML
<dependency>
<groupId>org.springframework.boot</groupId>
<artifactId>spring-boot-starter-security</artifactId>
</dependency>
```
- Add another dependency for OAuth2 Resource Server:
    - Right click and choose “Add Starters…”      
    - Search for “oauth2” and choose “OAuth2 Resource Server”
    - Hit Enter to continue
OR copy the following in pom.xml
```XML
<dependency>
<groupId>org.springframework.boot</groupId>
<artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```

- Add individual endpoints
    - Add the following GET mapping in ``MyController.java``:
    ```Java
    @GetMapping("/safe")
    public ResponseEntity<String> showSafeContent() {
        return new ResponseEntity<>("Only a token bearer can view this content.", HttpStatus.OK);
    }
    ```

OR let AI Copilot generate these suggestions for you 😊
- Define a JWT Key
    - We need to define a JWT Key which will be used to encode the token
    - Add it in application.properties
    ```Properties
    # should be at least 64 characters
    jwt.key=mysecret-which-needs-to-be-of-at-least-512bit-long!please-change
    ```
- Create Custom Security Config Class
    - Create a new package ``ch.fhnw.securitytest.security`` and a new class
``SecurityConfig.java``
    - Add the following class-level annotations:
        ``@Configuration``
        ``@EnableWebSecurity``
        ``@EnableMethodSecurity``
- Inside ``SecurityConfig.java``:
    - Inject the value of JWT Key
    - Add a bean that will replace the default implementation of UserDetailsService
    - Create one custom user with the role USER
    - Use the custom user details to perform in-memory authentication
```Java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Value("${jwt.key}")
    private String jwtKey;

    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
            User.withUsername("myuser")
                    .password("{noop}password")
                    .authorities("READ","ROLE_USER")
                    .build());
        
    }
}
```

Now we need to add a **Security Filter Chain** implementation.
- Add another bean inside ``SecurityConfig.java`` that will customize SecurityFilterChain implementation in Spring Boot
    - Disable csrf. We are not using cookies as we are developing a REST API. Hence, it is safe to disable CSRF.
    - Add role-based access to the ``/securitytest/safe`` endpoint
    - Set SessionManagement to ``STATELESS``
    - Use HTTP Basic Authentication on the custome user: ``myuser``

    ```Java
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests( auth -> auth
                        .requestMatchers("/securitytest/token").hasRole("USER") //only custom users with role USER can request a token
                        .anyRequest().hasAuthority("SCOPE_READ") // only requests with scope inside the JWT token can access the endpoints        
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(oAuth -> oAuth.jwt(Customizer.withDefaults()))
                .httpBasic(withDefaults())
                .build(); 
    }
    ```

Next, we need to define an **encoder** and **decoder** for our access tokens using the defined ``jwt.key``
- Inside SecurityConfig.java, define a bean that uses an implementation JWT encoder
- Define another bean that uses the same algorithm that was used to sign the token
to decode it
```Java
@Bean
    JwtEncoder jwtEncoder() {
        return new NimbusJwtEncoder(new ImmutableSecret<>(jwtKey.getBytes()));
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        byte[] bytes = jwtKey.getBytes();
        SecretKeySpec originalKey = new SecretKeySpec(bytes, 0, bytes.length,"RSA");
        return NimbusJwtDecoder.withSecretKey(originalKey).macAlgorithm(MacAlgorithm.HS512).build();
    }
```

Defining an encoder and decoder bean is not enough. Next, we need to actually generate a token and issue it. For this, we need to create another service class.
- Add a new package ``ch.fhnw.securitytest.security`` and a new class
``TokenService.java``
- Add the class level annotation ``@Service``
- Add a JWT encoder and a constructor
```Java
@Service
public class TokenService {

    //use the encoder bean from SecurityConfig
    private final JwtEncoder encoder;

    //Inject into the constructor
    public TokenService(JwtEncoder encoder) {
        this.encoder = encoder;
    }
}
```
- Add a method to generate a new token
```Java
public String generateToken(Authentication authentication) {
        // note the current time to determine the issuedAt and expiresAt
        Instant now = Instant.now(); 

        // the scope is the JWT scope SCOPE_READ which is checked in SecurityConfig during authentication, this is not the role-based scope
        String scope = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(authority -> !authority.startsWith("ROLE"))
                .collect(Collectors.joining(" "));

        // create the JWT claims - name/value pairs
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self") //issuer by this application
                .issuedAt(now) //issued now
                .expiresAt(now.plus(1, ChronoUnit.HOURS)) //expires in 1 hour
                .subject(authentication.getName()) //subject is the username
                .claim("scope", scope) //scope is the scope created above
                .build();

        // create the JWT encoder parameters
        var encoderParameters = JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS512).build(), claims); //use the symmetric key algorithm HS512 for signing the JWT
        return this.encoder.encode(encoderParameters).getTokenValue(); //encode the JWT and return the token value
    }
```

Let's add an endpoint in our controller to generate the token for authentication.
- Add an endpoint to retrieve the JWT token
    - Inject the ``TokenService`` in ``MyController.java``
    ```Java
    private final TokenService tokenService;

    public MyController(TokenService tokenService) {
        this.tokenService = tokenService;
    }
    ```
    - Add the following POST mapping in ``MyController.java``
    ```Java
    @PostMapping("/token")
    public String token(Authentication authentication) {
        if (authentication.isAuthenticated()) { //requires a valid user (created in SecurityConfig.java)
            return tokenService.generateToken(authentication);
        } else {
            throw new UsernameNotFoundException("invalid user request !");
        }
    ```

Let's test the endpoints using Postman.
- Start the application
- Change the port visibility to “public” otherwise you will not see the response in
Postman
- Copy the local address (``{baseURL}``) of the running application
- Create a new request in Postman
    - Method: POST
    - URL: ``{baseURL}/securitytest/token``
    - In the Authorization tab, choose/enter the following:
        - Basic Auth
        - Username: ``myser``
        - Password: ``password``
- Send the request
- In the response, you should receive the encoded JWT

Using this token, now you can access the secured endpoint.
- Copy the token from the previous response
- Create a new request in Postman
    - Method: GET
    - URL: ``{baseURL}/securitytest/safe``
    - In the Authorizatio tab
        - Choose Bearer Token
        - Paste the token
- Send the request
- In the response, you should see the appropriate content sent by the server.