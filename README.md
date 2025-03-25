Creating a **Spring Boot API Security Project** that covers all **OWASP API Security Top 10** vulnerabilities from basic to advanced is a great initiative. Below is a step-by-step breakdown of how we can achieve this:

---

## **Project Plan: Securing APIs in Spring Boot**
This project will create a **Spring Boot API** and systematically introduce vulnerabilities based on the **OWASP API Security Top 10 (2023)**. For each vulnerability, we will:
1. **Introduce the Vulnerability** (Understanding)
2. **Create an Insecure Example** (How it can be exploited)
3. **Fix the Vulnerability** (Best Security Practices)

---

### **🛠 Step 1: Set Up the Spring Boot Project**
#### **1️⃣ Create a Spring Boot Project**
Use **Spring Initializr** to generate a Spring Boot project:
- **Dependencies**: Spring Web, Spring Security, Spring Boot DevTools, Lombok, Spring Data JPA, MySQL Driver (or H2), JWT (Java JWT)

```bash
spring init --name SecureAPI --dependencies=web,security,jpa,mysql,lombok SecureAPI
```

#### **2️⃣ Configure `application.yml`**
```yaml
server:
  port: 8080

spring:
  datasource:
    url: jdbc:mysql://localhost:3306/secureapi
    username: root
    password: password
  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true
    database-platform: org.hibernate.dialect.MySQL8Dialect
```

---

### **🔐 Step 2: Implement & Fix OWASP API Security Top 10**
---

### ✅ **API1:2023 - Broken Object Level Authorization (BOLA)**
- **Issue**: Attackers can access unauthorized objects (e.g., viewing another user's data).
- **Fix**: Use proper authentication & authorization.

**🚨 Vulnerable Code**
```java
@GetMapping("/user/{id}")
public User getUser(@PathVariable Long id) {
    return userRepository.findById(id).orElseThrow(() -> new RuntimeException("User Not Found"));
}
```
**✅ Secure Code**
```java
@GetMapping("/user/{id}")
public ResponseEntity<?> getUser(@PathVariable Long id, @AuthenticationPrincipal UserDetails userDetails) {
    User user = userRepository.findById(id).orElseThrow(() -> new RuntimeException("User Not Found"));
    if (!user.getUsername().equals(userDetails.getUsername())) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access Denied!");
    }
    return ResponseEntity.ok(user);
}
```

---

### ✅ **API2:2023 - Broken User Authentication**
- **Issue**: Weak authentication mechanisms allow attackers to hijack accounts.
- **Fix**: Use **JWT Tokens** & **password hashing (BCrypt)**.

**🚀 Secure Authentication Flow**
1. **User Logs in** → Generates **JWT Token**
2. **JWT Token** is used for API requests
3. **Token Expiry & Refresh Mechanism** added

**🚀 Implementation**
- **Password Hashing**
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

- **JWT Authentication**
```java
public String generateToken(UserDetails userDetails) {
    return Jwts.builder()
            .setSubject(userDetails.getUsername())
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hour
            .signWith(SignatureAlgorithm.HS256, "SecretKey")
            .compact();
}
```

---

### ✅ **API3:2023 - Broken Object Property Level Authorization**
- **Issue**: Attackers modify **sensitive fields** (e.g., role, balance).
- **Fix**: Implement **DTOs** & **Field-Level Security**.

**🚨 Vulnerable Code**
```java
@PutMapping("/update-user")
public User updateUser(@RequestBody User user) {
    return userRepository.save(user);
}
```
**✅ Secure Code**
```java
@PutMapping("/update-user")
public ResponseEntity<?> updateUser(@RequestBody UserDTO userDto, @AuthenticationPrincipal UserDetails userDetails) {
    User user = userRepository.findByUsername(userDetails.getUsername());
    user.setEmail(userDto.getEmail()); // Only email can be updated
    userRepository.save(user);
    return ResponseEntity.ok("User updated successfully!");
}
```

---

### ✅ **API4:2023 - Unrestricted Resource Consumption**
- **Issue**: Attackers overload APIs (Denial-of-Service).
- **Fix**: Implement **Rate Limiting** (Spring Bucket4j).

```java
@Bean
public Filter rateLimiterFilter() {
    return (request, response, chain) -> {
        Bucket bucket = Bucket4j.builder()
                .addLimit(Bandwidth.simple(10, Duration.ofMinutes(1))) // Max 10 requests per min
                .build();
        if (bucket.tryConsume(1)) {
            chain.doFilter(request, response);
        } else {
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.getWriter().write("Too Many Requests!");
        }
    };
}
```

---

### ✅ **API5:2023 - Broken Function Level Authorization**
- **Issue**: Attackers access admin-only functions.
- **Fix**: Use **Spring Security Role-Based Access**.

```java
@PreAuthorize("hasRole('ADMIN')")
@DeleteMapping("/delete/{id}")
public ResponseEntity<?> deleteUser(@PathVariable Long id) {
    userRepository.deleteById(id);
    return ResponseEntity.ok("User deleted successfully!");
}
```

---

### ✅ **API6:2023 - Unrestricted Access to Sensitive Business Flows**
- **Issue**: Attackers exploit **critical business logic** (e.g., unlimited transactions).
- **Fix**: Implement **transaction limits** & **business logic checks**.

```java
@PostMapping("/transfer")
public ResponseEntity<?> transferMoney(@RequestBody TransferRequest request, @AuthenticationPrincipal UserDetails userDetails) {
    User sender = userRepository.findByUsername(userDetails.getUsername());
    if (request.getAmount() > 10000) { // Limit transaction
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Transfer limit exceeded!");
    }
    processTransaction(sender, request);
    return ResponseEntity.ok("Transfer Successful!");
}
```

---

### ✅ **API7:2023 - Server-Side Request Forgery (SSRF)**
- **Issue**: Attackers force API to send internal requests.
- **Fix**: Validate **URL Inputs**.

```java
public boolean isValidURL(String url) {
    return url.startsWith("https://trusted.com/");
}
```

---

### ✅ **API8:2023 - Security Misconfiguration**
- **Issue**: Default credentials, unprotected endpoints.
- **Fix**: Remove default passwords, configure security headers.

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .headers(headers -> headers.contentSecurityPolicy("default-src 'self'"))
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
        .formLogin(withDefaults());
    return http.build();
}
```

---

### ✅ **API9:2023 - Improper Inventory Management**
- **Issue**: Exposing **deprecated** or **test APIs**.
- **Fix**: Use **API Versioning**.

```java
@RestController
@RequestMapping("/api/v1") // Versioning
```

---

### ✅ **API10:2023 - Unsafe Consumption of APIs**
- **Issue**: Trusting **external APIs** blindly.
- **Fix**: Validate **external responses**.

```java
if (externalResponse.contains("<script>")) {
    throw new SecurityException("XSS Detected!");
}
```

---

## **🚀 Final Steps**
✅ **Testing**: Use **Postman, Burp Suite**  
✅ **Secure Headers**: Add **CSP, XSS Protection**  
✅ **Docker Deployment**: Package as **Docker Image**  
✅ **CI/CD Pipeline Security**: Add **SAST & DAST Scans**  

---

# **OWASP API Security Top 10 (2023) - API1:2023 Broken Object Level Authorization (BOLA) - Deep Explanation**  

---

## **🔍 What is BOLA (Broken Object Level Authorization)?**  
Broken Object Level Authorization (BOLA) is the most **critical API vulnerability**, where an API **fails to properly enforce authorization** at the object level. This allows attackers to **access or modify other users' data** by simply changing an object identifier in an API request.  

💡 **BOLA = Broken Access Control at the Object Level**  

### **🚨 Why is BOLA Dangerous?**  
- Attackers can **access sensitive user data** (Personal Identifiable Information, payment details).  
- Can lead to **data breaches, account takeovers, or even financial fraud**.  
- Often found in **ID-based API endpoints** (`/user/12345/orders`).  

---

## **🕵️‍♂️ Real-World Example of BOLA Exploitation**
### **Case 1: Unauthorized Access to Another User's Profile**
**Scenario:**  
A social media platform has an API endpoint to fetch user profiles:  

```http
GET /api/users/12345/profile
Host: socialmedia.com
Authorization: Bearer token123
```
**🔴 Vulnerability:**  
- The API **does not check** if `userID 12345` belongs to the logged-in user.  
- An attacker changes `12345` to another user's ID (`67890`).  

```http
GET /api/users/67890/profile
```
- If the API is vulnerable, it **returns another user's profile**.  
- Attackers can **scrape PII** (name, email, phone number, address).  

**✅ Fix: Enforce Object-Level Authorization**
In **Spring Boot**, validate the logged-in user:  

```java
@GetMapping("/users/{userId}/profile")
public ResponseEntity<?> getUserProfile(@PathVariable Long userId, Principal principal) {
    User currentUser = userService.findByUsername(principal.getName());

    if (!currentUser.getId().equals(userId)) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Unauthorized access");
    }
    return ResponseEntity.ok(userService.getUserProfile(userId));
}
```

---

### **Case 2: Modifying Another User’s Data (Account Takeover)**
**Scenario:**  
A banking API allows users to update account details:  

```http
PUT /api/accounts/67890
Host: bank.com
Authorization: Bearer token123
Content-Type: application/json

{
  "accountName": "Hacked Account"
}
```
**🔴 Vulnerability:**  
- API **does not validate if the user owns account `67890`**.  
- Attackers can update **any user’s account details**.  

**✅ Fix: Validate Ownership Before Modifying Data**
```java
@PutMapping("/accounts/{accountId}")
public ResponseEntity<?> updateAccount(@PathVariable Long accountId, 
                                       @RequestBody AccountUpdateRequest request, 
                                       Principal principal) {
    Account account = accountService.getAccountById(accountId);
    
    if (!account.getOwner().equals(principal.getName())) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Unauthorized action");
    }

    accountService.updateAccount(accountId, request);
    return ResponseEntity.ok("Account updated successfully");
}
```

---

### **Case 3: IDOR (Insecure Direct Object Reference) in E-Commerce API**
**Scenario:**  
An e-commerce API allows users to view **order details** via:  

```http
GET /api/orders/7890
Host: shop.com
Authorization: Bearer token123
```
**🔴 Vulnerability:**  
- An attacker **changes the order ID** to another user's (`9999`).  

```http
GET /api/orders/9999
```
- If the API is vulnerable, it **returns someone else's order history**.  
- Attackers can **steal credit card details, addresses, phone numbers**.  

**✅ Fix: Enforce Object-Level Authorization Using Claims**
Use JWT tokens to check **if the order belongs to the logged-in user**:  

```java
@GetMapping("/orders/{orderId}")
public ResponseEntity<?> getOrderDetails(@PathVariable Long orderId, Principal principal) {
    Order order = orderService.getOrderById(orderId);
    
    if (!order.getUser().getUsername().equals(principal.getName())) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Unauthorized access");
    }

    return ResponseEntity.ok(order);
}
```

---

### **Case 4: BOLA in File Download APIs**
**Scenario:**  
A cloud storage API lets users download files using:  

```http
GET /api/files/9876/download
```
**🔴 Vulnerability:**  
- Attackers change the `file ID` to another user’s file (`6543`).  
- If the API lacks authorization, **they can download private files**.  

```http
GET /api/files/6543/download
```
**✅ Fix: Check File Ownership Before Allowing Download**
```java
@GetMapping("/files/{fileId}/download")
public ResponseEntity<?> downloadFile(@PathVariable Long fileId, Principal principal) {
    File file = fileService.getFileById(fileId);

    if (!file.getOwner().equals(principal.getName())) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access denied");
    }

    return ResponseEntity.ok(fileService.download(fileId));
}
```

---

## **🔐 Best Practices for Preventing BOLA**
| 🔍 Security Issue | 🛑 Impact | ✅ Fix |
|------------------|----------|--------|
| **No Object-Level Authorization** | Attackers access other users' data | Validate ownership in API logic |
| **IDOR (Insecure Direct Object Reference)** | Attackers modify other users' data | Use `@PreAuthorize` for access control |
| **Exposed PII in API Responses** | Data leaks & compliance violations (GDPR) | Return only necessary fields |
| **Lack of Role-Based Access Control (RBAC)** | Unauthorized API modifications | Implement `@RolesAllowed` for admins |
| **Weak Session Validation** | Attackers reuse old sessions | Implement session timeouts & refresh tokens |

---

## **🚀 Secure BOLA Implementation in Spring Security**
Create a `SecurityConfig.java` file:  
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/users/*").authenticated()
                .requestMatchers("/api/admin/*").hasRole("ADMIN")
                .anyRequest().permitAll())
            .csrf(csrf -> csrf.disable())
            .formLogin(withDefaults());

        return http.build();
    }
}
```

---

## **🛠️ How to Test for BOLA Vulnerabilities**
### **1️⃣ Manual Testing Using Postman or Burp Suite**
1. **Log in as User A** → Fetch your user ID (`12345`).  
2. **Modify API request** → Change user ID to another (`67890`).  
3. **Check response** → If data is exposed, API is vulnerable.  

### **2️⃣ Automated Testing Using OWASP ZAP**
1. Run **ZAP Scanner** against API endpoints.  
2. Look for **BOLA-related vulnerabilities** (`401`, `403` bypass).  
3. Fix issues based on **misconfigured authorization logic**.  

---

## **📌 Conclusion**
✅ **BOLA is the #1 OWASP API vulnerability**—always enforce **object-level authorization**.  
✅ **Attackers exploit predictable API IDs**—never expose **raw identifiers**.  
✅ **Secure APIs using RBAC, ownership checks, and JWT claims**.  

---

# **🚨 OWASP API Security Top 10 (2023) - API2:2023 - Broken User Authentication**  

### **🔍 What is Broken User Authentication?**  
Broken User Authentication occurs when an API **fails to properly verify user identities**, allowing attackers to:  
✔ **Bypass authentication** mechanisms.  
✔ **Hijack accounts** using credential stuffing, brute force, or weak tokens.  
✔ **Exploit session management issues** to stay logged in even after logout.  

### **🚨 Why is Broken Authentication Dangerous?**  
❌ Attackers can **take over user accounts** and access private data.  
❌ Weak password policies allow **brute-force attacks**.  
❌ Unprotected JWT tokens can be **stolen and reused**.  
❌ Missing **token expiration & refresh mechanisms** leads to session hijacking.  

---

## **🕵️‍♂️ Real-World Example of Broken User Authentication**
### **Case 1: Brute-Force Login Attack**
#### **Scenario:**  
A login API allows users to authenticate:  
```http
POST /api/login
Host: example.com
Content-Type: application/json

{
    "username": "admin",
    "password": "password123"
}
```
#### **🔴 Vulnerability:**  
- If the API **does not limit login attempts**, attackers can try thousands of passwords.  
- Attackers use **brute-force tools** to crack weak passwords.  

#### **✅ Fix: Implement Account Lockout on Failed Attempts**  
```java
@Service
public class LoginAttemptService {
    private final Cache<String, Integer> attemptsCache;

    public LoginAttemptService() {
        this.attemptsCache = CacheBuilder.newBuilder()
            .expireAfterWrite(15, TimeUnit.MINUTES)
            .build();
    }

    public void loginFailed(String username) {
        int attempts = attemptsCache.getOrDefault(username, 0);
        attemptsCache.put(username, attempts + 1);
    }

    public boolean isBlocked(String username) {
        return attemptsCache.getOrDefault(username, 0) >= 5;  // Blocks after 5 failed attempts
    }
}
```

---

### **Case 2: Weak Password Storage**
#### **Scenario:**  
- If passwords are stored in **plain text**, an attacker who breaches the database gets **all user passwords**.  

#### **✅ Fix: Hash Passwords with BCrypt**
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```
🔐 **Why use BCrypt?**  
✔ **Slow hashing** prevents brute-force attacks.  
✔ **Salted hashing** ensures unique hashes for the same password.  

---

### **Case 3: Insecure JWT Token Handling**
#### **Scenario:**  
A weakly signed JWT token is used for authentication:  
```java
public String generateToken(UserDetails userDetails) {
    return Jwts.builder()
            .setSubject(userDetails.getUsername())
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hour
            .signWith(SignatureAlgorithm.HS256, "SecretKey")  // ❌ Weak Secret Key
            .compact();
}
```
#### **🔴 Vulnerability:**  
- If **"SecretKey"** is weak, attackers can **crack** the JWT and generate valid tokens.  
- If **tokens don’t expire**, stolen tokens remain valid forever.  

#### **✅ Fix: Use a Strong Secret Key & Token Expiry**
```java
public String generateToken(UserDetails userDetails) {
    return Jwts.builder()
            .setSubject(userDetails.getUsername())
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hour
            .signWith(SignatureAlgorithm.HS256, Keys.secretKeyFor(SignatureAlgorithm.HS256)) // 🔐 Secure Key
            .compact();
}
```
🔐 **Best Practices for JWT Security**  
✔ **Use a strong, unpredictable secret key.**  
✔ **Set expiration time** to avoid long-lived tokens.  
✔ **Rotate keys regularly**.  

---

### **Case 4: Missing Logout & Token Revocation**
#### **Scenario:**  
- A user logs out, but the JWT remains valid.  
- If an attacker steals the token, they **stay logged in forever**.  

#### **✅ Fix: Implement Logout & Token Blacklisting**
1️⃣ **Store revoked tokens in a blacklist**  
```java
@Service
public class TokenBlacklistService {
    private final Set<String> blacklistedTokens = new HashSet<>();

    public void blacklistToken(String token) {
        blacklistedTokens.add(token);
    }

    public boolean isBlacklisted(String token) {
        return blacklistedTokens.contains(token);
    }
}
```
2️⃣ **Check if token is blacklisted during authentication**  
```java
public boolean validateToken(String token) {
    if (tokenBlacklistService.isBlacklisted(token)) {
        return false; // ❌ Reject Blacklisted Token
    }
    return !isTokenExpired(token);
}
```

---

## **🚀 Secure Authentication Flow (Step-by-Step)**
1️⃣ **User logs in with username & password.**  
2️⃣ **API verifies credentials & generates a JWT token.**  
3️⃣ **JWT token is used for API requests (Bearer Token).**  
4️⃣ **Token expires after a set time, requiring renewal.**  
5️⃣ **Logout revokes the token.**  

---

## **🔐 Best Practices for Securing API Authentication**
| 🔍 Security Issue | 🛑 Impact | ✅ Fix |
|------------------|----------|--------|
| **Weak Password Storage** | Attackers steal all user credentials | Use `BCryptPasswordEncoder` |
| **Brute-Force Attacks** | Hackers guess weak passwords | Lock account after failed attempts |
| **Insecure JWT Tokens** | Attackers forge authentication tokens | Use strong keys & expiry |
| **Session Hijacking** | Users stay logged in even after logout | Implement logout & token revocation |
| **Lack of MFA** | Single-factor authentication is easily bypassed | Enable multi-factor authentication |

---

## **📌 Conclusion**
✅ **Broken User Authentication is a major API security flaw**—always enforce **strong authentication mechanisms**.  
✅ **JWT tokens must be securely generated, expired, and revoked**.  
✅ **Never store passwords in plain text**—always use **BCrypt hashing**.  

---


# **🚨 OWASP API Security Top 10 (2023) - API3:2023 - Broken Object Property Level Authorization**  

## **🔍 What is Broken Object Property Level Authorization?**  
This vulnerability occurs when an API **fails to properly restrict which object properties a user can modify**, allowing attackers to:  
✔ **Modify sensitive fields**, such as `role`, `balance`, or `isAdmin`.  
✔ **Escalate privileges**, gaining unauthorized access to admin features.  
✔ **Alter financial data**, changing their own balance or someone else’s.  
✔ **Bypass business rules**, like order pricing or subscription limits.  

---

## **🚨 Why is This Dangerous?**  
❌ Attackers can **change their role from 'user' to 'admin'**, gaining full control.  
❌ Users can **modify restricted fields**, such as increasing their account balance.  
❌ Lack of proper property-level access control leads to **data tampering attacks**.  

---

## **🕵️‍♂️ Real-World Example of Broken Object Property Level Authorization**
### **Case 1: Role Escalation via API Request**
#### **Scenario:**  
A user profile update API allows modifying account details:  
```http
PUT /api/update-user
Host: example.com
Content-Type: application/json

{
    "username": "john_doe",
    "email": "john@example.com",
    "role": "admin"  // 🔴 ATTACKER ADDS THIS FIELD
}
```
#### **🔴 Vulnerability:**  
- If the backend **directly updates the user object**, the attacker **escalates privileges to admin**.  
- No **authorization check** is in place to prevent unauthorized modifications.  

#### **🚨 Vulnerable Code (No Property-Level Authorization)**
```java
@PutMapping("/update-user")
public User updateUser(@RequestBody User user) {
    return userRepository.save(user);  // ❌ Updates ALL fields without restriction
}
```
🚨 **Danger:**  
- This API allows attackers to **change any property** of their account, including `role`.  
- If no access control is implemented, attackers can **become administrators**.  

---

### **✅ Secure Solution: Use DTOs to Restrict Editable Fields**
#### **Fix: Implement Data Transfer Objects (DTOs)**
A **DTO (Data Transfer Object)** ensures that only **allowed fields** can be modified.
```java
public class UserDTO {
    private String email;  // ✅ Only email can be modified
    // ❌ No role, isAdmin, or other sensitive fields
}
```
Now, modify the controller:
```java
@PutMapping("/update-user")
public ResponseEntity<?> updateUser(@RequestBody UserDTO userDto, @AuthenticationPrincipal UserDetails userDetails) {
    User user = userRepository.findByUsername(userDetails.getUsername());
    user.setEmail(userDto.getEmail()); // ✅ Only email can be updated
    userRepository.save(user);
    return ResponseEntity.ok("User updated successfully!");
}
```
🔐 **Why This Works?**  
✔ The `UserDTO` **prevents modification of sensitive fields** like `role`.  
✔ Attackers cannot escalate privileges since `role` is **not included** in the DTO.  

---

### **Case 2: Manipulating Financial Data (Balance Tampering)**
#### **Scenario:**  
A banking API allows users to update their profile information:  
```http
PUT /api/update-profile
Host: bank.com
Content-Type: application/json

{
    "username": "alice",
    "email": "alice@example.com",
    "balance": 1000000  // 🔴 ATTACKER MODIFIES BALANCE
}
```
#### **🔴 Vulnerability:**  
- If the API **blindly updates all user fields**, attackers can **change their account balance**.  

#### **✅ Fix: Prevent Unauthorized Fields from Being Updated**
Modify the DTO:
```java
public class UserDTO {
    private String email; // ✅ Only email is editable
}
```
Modify the API:
```java
@PutMapping("/update-profile")
public ResponseEntity<?> updateUser(@RequestBody UserDTO userDto, @AuthenticationPrincipal UserDetails userDetails) {
    User user = userRepository.findByUsername(userDetails.getUsername());
    user.setEmail(userDto.getEmail()); // ✅ Only email can be changed
    userRepository.save(user);
    return ResponseEntity.ok("Profile updated successfully!");
}
```
🚀 **Impact:**  
✔ Users **cannot modify their balance** or other restricted fields.  
✔ The **backend controls what can be changed**, preventing tampering.  

---

### **Case 3: Bypassing Subscription Restrictions**
#### **Scenario:**  
An e-learning platform offers **free and premium subscriptions**. A user's subscription status is stored in the API:  
```json
{
    "username": "student1",
    "email": "student@example.com",
    "subscription": "free"
}
```
Attackers modify the API request to upgrade their plan:  
```http
PUT /api/update-subscription
Host: elearning.com
Content-Type: application/json

{
    "username": "student1",
    "subscription": "premium"  // 🔴 ATTACKER CHANGES SUBSCRIPTION STATUS
}
```
#### **🔴 Vulnerability:**  
- If the API **does not verify user roles**, attackers can **upgrade themselves to premium for free**.  

#### **✅ Fix: Restrict Subscription Changes to Admins**
Modify the controller:
```java
@PutMapping("/update-subscription")
@PreAuthorize("hasRole('ADMIN')") // ✅ Only admin can modify subscriptions
public ResponseEntity<?> updateSubscription(@RequestBody SubscriptionDTO subscriptionDto) {
    User user = userRepository.findByUsername(subscriptionDto.getUsername());
    user.setSubscription(subscriptionDto.getSubscriptionType()); // ✅ Only admins can modify
    userRepository.save(user);
    return ResponseEntity.ok("Subscription updated successfully!");
}
```
🔐 **Why This Works?**  
✔ Only **admins** can update subscription details.  
✔ Regular users **cannot modify** their subscription via API requests.  

---

## **🚀 Secure Object Property-Level Authorization (Step-by-Step)**
| 🔍 Security Issue | 🛑 Impact | ✅ Fix |
|------------------|----------|--------|
| **Role Escalation** | Attackers modify `role` to become admin | Use `DTO` to allow only specific fields |
| **Balance Tampering** | Users increase their own account balance | Backend should restrict modifiable fields |
| **Subscription Bypass** | Attackers upgrade to premium without paying | Use role-based access control (`@PreAuthorize`) |
| **Data Corruption** | Users overwrite sensitive business logic fields | Apply strict backend validation |

---

## **📌 Conclusion**
✅ **APIs must validate and control which object properties users can modify.**  
✅ **Use DTOs** to allow only authorized fields for updates.  
✅ **Enforce role-based access control (RBAC)** to prevent unauthorized modifications.  
✅ **Apply security at multiple levels (DTOs, role checks, validation).**  

---
























### **OWASP API Security Top 10 (2023) - API8:2023 Security Misconfiguration (Deep Explanation)**  

---

## **🔍 What is Security Misconfiguration?**  
Security misconfiguration happens when an API is **improperly configured**, leaving it vulnerable to attacks. This can include:  
- **Exposed sensitive information** (stack traces, error messages).  
- **Default credentials left unchanged** (admin:admin).  
- **Unnecessary HTTP methods enabled** (PUT, DELETE).  
- **Lack of proper security headers** (CORS misconfigurations).  
- **Open debugging endpoints** (e.g., `actuator` endpoints).  

**🛑 Impact of Security Misconfiguration**  
- Attackers **enumerate API endpoints** to find sensitive data.  
- They **bypass authentication** using weak configurations.  
- APIs can be **hijacked, defaced, or disrupted**.  

---

## **🕵️‍♂️ Real-World Example of Security Misconfiguration**
### **Case 1: Exposed Admin Panel**  
**Scenario:**  
A **finance application API** exposes an unauthenticated `/admin` endpoint.  

```http
GET /admin/dashboard
Host: api.bank.com
```
**Vulnerability:**  
- No authentication required → Attackers can **access the admin panel**.  
- Sensitive **user transaction logs** can be leaked.  

**✅ Fix:**  
Use **Spring Security** to enforce authentication & role-based access control.  

```java
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin/dashboard")
public ResponseEntity<?> getAdminDashboard() {
    return ResponseEntity.ok("Secure Admin Panel");
}
```

---

### **Case 2: Unrestricted Actuator Endpoints**  
Spring Boot applications have **Actuator endpoints** (`/actuator`) for monitoring. By default, some of these are **open to the public**, leading to information leaks.  

#### **🚨 Vulnerable Example**
```http
GET /actuator/env
Host: api.target.com
```
#### **⚠️ What an Attacker Can Do**
- Access **database credentials** (`spring.datasource.password`)  
- Modify **application properties** (`logging.level`)  
- Shut down the application (`/actuator/shutdown`)  

#### **✅ Secure Fix**
In `application.yml`, disable sensitive Actuator endpoints:  
```yaml
management:
  endpoints:
    web:
      exposure:
        include: "health,info"
  endpoint:
    shutdown:
      enabled: false
    env:
      enabled: false
```

---

### **Case 3: Exposed Stack Traces**
**Scenario:**  
A poorly configured API leaks stack traces when an error occurs.  
```http
GET /users/99999
```
**Response (🚨 Vulnerability)**  
```json
{
  "error": "java.sql.SQLException: Table 'users' doesn't exist",
  "stacktrace": "at org.example.dao.UserDAO.getUserById(UserDAO.java:45)"
}
```
**🔴 Why is this dangerous?**  
- Reveals **internal database structure**.  
- Attackers gain insight into API **libraries & versions**.  

**✅ Fix: Disable Detailed Error Messages**
In `application.yml`:  
```yaml
server:
  error:
    include-message: never
    include-stacktrace: never
```
Instead, return **generic error responses**:  
```java
@ExceptionHandler(Exception.class)
public ResponseEntity<?> handleException(Exception ex) {
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body("An error occurred, please contact support.");
}
```

---

### **Case 4: Missing Security Headers (CORS Misconfiguration)**
Cross-Origin Resource Sharing (**CORS**) misconfigurations allow unauthorized cross-site requests.  

#### **🚨 Vulnerable Configuration**
```java
@CrossOrigin(origins = "*")
@RestController
public class UserController { }
```
**🛑 Why is this bad?**
- `*` allows **any website** to make requests, leading to **CSRF attacks**.  

**✅ Secure Fix: Restrict Trusted Origins**
```java
@Bean
public WebMvcConfigurer corsConfigurer() {
    return new WebMvcConfigurer() {
        @Override
        public void addCorsMappings(CorsRegistry registry) {
            registry.addMapping("/api/**")
                    .allowedOrigins("https://trusted.com")
                    .allowedMethods("GET", "POST");
        }
    };
}
```

---

### **Case 5: Default Passwords & Unchanged Configurations**
Many APIs ship with **default admin credentials**, which developers **forget to change**.  

#### **🚨 Vulnerable Configuration**
```bash
# Default credentials in environment variables
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin
```
An attacker can **easily guess these credentials** and log in.  

#### **✅ Secure Fix:**
- **Force password updates** on first login.  
- **Use environment variables instead of hardcoded passwords**.  
- Implement **multi-factor authentication (MFA)**.  
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```
---

## **🔐 Best Practices for Preventing Security Misconfigurations**
| 🔍 Security Issue | 🛑 Impact | ✅ Fix |
|------------------|----------|--------|
| **Exposed Admin Panels** | Attackers gain unauthorized access | Use authentication & role-based access |
| **Open Actuator Endpoints** | API secrets & logs leaked | Restrict `/actuator/*` access |
| **Stack Traces in API Responses** | Reveals database structure | Disable stack traces in production |
| **CORS Misconfiguration** | Unauthorized requests from other origins | Restrict to trusted domains |
| **Default Credentials** | Attackers can log in with default admin credentials | Enforce strong passwords & MFA |
| **Exposed HTTP Methods** | Attackers modify data using `PUT/DELETE` | Use `@Secured` to restrict methods |
| **Missing Security Headers** | API vulnerable to **Clickjacking, XSS** | Use **CSP, HSTS, X-Frame-Options** |

---

## **🚀 Final Secure Spring Security Configuration**
Create a `SecurityConfig.java` file:  
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
                .contentSecurityPolicy("default-src 'self'")
                .xssProtection(xss -> xss.block(true))
                .frameOptions(frame -> frame.sameOrigin()))
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated())
            .formLogin(withDefaults());
        return http.build();
    }
}
```

---

## **📌 Conclusion**
✅ Security misconfiguration is one of the **most common** API vulnerabilities.  
✅ Attackers **scan APIs** for weak configurations.  
✅ Following **secure defaults** & **best practices** reduces attack risk.  

