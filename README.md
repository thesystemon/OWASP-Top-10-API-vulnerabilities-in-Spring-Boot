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

# **🚨 OWASP API Security Top 10 (2023) - API1:2023 - Broken Object Level Authorization (BOLA)**  

---

## **🔍 What is BOLA?**  
**Broken Object Level Authorization (BOLA)** is the most critical vulnerability in **API security**. It occurs when an API does not **properly check user permissions**, allowing attackers to **access, modify, or delete unauthorized data**.  

### **🚨 What Can Attackers Do?**
✔ **View sensitive data of other users** (e.g., profile details, financial records).  
✔ **Modify or delete data they don’t own** (e.g., another user's orders, messages).  
✔ **Access restricted API endpoints** (e.g., admin-only data).  
✔ **Exploit predictable IDs to extract data** (e.g., `GET /user/123`, `GET /user/124`).

---

## **🕵️‍♂️ Real-World Example of BOLA**
### **Case 1: API Allows Any User to View Any Profile**
#### **Scenario:**  
A banking application provides an endpoint to fetch **user details**:
```http
GET /user/1001
Authorization: Bearer <user_token>
```
A logged-in user **John (ID: 1001)** can retrieve his profile.  
However, if **John modifies the ID** to another user’s ID (`1002`), he might access **someone else's profile**:
```http
GET /user/1002
Authorization: Bearer <user_token>
```
🚨 **This works if the API does not check if the requested user ID matches the logged-in user.**  

#### **🔴 Vulnerable Code (No Authorization Check)**
```java
@GetMapping("/user/{id}")
public User getUser(@PathVariable Long id) {
    return userRepository.findById(id)
           .orElseThrow(() -> new RuntimeException("User Not Found"));
}
```
🚨 **Danger:**  
- **No authentication check** – anyone can request any user’s details.  
- **No ownership validation** – users can access others' data by changing the ID.  
- **Attackers can scrape large amounts of user data**.  

---

## **✅ Secure Solution: Enforce Authentication & Authorization**
✔ **Verify the authenticated user matches the requested data.**  
✔ **Use `@AuthenticationPrincipal` to retrieve the logged-in user.**  
✔ **Deny access if the user ID does not match.**  

```java
@GetMapping("/user/{id}")
public ResponseEntity<?> getUser(@PathVariable Long id, @AuthenticationPrincipal UserDetails userDetails) {
    User user = userRepository.findById(id)
              .orElseThrow(() -> new RuntimeException("User Not Found"));

    // 🚀 Step 1: Check if the logged-in user is requesting their own data
    if (!user.getUsername().equals(userDetails.getUsername())) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access Denied!");
    }

    return ResponseEntity.ok(user);
}
```
🔐 **Why This Works?**  
✔ **Only allows users to access their own data**.  
✔ **Prevents attackers from accessing other users' data.**  
✔ **Returns `403 Forbidden` when unauthorized access is attempted.**  

---

### **🔧 Improved Secure Implementation**
✅ **Use Role-Based Access Control (RBAC) for better security.**  
✅ **Use UUIDs instead of predictable numeric IDs.**  
✅ **Log unauthorized access attempts.**  

```java
@GetMapping("/user/{id}")
public ResponseEntity<?> getUser(@PathVariable Long id, 
                                 @AuthenticationPrincipal UserDetails userDetails) {
    Optional<User> userOpt = userRepository.findById(id);
    if (userOpt.isEmpty()) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User Not Found");
    }

    User user = userOpt.get();

    // 🚀 Step 1: Check if the logged-in user is requesting their own data
    if (!user.getUsername().equals(userDetails.getUsername())) {
        log.warn("Unauthorized access attempt by user: {}", userDetails.getUsername());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access Denied!");
    }

    return ResponseEntity.ok(user);
}
```
🔐 **Why This Works?**  
✔ **Returns `404 Not Found` if the user does not exist.**  
✔ **Prevents attackers from distinguishing between valid/invalid user IDs.**  
✔ **Logs unauthorized access attempts for security monitoring.**  

---

## **🚀 Advanced BOLA Prevention Techniques**
### **Case 2: Preventing BOLA in an E-commerce Application**
#### **Scenario:**  
A shopping platform provides an API to fetch **order details**:
```http
GET /orders/5001
Authorization: Bearer <user_token>
```
A user can **modify the ID (`5002`)** to access **another customer's order details**.

#### **✅ Fix: Ensure Users Can Only View Their Own Orders**
```java
@GetMapping("/orders/{orderId}")
public ResponseEntity<?> getOrder(@PathVariable Long orderId, 
                                  @AuthenticationPrincipal UserDetails userDetails) {
    Order order = orderRepository.findById(orderId)
                 .orElseThrow(() -> new RuntimeException("Order Not Found"));

    // 🚀 Check if the authenticated user owns the order
    if (!order.getUser().getUsername().equals(userDetails.getUsername())) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access Denied!");
    }

    return ResponseEntity.ok(order);
}
```
🚀 **Impact:**  
✔ **Ensures users can only access their own orders.**  
✔ **Prevents unauthorized users from viewing sensitive data.**  

---

## **🕵️‍♂️ Use Case 3: Unauthorized Ticket Cancellation in an Airline System**
### **Scenario:**  
A flight booking system provides an API for users to cancel their flight tickets:  
```http
DELETE /tickets/7001
Authorization: Bearer <user_token>
```
A logged-in user **Alex (ticket ID: 7001)** can cancel his ticket.  
However, if **Alex modifies the ticket ID (`7002`)**, he might cancel **someone else's booking**:
```http
DELETE /tickets/7002
Authorization: Bearer <user_token>
```
🚨 **This works if the API does not check if the ticket actually belongs to Alex.**  
#### **🔴 Vulnerable Code (No Authorization Check)**
```java
@DeleteMapping("/tickets/{ticketId}")
public ResponseEntity<?> cancelTicket(@PathVariable Long ticketId) {
    ticketRepository.deleteById(ticketId);
    return ResponseEntity.ok("Ticket Cancelled Successfully!");
}
```
🚨 **Issues:**  
- **Any user can cancel any ticket.**  
- **No authentication check – attackers can modify the `ticketId`.**  
- **Attackers can cause mass ticket cancellations.**  
#### **✅ Secure Code (Restrict Access to Owner)**
```java
@DeleteMapping("/tickets/{ticketId}")
public ResponseEntity<?> cancelTicket(@PathVariable Long ticketId, @AuthenticationPrincipal UserDetails userDetails) {
    Ticket ticket = ticketRepository.findById(ticketId)
                  .orElseThrow(() -> new RuntimeException("Ticket Not Found"));
    // 🚀 Check if the authenticated user owns the ticket
    if (!ticket.getUser().getUsername().equals(userDetails.getUsername())) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access Denied!");
    }
    ticketRepository.delete(ticket);
    return ResponseEntity.ok("Ticket Cancelled Successfully!");
}
```
🔐 **Why This Works?**  
✔ **Ensures users can only cancel their own tickets.**  
✔ **Prevents unauthorized modifications by attackers.**  
✔ **Protects users from fraudulent cancellations.**  
---

## **📌 Summary: Secure API Design Against BOLA**
| 🔍 Security Issue | 🛑 Impact | ✅ Fix |
|------------------|----------|--------|
| **No authentication check** | Any user can access any object | **Enforce authentication using `@AuthenticationPrincipal`** |
| **Predictable object IDs** | Attackers can enumerate IDs | **Use UUIDs instead of numeric IDs** |
| **Lack of ownership validation** | Users can access other users' data | **Check if the object belongs to the authenticated user** |
| **No access logs** | Security breaches go undetected | **Log unauthorized access attempts** |

---

## **📌 Conclusion**
✅ **Always check if the authenticated user is allowed to access the requested object.**  
✅ **Use UUIDs instead of numeric IDs to prevent easy enumeration.**  
✅ **Log unauthorized access attempts for security monitoring.**  
✅ **Use role-based access control (RBAC) for fine-grained permissions.**  

---

# **🚨 OWASP API Security Top 10 (2023) - API2:2023 - Broken User Authentication**  

---

## **🔍 What is Broken User Authentication?**  
**Broken User Authentication** occurs when an API fails to **properly secure login mechanisms**, allowing attackers to **hijack accounts, bypass authentication, or perform unauthorized actions**.  

### **🚨 What Can Attackers Do?**
✔ **Brute-force weak passwords.**  
✔ **Exploit missing account lockout protections.**  
✔ **Steal session tokens and impersonate users.**  
✔ **Exploit insecure JWT implementations.**  

---

## **🕵️‍♂️ Use Case 1: Brute-Force Attack on Login API**
### **Scenario:**  
A banking application provides an API for users to log in:  
```http
POST /api/login
Content-Type: application/json

{
  "username": "john_doe",
  "password": "password123"
}
```
🚨 **If there’s no brute-force protection, an attacker can try multiple passwords until they find the correct one.**  

#### **🔴 Vulnerable Code (No Protection Against Brute Force)**
```java
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
    User user = userRepository.findByUsername(loginRequest.getUsername());
    
    if (user == null || !user.getPassword().equals(loginRequest.getPassword())) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Credentials");
    }

    return ResponseEntity.ok("Login Successful");
}
```
🚨 **Issues:**  
- **No password hashing** – passwords are stored in plain text.  
- **No brute-force protection** – attackers can guess passwords.  
- **No token-based authentication** – sessions are not managed securely.  

#### **✅ Secure Code (Using JWT and Password Hashing)**
```java
@Autowired
private AuthenticationManager authenticationManager;

@Autowired
private JwtUtil jwtUtil;

@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
    Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);

    String token = jwtUtil.generateToken(authentication.getName());

    return ResponseEntity.ok(new AuthResponse(token));
}
```
🔐 **Why This Works?**  
✔ **Uses `BCrypt` to store passwords securely.**  
✔ **Uses JWT tokens instead of session-based authentication.**  
✔ **Prevents brute-force attacks by implementing account lockout after failed attempts.**  

---

## **🕵️‍♂️ Use Case 2: Session Hijacking via Insecure JWT**
### **Scenario:**  
An e-commerce website uses **JWT tokens** for authentication:  
```http
GET /api/orders
Authorization: Bearer <JWT-TOKEN>
```
🚨 **If the JWT is not securely implemented, an attacker can forge tokens and impersonate users.**  

#### **🔴 Vulnerable Code (Using a Weak Secret Key)**
```java
public String generateToken(UserDetails userDetails) {
    return Jwts.builder()
            .setSubject(userDetails.getUsername())
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hour
            .signWith(SignatureAlgorithm.HS256, "12345") // 🚨 Weak Secret Key
            .compact();
}
```
🚨 **Issues:**  
- **Uses a weak secret key (`"12345"`) that can be guessed.**  
- **Tokens can be forged, allowing attackers to impersonate users.**  
- **No token expiration check, enabling session hijacking.**  

#### **✅ Secure Code (Using Strong Secret & Expiry)**
```java
public String generateToken(UserDetails userDetails) {
    return Jwts.builder()
            .setSubject(userDetails.getUsername())
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hour
            .signWith(SignatureAlgorithm.HS256, "SuperSecretKeyWithHighEntropy123!") // Strong Secret Key
            .compact();
}
```
🔐 **Why This Works?**  
✔ **Uses a strong secret key that attackers cannot guess.**  
✔ **Ensures tokens expire after 1 hour to prevent misuse.**  
✔ **Prevents session hijacking by forcing re-authentication.**  

---

## **🕵️‍♂️ Use Case 3: Account Takeover via Weak Password Storage**
### **Scenario:**  
A user signs up on a social media platform with a password:  
```http
POST /api/register
Content-Type: application/json

{
  "username": "johndoe",
  "password": "mypassword123"
}
```
🚨 **If passwords are stored in plaintext, an attacker who gains database access can steal user credentials.**  

#### **🔴 Vulnerable Code (Plaintext Password Storage)**
```java
@PostMapping("/register")
public ResponseEntity<?> register(@RequestBody User user) {
    userRepository.save(user); // 🚨 Password is stored as plaintext!
    return ResponseEntity.ok("User Registered");
}
```
🚨 **Issues:**  
- **Stores passwords in plaintext – a major security risk!**  
- **If the database is leaked, all user accounts are compromised.**  

#### **✅ Secure Code (Using BCrypt for Password Hashing)**
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}

@PostMapping("/register")
public ResponseEntity<?> register(@RequestBody User user) {
    user.setPassword(passwordEncoder().encode(user.getPassword())); // 🔒 Encrypt Password
    userRepository.save(user);
    return ResponseEntity.ok("User Registered Securely");
}
```
🔐 **Why This Works?**  
✔ **Uses `BCrypt` hashing to store passwords securely.**  
✔ **Even if the database is leaked, attackers cannot retrieve plain-text passwords.**  
✔ **Prevents account takeovers from credential leaks.**  

---

## **📌 Summary: Secure Authentication Practices**
| 🔍 Security Issue | 🛑 Impact | ✅ Fix |
|------------------|----------|--------|
| **No brute-force protection** | Attackers can guess passwords | **Implement account lockout & rate limiting** |
| **Plaintext passwords** | Stolen database = All accounts hacked | **Use `BCrypt` for password hashing** |
| **Weak JWT secret** | Attackers can forge tokens | **Use a strong secret key** |
| **No token expiration** | Session hijacking | **Implement token expiry & refresh mechanisms** |

---

## **📌 Conclusion**
✅ **Use strong password hashing (`BCrypt`) to store passwords securely.**  
✅ **Implement JWT-based authentication with a strong secret key.**  
✅ **Ensure JWT tokens expire and implement a refresh mechanism.**  
✅ **Add brute-force protection by locking accounts after failed login attempts.**  

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

# **🚨 OWASP API Security Top 10 (2023) - API4:2023 - Unrestricted Resource Consumption**  

## **🔍 What is Unrestricted Resource Consumption?**  
This vulnerability occurs when an API **fails to limit how much CPU, memory, bandwidth, or database connections a user can consume**, allowing attackers to:  

✔ **Launch Denial-of-Service (DoS) attacks** by overloading the server.  
✔ **Consume excessive system resources**, slowing down services for other users.  
✔ **Exploit unauthenticated APIs**, leading to high operational costs.  
✔ **Bypass API rate limits** to abuse free-tier services.  

---

## **🚨 Why is This Dangerous?**  
❌ Attackers can **spam API requests**, making the service **unavailable**.  
❌ High API traffic **increases cloud costs**, leading to **financial losses**.  
❌ Attackers can **exploit computationally expensive operations** (e.g., database-heavy requests).  
❌ A single user **can exhaust all available resources**, affecting all other users.  

---

## **🕵️‍♂️ Real-World Example of Unrestricted Resource Consumption**
### **Case 1: API Overloading via Unlimited Requests**
#### **Scenario:**  
An API allows fetching user profile details with no request limits:  
```http
GET /api/user-profile?username=john
```
An attacker writes a script to **send thousands of requests per second**, overloading the server:  
```bash
while true; do curl -X GET "https://example.com/api/user-profile?username=john"; done
```
#### **🔴 Vulnerability:**  
- If there is **no rate limiting**, the attacker **saturates API resources**.  
- This can **crash the server** or **slow it down for legitimate users**.  

#### **🚨 Vulnerable Code (No Rate Limiting)**
```java
@GetMapping("/user-profile")
public User getUserProfile(@RequestParam String username) {
    return userRepository.findByUsername(username); // ❌ No request limit
}
```
🚨 **Danger:**  
- Any user can send **unlimited requests**, consuming all resources.  
- Attackers can **cause API downtime** without authentication.  

---

### **✅ Secure Solution: Implement Rate Limiting with Bucket4j**
#### **Fix: Use Bucket4j to Limit API Requests**
`Bucket4j` is a Java library that enforces rate limits using the **Token Bucket Algorithm**.

```java
@Bean
public Filter rateLimiterFilter() {
    return (request, response, chain) -> {
        Bucket bucket = Bucket4j.builder()
                .addLimit(Bandwidth.simple(10, Duration.ofMinutes(1))) // ✅ Max 10 requests per min
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
🔐 **Why This Works?**  
✔ Each user **can only make 10 API requests per minute**.  
✔ Attackers **cannot overload the API** with excessive requests.  
✔ If the limit is exceeded, the API **returns HTTP 429 (Too Many Requests)**.  

---

### **Case 2: Server Resource Exhaustion via Expensive API Calls**
#### **Scenario:**  
An e-commerce API allows users to search for products:  
```http
GET /api/search?query=laptop
```
Attackers **abuse this API** by sending millions of requests with complex filters:  
```http
GET /api/search?query=laptop&sort=price_desc&limit=1000
```
#### **🔴 Vulnerability:**  
- If the API does not **restrict expensive operations**, attackers can **overload the database**.  
- **Large queries** consume high memory and **slow down** the service.  

#### **✅ Fix: Implement Query Limits**
Modify the API to **limit the number of results** and enforce caching:
```java
@GetMapping("/search")
public ResponseEntity<List<Product>> searchProducts(
        @RequestParam String query,
        @RequestParam(defaultValue = "20") int limit) { // ✅ Limit results
    if (limit > 50) { // ✅ Enforce max limit
        return ResponseEntity.badRequest().body(Collections.emptyList());
    }
    List<Product> results = productService.search(query, limit);
    return ResponseEntity.ok(results);
}
```
🚀 **Impact:**  
✔ Attackers **cannot fetch unlimited records** in a single request.  
✔ The **database is protected** from excessive load.  
✔ **Caching** can be used to optimize repeated queries.  

---

### **Case 3: Unrestricted File Uploads Leading to Disk Exhaustion**
#### **Scenario:**  
A document upload API allows users to upload files:  
```http
POST /api/upload
```
Attackers abuse this API by uploading **huge files** or **infinite loops**:  
```bash
while true; do curl -X POST -F "file=@largefile.zip" "https://example.com/api/upload"; done
```
#### **🔴 Vulnerability:**  
- If there is **no file size limit**, attackers can **fill up the disk space**.  
- **Large file uploads** can cause **server crashes**.  

#### **✅ Fix: Restrict File Uploads**
```java
@PostMapping("/upload")
public ResponseEntity<?> uploadFile(@RequestParam("file") MultipartFile file) {
    if (file.getSize() > 5_000_000) { // ✅ Max 5MB per file
        return ResponseEntity.badRequest().body("File size exceeds limit!");
    }
    fileService.saveFile(file);
    return ResponseEntity.ok("File uploaded successfully!");
}
```
🚀 **Impact:**  
✔ Attackers **cannot upload large files**, preventing disk exhaustion.  
✔ The API **enforces strict file size limits**.  

---

## **🚀 Secure API Resource Management (Step-by-Step)**
| 🔍 Security Issue | 🛑 Impact | ✅ Fix |
|------------------|----------|--------|
| **Unlimited API Requests** | Attackers spam requests, causing DoS | Use **rate limiting** (Bucket4j) |
| **Expensive Database Queries** | Large queries slow down API | Limit query results & use caching |
| **Unrestricted File Uploads** | Large files fill up server disk | Set **file size limits** (5MB max) |
| **Infinite API Loops** | API processing overload | Use **timeout & request validation** |

---

## **📌 Conclusion**
✅ **APIs should restrict resource consumption to prevent abuse.**  
✅ **Use rate limiting (Bucket4j)** to prevent API overuse.  
✅ **Limit database queries** and apply caching for efficiency.  
✅ **Restrict file upload sizes** to prevent storage exhaustion.  

---

# **🚨 OWASP API Security Top 10 (2023) - API5:2023 - Broken Function Level Authorization**  

---

## **🔍 What is Broken Function Level Authorization?**  
Broken Function Level Authorization (BFLA) occurs when an API **does not properly enforce user roles and privileges**, allowing attackers to:  

✔ **Access admin-only endpoints** (e.g., delete users, modify system settings).  
✔ **Escalate privileges** by calling unauthorized functions.  
✔ **Perform actions they are not supposed to** (e.g., non-admin users deleting accounts).  
✔ **Modify sensitive configurations** without proper authorization.  

---

## **🚨 Why is This Dangerous?**  
❌ **Attackers can perform admin actions**, leading to **data loss**.  
❌ **Malicious users can bypass authorization**, accessing restricted functionalities.  
❌ **Unauthorized API endpoints** may expose **critical system controls**.  
❌ **Lack of role-based access control (RBAC)** allows privilege escalation attacks.  

---

## **🕵️‍♂️ Real-World Example of Broken Function Level Authorization**
### **Case 1: Unauthorized User Deleting Other Users**
#### **Scenario:**  
An API has an endpoint to **delete a user**:  
```http
DELETE /api/delete-user/5
```
A regular user **should not** be able to access this, but **if there is no authorization check**, any user can execute:  
```bash
curl -X DELETE "https://example.com/api/delete-user/5"
```
#### **🔴 Vulnerability:**  
- If the API **does not check the user's role**, any user can **delete accounts**.  
- Attackers can **brute-force user IDs** and **delete multiple accounts**.  

#### **🚨 Vulnerable Code (No Role-Based Access Control)**
```java
@DeleteMapping("/delete/{id}")
public ResponseEntity<?> deleteUser(@PathVariable Long id) {
    userRepository.deleteById(id); // ❌ No authorization check
    return ResponseEntity.ok("User deleted successfully!");
}
```
🚨 **Danger:**  
- No **role-based check** allows any user to **delete accounts**.  
- Attackers can **delete any user** just by changing the ID.  

---

### **✅ Secure Solution: Implement Role-Based Access Control (RBAC)**
#### **Fix: Restrict Access Using Spring Security**
Use `@PreAuthorize` to ensure only **admins** can access this function.

```java
@PreAuthorize("hasRole('ADMIN')")
@DeleteMapping("/delete/{id}")
public ResponseEntity<?> deleteUser(@PathVariable Long id) {
    userRepository.deleteById(id);
    return ResponseEntity.ok("User deleted successfully!");
}
```
🔐 **Why This Works?**  
✔ Only users with the **ADMIN role** can call this function.  
✔ Regular users **cannot execute** unauthorized operations.  
✔ Attackers **cannot escalate privileges** or delete accounts.  

---

### **Case 2: Unauthorized User Changing Account Privileges**
#### **Scenario:**  
A regular user should **not** be able to **promote themselves to admin**, but the API has a vulnerable endpoint:  
```http
POST /api/change-role
Body: { "username": "attacker", "role": "ADMIN" }
```
If there is **no role validation**, attackers can **escalate privileges**.

#### **🔴 Vulnerable Code (No Access Control)**
```java
@PostMapping("/change-role")
public ResponseEntity<?> changeUserRole(@RequestBody User user) {
    User existingUser = userRepository.findByUsername(user.getUsername());
    existingUser.setRole(user.getRole()); // ❌ Any user can change roles
    userRepository.save(existingUser);
    return ResponseEntity.ok("User role updated!");
}
```
🚨 **Danger:**  
- Any user can change their role to **ADMIN**.  
- Attackers can **gain full system access** by modifying roles.  

#### **✅ Fix: Validate Role Changes**
```java
@PreAuthorize("hasRole('ADMIN')")
@PostMapping("/change-role")
public ResponseEntity<?> changeUserRole(@RequestBody UserRoleDTO userRoleDto) {
    User existingUser = userRepository.findByUsername(userRoleDto.getUsername());
    existingUser.setRole(userRoleDto.getNewRole());
    userRepository.save(existingUser);
    return ResponseEntity.ok("User role updated successfully!");
}
```
🚀 **Impact:**  
✔ Only **admins** can change user roles.  
✔ Attackers **cannot escalate privileges**.  
✔ API **blocks unauthorized role modifications**.  

---

### **Case 3: Unauthorized Access to Admin-Only Dashboards**
#### **Scenario:**  
A web application has an **admin dashboard** at:  
```http
GET /admin-dashboard
```
But there is **no authentication check**, so any user can access it.

#### **🔴 Vulnerable Code (No Authorization)**
```java
@GetMapping("/admin-dashboard")
public String getAdminDashboard() {
    return "Welcome to Admin Panel!"; // ❌ No access control
}
```
#### **✅ Fix: Restrict Dashboard Access**
```java
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin-dashboard")
public String getAdminDashboard() {
    return "Welcome to Admin Panel!";
}
```
🚀 **Impact:**  
✔ **Only admins** can view the admin dashboard.  
✔ Regular users **cannot access restricted pages**.  

---

## **🚀 Secure Function-Level Authorization (Step-by-Step)**
| 🔍 Security Issue | 🛑 Impact | ✅ Fix |
|------------------|----------|--------|
| **No Role-Based Access Control (RBAC)** | Attackers can access admin functions | Use `@PreAuthorize("hasRole('ADMIN')")` |
| **Privilege Escalation via API Calls** | Regular users can promote themselves | Validate role changes |
| **No Authorization for Admin Dashboards** | Anyone can access admin features | Restrict admin-only routes |

---

## **📌 Conclusion**
✅ **Always enforce role-based access control (RBAC).**  
✅ **Use `@PreAuthorize` in Spring Security** to protect sensitive functions.  
✅ **Validate user roles before executing privileged actions.**  
✅ **Prevent unauthorized users from modifying roles or deleting accounts.**  

---

# **🚨 OWASP API Security Top 10 (2023) - API6:2023 - Unrestricted Access to Sensitive Business Flows**  

---

## **🔍 What is Unrestricted Access to Sensitive Business Flows?**  
This vulnerability occurs when APIs expose **critical business logic** without proper restrictions, allowing attackers to **abuse** application functionalities.  

### **🚨 What Can Attackers Do?**
✔ **Bypass limits on financial transactions** (e.g., unlimited money transfers).  
✔ **Exploit weak rate limits** to automate attacks (e.g., bulk purchases, spam registrations).  
✔ **Trigger unintended business actions** (e.g., infinite discounts, multiple referrals).  
✔ **Perform privilege escalation via API flaws** (e.g., unauthorized access to premium features).  

---

## **🕵️‍♂️ Real-World Example of Unrestricted Access to Sensitive Business Flows**
### **Case 1: Unlimited Money Transfers**
#### **Scenario:**  
An API allows users to **transfer money** via:  
```http
POST /api/transfer
Body: { "amount": 100000 }
```
If the API does **not** enforce limits, an attacker can **drain accounts** by automating requests.

#### **🔴 Vulnerable Code (No Transaction Limits)**
```java
@PostMapping("/transfer")
public ResponseEntity<?> transferMoney(@RequestBody TransferRequest request, 
                                       @AuthenticationPrincipal UserDetails userDetails) {
    User sender = userRepository.findByUsername(userDetails.getUsername());
    processTransaction(sender, request); // ❌ No checks on transfer amount
    return ResponseEntity.ok("Transfer Successful!");
}
```
🚨 **Danger:**  
- Any user can **transfer unlimited money** without restriction.  
- Attackers can **brute-force transactions** and **exploit financial APIs**.  
- No **fraud detection** or **business logic validation** exists.  

---

### **✅ Secure Solution: Enforce Business Logic**
✔ **Limit the transaction amount** to prevent abuse.  
✔ **Validate user balance before processing transactions.**  
✔ **Log and monitor transaction patterns for fraud detection.**  
✔ **Implement rate limiting to prevent brute-force transactions.**  

```java
@PostMapping("/transfer")
public ResponseEntity<?> transferMoney(@RequestBody TransferRequest request, 
                                       @AuthenticationPrincipal UserDetails userDetails) {
    User sender = userRepository.findByUsername(userDetails.getUsername());

    // 🚀 Step 1: Enforce transaction limits
    if (request.getAmount() > 10000) { 
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                             .body("Transfer limit exceeded! Max transfer: $10,000");
    }

    // 🚀 Step 2: Check sender's account balance
    if (sender.getBalance() < request.getAmount()) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                             .body("Insufficient funds!");
    }

    // 🚀 Step 3: Log transaction for fraud monitoring
    transactionService.logTransaction(sender, request.getAmount());

    // 🚀 Step 4: Process transaction securely
    processTransaction(sender, request);

    return ResponseEntity.ok("Transfer Successful!");
}
```
🔐 **Why This Works?**  
✔ **Prevents high-value fraudulent transfers** by capping transactions.  
✔ **Ensures users have enough balance before transfers.**  
✔ **Logs transactions for fraud detection and auditing.**  
✔ **Blocks unauthorized bulk transfers or account draining.**  

---

### **Case 2: Exploiting Unlimited Discount Codes**
#### **Scenario:**  
An e-commerce API allows users to **apply discount codes** via:  
```http
POST /api/apply-discount
Body: { "code": "FREEDISCOUNT" }
```
If the API does **not track** or **limit usage**, an attacker can:  
- **Abuse the discount** for unlimited free items.  
- **Automate bulk purchases with fraudulent codes.**  

#### **🔴 Vulnerable Code (No Business Logic Check)**
```java
@PostMapping("/apply-discount")
public ResponseEntity<?> applyDiscount(@RequestBody DiscountRequest request) {
    double discount = discountService.getDiscount(request.getCode());
    return ResponseEntity.ok("Discount applied: " + discount + "%");
}
```
🚨 **Danger:**  
- **Attackers can use the same discount code repeatedly.**  
- **No check exists to limit how many times a user can apply it.**  

#### **✅ Fix: Restrict Discount Usage**
```java
@PostMapping("/apply-discount")
public ResponseEntity<?> applyDiscount(@RequestBody DiscountRequest request, 
                                       @AuthenticationPrincipal UserDetails userDetails) {
    if (discountService.isCodeUsed(userDetails.getUsername(), request.getCode())) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                             .body("Discount code already used!");
    }

    double discount = discountService.getDiscount(request.getCode());
    discountService.markCodeAsUsed(userDetails.getUsername(), request.getCode());

    return ResponseEntity.ok("Discount applied: " + discount + "%");
}
```
🚀 **Impact:**  
✔ **Prevents users from exploiting unlimited discounts.**  
✔ **Tracks discount usage per user.**  
✔ **Blocks automated fraud attempts.**  

---

### **Case 3: Unlimited Reward Points Abuse**
#### **Scenario:**  
A company offers a referral system where users **earn points for inviting friends**.  
The API allows users to **refer friends** via:  
```http
POST /api/refer
Body: { "email": "friend@example.com" }
```
If there is **no validation**, attackers can:  
- **Use fake emails to generate unlimited points.**  
- **Automate the process using scripts.**  

#### **🔴 Vulnerable Code (No Referral Validation)**
```java
@PostMapping("/refer")
public ResponseEntity<?> referFriend(@RequestBody ReferralRequest request, 
                                     @AuthenticationPrincipal UserDetails userDetails) {
    referralService.addPoints(userDetails.getUsername(), 100); // ❌ Unlimited points
    return ResponseEntity.ok("Referral successful! 100 points added.");
}
```
🚨 **Danger:**  
- Attackers can **generate fake referrals** to earn unlimited points.  
- No validation **ensures legitimate referrals**.  

#### **✅ Fix: Implement Referral Limits**
```java
@PostMapping("/refer")
public ResponseEntity<?> referFriend(@RequestBody ReferralRequest request, 
                                     @AuthenticationPrincipal UserDetails userDetails) {
    if (referralService.hasExceededReferralLimit(userDetails.getUsername())) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                             .body("Referral limit exceeded!");
    }

    referralService.addPoints(userDetails.getUsername(), 100);
    return ResponseEntity.ok("Referral successful! 100 points added.");
}
```
🚀 **Impact:**  
✔ **Prevents fake referrals.**  
✔ **Ensures referral limits are enforced.**  
✔ **Reduces reward abuse.**  

---

## **🚀 Secure Business Logic Implementation (Step-by-Step)**
| 🔍 Security Issue | 🛑 Impact | ✅ Fix |
|------------------|----------|--------|
| **No transaction limits** | Attackers transfer unlimited money | Enforce transfer caps (`max $10,000`) |
| **No discount usage tracking** | Users exploit discounts repeatedly | Limit each discount to `one-time use` |
| **No referral validation** | Attackers generate unlimited fake referrals | Implement `referral limits` per user |
| **No rate limiting** | Attackers automate abuse | Use `rate limiting` (`Bucket4j`) |

---

## **📌 Conclusion**
✅ **Always enforce business logic constraints** to prevent abuse.  
✅ **Set limits on financial transactions, rewards, and discounts.**  
✅ **Monitor and log transactions for fraud detection.**  
✅ **Prevent bulk API exploitation using rate limiting (`Bucket4j`).**  

---

# **🚨 OWASP API Security Top 10 (2023) - API7:2023 - Server-Side Request Forgery (SSRF)**  

---

## **🔍 What is Server-Side Request Forgery (SSRF)?**  
SSRF occurs when an API allows **unrestricted external URL requests**, enabling attackers to make the server **send requests** to internal or unauthorized services.  

### **🚨 What Can Attackers Do?**
✔ **Access internal systems** not meant to be exposed.  
✔ **Scan private networks** (e.g., AWS metadata service, localhost services).  
✔ **Retrieve sensitive data** (e.g., cloud credentials, database information).  
✔ **Bypass firewalls** and perform lateral movement within an internal network.  

---

## **🕵️‍♂️ Real-World Example of SSRF**
### **Case 1: API Allows Open URL Fetching**
#### **Scenario:**  
An API allows users to **fetch content from a given URL**, like:  
```http
POST /api/fetch-url
Body: { "url": "https://example.com" }
```
If the API **does not restrict URLs**, attackers can:  
- **Access internal services:** `http://localhost:8080/admin`  
- **Extract AWS credentials:** `http://169.254.169.254/latest/meta-data/iam/security-credentials/`  
- **Perform internal network scans:** `http://192.168.1.1`  

#### **🔴 Vulnerable Code (No URL Validation)**
```java
@PostMapping("/fetch-url")
public ResponseEntity<?> fetchContent(@RequestBody UrlRequest request) throws IOException {
    URL url = new URL(request.getUrl());
    BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
    String content = reader.lines().collect(Collectors.joining());
    return ResponseEntity.ok(content); // ❌ Returns content without restriction
}
```
🚨 **Danger:**  
- Any **external or internal** URL can be accessed.  
- **Attackers can retrieve private data from internal APIs.**  
- **Firewall rules may be bypassed**, allowing access to private servers.  

---

## **✅ Secure Solution: Validate URL Inputs**
✔ **Allow only trusted domains** (`whitelisting`).  
✔ **Block requests to internal/private IPs.**  
✔ **Use a DNS allowlist to prevent hostname manipulation.**  
✔ **Restrict response types (e.g., only allow JSON responses).**  

```java
public boolean isValidURL(String url) {
    return url.startsWith("https://trusted.com/");
}
```
🚀 **Impact:**  
✔ Prevents API from fetching data from **untrusted sources**.  
✔ Blocks **requests to internal networks** (`localhost`, `127.0.0.1`, `169.254.169.254`).  
✔ Reduces **risk of data exposure and internal service attacks**.  

---

### **🔧 Improved Secure Implementation**
```java
@PostMapping("/fetch-url")
public ResponseEntity<?> fetchContent(@RequestBody UrlRequest request) {
    String url = request.getUrl();

    // 🚀 Step 1: Validate URL against a trusted allowlist
    if (!isValidURL(url)) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                             .body("Invalid URL: Only trusted.com is allowed.");
    }

    // 🚀 Step 2: Fetch content securely (Optional: Restrict response types)
    try {
        URL validUrl = new URL(url);
        BufferedReader reader = new BufferedReader(new InputStreamReader(validUrl.openStream()));
        String content = reader.lines().collect(Collectors.joining());

        return ResponseEntity.ok(content);
    } catch (IOException e) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                             .body("Error fetching content.");
    }
}
```
🔐 **Why This Works?**  
✔ **Only allows URLs from `trusted.com`**.  
✔ **Blocks attempts to request internal services**.  
✔ **Handles errors securely (prevents stack trace exposure).**  
✔ **Prevents misuse by restricting URL inputs**.  

---

## **🛡️ Advanced SSRF Prevention Techniques**
### **Case 2: Attackers Manipulate DNS Resolution**
#### **Scenario:**  
Attackers can **bypass simple URL checks** using **redirects** or **manipulating DNS resolution**.  

##### **🔴 Attack:**
```http
POST /api/fetch-url
Body: { "url": "https://trusted.com.evil.com" }
```
✔ This URL **looks** like `trusted.com`, but actually points to `evil.com`.  
✔ The server processes it as a **trusted URL**, but it’s **malicious**.  

#### **✅ Fix: Strict URL Validation**
```java
public boolean isValidURL(String url) {
    try {
        URI uri = new URI(url);
        String host = uri.getHost();
        return host != null && host.equals("trusted.com");
    } catch (URISyntaxException e) {
        return false;
    }
}
```
🚀 **Impact:**  
✔ **Blocks lookalike domains (`trusted.com.evil.com`).**  
✔ **Ensures only exact matches for `trusted.com` are allowed.**  
✔ **Prevents hostname tricks that bypass basic validation.**  

---

### **Case 3: Preventing Internal Network Access**
#### **Scenario:**  
Attackers attempt to **scan internal networks** by sending requests to:  
```http
http://localhost:8080/admin
http://192.168.1.100/internal-api
http://10.0.0.1/private
http://169.254.169.254/latest/meta-data/
```
#### **✅ Fix: Block Private & Internal IP Ranges**
```java
public boolean isValidURL(String url) {
    try {
        URI uri = new URI(url);
        InetAddress address = InetAddress.getByName(uri.getHost());

        // 🚀 Block private/internal IPs
        if (address.isLoopbackAddress() || address.isSiteLocalAddress() ||
            address.getHostAddress().startsWith("169.254.")) {
            return false;
        }

        // 🚀 Allow only trusted domains
        return uri.getHost().equals("trusted.com");
    } catch (Exception e) {
        return false;
    }
}
```
🚀 **Impact:**  
✔ **Blocks requests to `localhost`, `127.0.0.1`, private/internal IPs.**  
✔ **Prevents API from being used as an internal network scanner.**  
✔ **Stops AWS metadata service attacks.**  

---

## **🚀 Secure API Design Against SSRF (Step-by-Step)**
| 🔍 Security Issue | 🛑 Impact | ✅ Fix |
|------------------|----------|--------|
| **No URL validation** | API can request internal/private services | Enforce URL allowlists (`trusted.com`) |
| **DNS hostname tricks** | Attackers bypass checks using fake subdomains | Strict host validation (`trusted.com` only) |
| **Private IP access** | Attackers scan internal networks | Block private/internal IPs (`localhost`, `10.0.0.0/8`) |
| **Open redirects** | Attackers redirect users to malicious sites | Restrict redirects to trusted domains |
| **No logging or monitoring** | SSRF attacks go undetected | Log all outbound API requests |

---

## **📌 Conclusion**
✅ **Always validate and sanitize URLs before making requests.**  
✅ **Restrict API requests to trusted domains using an allowlist.**  
✅ **Block private/internal IP access to prevent network scans.**  
✅ **Log and monitor outbound API calls to detect SSRF attempts.**  

---

# **🚨 OWASP API Security Top 10 (2023) - API8:2023 - Security Misconfiguration**  

## **🔍 What is Security Misconfiguration?**  
Security misconfiguration happens when APIs are **deployed with insecure settings**, such as:  
✔ **Default credentials** (e.g., admin/admin, root/root).  
✔ **Exposed debugging information** (stack traces, API keys in responses).  
✔ **Lack of security headers** (e.g., Content Security Policy, CORS restrictions).  
✔ **Unprotected admin panels and endpoints**.  
✔ **Unpatched or outdated components** (e.g., old libraries with known vulnerabilities).  

---

## **🚨 Why is Security Misconfiguration Dangerous?**  
❌ Attackers **easily exploit weak settings** to gain unauthorized access.  
❌ **Debug endpoints** expose sensitive information.  
❌ **Missing security headers** allow data leaks and XSS attacks.  
❌ **Default credentials** make brute-force attacks easy.  

---

## **🕵️‍♂️ Real-World Example of Security Misconfiguration**  

### **Case 1: Default Admin Credentials**  
#### **Scenario:**  
A company deploys an API with a default admin account:  
```
Username: admin  
Password: admin  
```
An attacker **logs in using default credentials** and gains full control.  

#### **🚨 Vulnerable Code (Hardcoded Default Credentials)**
```java
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest request) {
    if (request.getUsername().equals("admin") && request.getPassword().equals("admin")) { // ❌ Hardcoded password
        return ResponseEntity.ok("Logged in as Admin!");
    }
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
}
```
🚨 **Danger:**  
- Attackers **try default credentials and gain access**.  
- Many developers forget to **change default passwords** before deployment.  

#### **✅ Secure Code: Enforce Strong Authentication**
```java
@Autowired
private PasswordEncoder passwordEncoder;

@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest request) {
    User user = userRepository.findByUsername(request.getUsername());
    
    if (user != null && passwordEncoder.matches(request.getPassword(), user.getPassword())) { // ✅ Secure password check
        return ResponseEntity.ok("Login successful!");
    }
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
}
```
✔ **Removes hardcoded credentials.**  
✔ **Uses password hashing (BCrypt, Argon2).**  
✔ **Prevents attackers from logging in with default passwords.**  

---

### **Case 2: Missing Security Headers**  
#### **Scenario:**  
An API does not set **Content Security Policy (CSP)** or other security headers.  
Attackers **inject malicious JavaScript**, stealing user data.  

#### **🚨 Vulnerable Code (No Security Headers)**
```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
        .formLogin(withDefaults()); // ❌ No security headers
    return http.build();
}
```
🚨 **Danger:**  
- **No CSP** → Attackers inject malicious scripts (**XSS attack**).  
- **No CORS restriction** → Any site can access the API.  
- **No Frame Options** → Clickjacking attacks are possible.  

#### **✅ Secure Code: Add Security Headers**
```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .headers(headers -> headers
            .contentSecurityPolicy("default-src 'self'") // ✅ Blocks external scripts
            .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny) // ✅ Prevents clickjacking
            .xssProtection(xss -> xss.policy(XssProtectionPolicy.BLOCK)) // ✅ Blocks reflected XSS
        )
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
        .formLogin(withDefaults());
    return http.build();
}
```
🔐 **Why This Works?**  
✔ **Prevents XSS and clickjacking attacks.**  
✔ **Restricts API access to trusted sources.**  
✔ **Reduces attack surface by enforcing security headers.**  

---

### **Case 3: Exposed Debugging Information**  
#### **Scenario:**  
A developer forgets to disable **stack traces in production**, exposing sensitive details.  

#### **🚨 Vulnerable Code (Leaking Debug Info)**
```java
@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleException(Exception e) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage()); // ❌ Leaks stack trace
    }
}
```
🚨 **Danger:**  
- Attackers see **detailed error messages**.  
- Exposes **API keys, database credentials, and internal paths**.  

#### **✅ Secure Code: Hide Detailed Error Messages**
```java
@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleException(Exception e) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("An unexpected error occurred. Please contact support."); // ✅ Hides internal errors
    }
}
```
✔ **Prevents attackers from learning API internals.**  
✔ **Protects against information leakage.**  

---

## **🚀 Best Practices for Preventing Security Misconfigurations**  
| 🔍 Security Issue | 🛑 Impact | ✅ Fix |
|------------------|----------|--------|
| **Default credentials** | Attackers log in with admin/admin | **Use strong, unique passwords** |
| **Missing security headers** | XSS, Clickjacking, Data leaks | **Enforce CSP, CORS, XSS Protection** |
| **Debugging enabled** | Leaks sensitive data | **Disable stack traces in production** |
| **Unpatched dependencies** | Vulnerabilities get exploited | **Regularly update libraries & APIs** |
| **Open admin panels** | Attackers gain control | **Restrict admin access with authentication** |

---

## **📌 Conclusion**
✅ **Security misconfigurations are one of the most common API vulnerabilities.**  
✅ Always **remove default credentials** and **enforce strong authentication**.  
✅ Use **security headers (CSP, XSS protection, CORS restrictions)**.  
✅ **Hide error messages** to prevent attackers from gathering information.  
✅ **Regularly update libraries** to avoid vulnerabilities.  

---

# **🚨 OWASP API Security Top 10 (2023) - API9:2023 - Improper Inventory Management**  

## **🔍 What is Improper Inventory Management?**  
Improper Inventory Management occurs when organizations **fail to properly track, secure, or deprecate APIs**. This results in:  
✔ **Exposing outdated or vulnerable API versions** (e.g., `/api/v1/` still accessible while `/api/v3/` is in use).  
✔ **Leaving test, debug, or internal APIs open to attackers**.  
✔ **Lack of proper documentation**, leading to security gaps.  
✔ **Shadow APIs** (undocumented or forgotten APIs still accessible).  

---

## **🚨 Why is Improper Inventory Management Dangerous?**  
❌ Attackers **find old APIs with known vulnerabilities**.  
❌ **Unmaintained endpoints** lead to security breaches.  
❌ **Test APIs expose sensitive data** (e.g., `/test/payment`).  
❌ **Shadow APIs** allow unauthorized access.  

---

## **🕵️‍♂️ Real-World Example of Improper Inventory Management**  

### **Case 1: Exposing Deprecated APIs**  
#### **Scenario:**  
A company upgrades its API from `/api/v1` to `/api/v2`, but **forgets to disable** the old version.  
Attackers use `/api/v1/login` with **known exploits** to gain access.  

#### **🚨 Vulnerable Code (Deprecated API Still Accessible)**
```java
@RestController
@RequestMapping("/api/v1") // ❌ Old API version still available
public class DeprecatedUserController {
    
    @GetMapping("/users")
    public List<User> getAllUsers() {
        return userRepository.findAll(); // ❌ Exposes all user data
    }
}
```
🚨 **Danger:**  
- Attackers **target old endpoints** with known vulnerabilities.  
- Old versions **don’t have security patches**.  
- API clients **still use outdated APIs**, making migration harder.  

#### **✅ Secure Code: Proper API Versioning**
```java
@RestController
@RequestMapping("/api/v2") // ✅ New API version
public class UserController {
    
    @GetMapping("/users")
    public List<UserDTO> getAllUsers() {
        return userService.getSafeUserList(); // ✅ Uses DTO to avoid exposing sensitive data
    }
}
```
✔ **Old versions are removed after migration.**  
✔ **Data is secured using DTOs** to prevent overexposure.  

#### **Best Practice: Deprecate Old APIs Using Annotations**
```java
@Deprecated // ✅ Marks API as deprecated
@RestController
@RequestMapping("/api/v1")
public class DeprecatedUserController {
    
    @GetMapping("/users")
    public ResponseEntity<String> deprecatedEndpoint() {
        return ResponseEntity.status(HttpStatus.GONE).body("This API version is deprecated. Please use /api/v2.");
    }
}
```
✔ **Redirects users to newer APIs.**  
✔ **Prevents accidental usage of outdated versions.**  

---

### **Case 2: Exposed Test APIs**  
#### **Scenario:**  
A developer forgets to **remove test endpoints** from production.  
Hackers access `/test/payment` to manipulate transactions.  

#### **🚨 Vulnerable Code (Test API Left Open)**
```java
@RestController
@RequestMapping("/test")
public class TestPaymentController {

    @GetMapping("/payment")
    public String testPayment() {
        return "Payment test successful!"; // ❌ Exposed test API
    }
}
```
🚨 **Danger:**  
- Test APIs **bypass authentication** for testing.  
- Attackers **manipulate test endpoints** to abuse transactions.  

#### **✅ Secure Code: Remove Test Endpoints Before Deployment**
```java
// ❌ Do not include test endpoints in production
```
✔ **Test APIs should only be available in development environments.**  
✔ **Use feature flags** to disable test endpoints in production.  

---

### **Case 3: Shadow APIs (Undocumented Endpoints Still Active)**  
#### **Scenario:**  
A company builds an internal API `/internal/stats` for monitoring.  
Developers forget about it, leaving it **exposed on the internet**.  

#### **🚨 Vulnerable Code (Shadow API Left Open)**
```java
@RestController
@RequestMapping("/internal")
public class InternalController {

    @GetMapping("/stats")
    public ServerStats getStats() {
        return monitoringService.getServerStats(); // ❌ Exposes internal data
    }
}
```
🚨 **Danger:**  
- Attackers **find undocumented APIs using fuzzing tools**.  
- Shadow APIs **leak sensitive system details**.  

#### **✅ Secure Code: Restrict Internal APIs**
```java
@RestController
@RequestMapping("/internal")
@PreAuthorize("hasRole('ADMIN')") // ✅ Restricts access
public class SecureInternalController {

    @GetMapping("/stats")
    public ServerStats getStats() {
        return monitoringService.getServerStats();
    }
}
```
✔ **Only authorized users can access sensitive APIs.**  
✔ **Prevents unauthorized access to internal data.**  

---

## **🚀 Best Practices for Preventing Improper Inventory Management**  
| 🔍 Security Issue | 🛑 Impact | ✅ Fix |
|------------------|----------|--------|
| **Exposed old API versions** | Attackers exploit known vulnerabilities | **Remove deprecated APIs** |
| **Test endpoints left in production** | Bypass security measures | **Disable test APIs before deployment** |
| **Shadow APIs (Undocumented endpoints)** | Hackers find hidden APIs | **Document & secure all APIs** |
| **Lack of API versioning** | Clients use outdated, vulnerable APIs | **Implement API versioning** |

---

## **📌 Conclusion**  
✅ **Improper Inventory Management leaves APIs vulnerable.**  
✅ **Always remove old, test, and undocumented APIs.**  
✅ **Use proper API versioning (`/api/v1`, `/api/v2`) and deprecate outdated versions.**  
✅ **Restrict access to internal and admin APIs.**  
✅ **Regularly scan for shadow APIs to ensure they are secure.**  

---

# **🚨 OWASP API Security Top 10 (2023) - API10:2023 - Unsafe Consumption of APIs**  

## **🔍 What is Unsafe Consumption of APIs?**  
Unsafe consumption of APIs occurs when a system **blindly trusts external APIs** without validating responses.  
Attackers can exploit this to:  
✔ Inject **malicious scripts (XSS attacks)**.  
✔ Manipulate **API responses to cause logic flaws**.  
✔ Trick the system into executing **unexpected or harmful actions**.  
✔ **Expose sensitive data** due to poor input sanitization.  

---

## **🚨 Why is Unsafe Consumption of APIs Dangerous?**  
❌ External APIs **may return manipulated data**, leading to XSS or SQL injection.  
❌ **No validation = Security Risks!** An API could return unexpected data that the system executes blindly.  
❌ Attackers **intercept API responses**, modifying them for privilege escalation.  
❌ **Broken business logic** if the API is exploited to return unauthorized data.  

---

## **🕵️‍♂️ Real-World Example of Unsafe API Consumption**  

### **Case 1: Cross-Site Scripting (XSS) via API Response**  
#### **Scenario:**  
Your application fetches **user profile data** from an external API and displays it on the UI.  
The API **is compromised**, and instead of valid user data, it returns:  
```html
<script>alert('Hacked!');</script>
```
If your system **does not validate** the response before displaying it, **XSS is executed**, compromising user security.

#### **🚨 Vulnerable Code (No Validation of External API Response)**
```java
public String getUserProfile(String userId) {
    String externalResponse = externalApiService.fetchUserData(userId); // ❌ Directly using external API response
    return "<h1>" + externalResponse + "</h1>"; // ❌ Potential XSS risk
}
```
🚨 **Danger:**  
- The API could return **malicious JavaScript** (`<script>alert("Hacked!");</script>`)  
- If this response is displayed **without sanitization**, users can be attacked.  
- **Stealing user cookies, session hijacking, defacing websites, phishing attacks.**  

#### **✅ Secure Code: Validate API Responses Before Displaying**
```java
public String getUserProfile(String userId) {
    String externalResponse = externalApiService.fetchUserData(userId);
    
    if (externalResponse.contains("<script>")) { // ✅ Blocks XSS injection
        throw new SecurityException("XSS Detected!");
    }
    
    return StringEscapeUtils.escapeHtml4(externalResponse); // ✅ Escapes HTML content
}
```
✔ **Prevents script execution by blocking `<script>` tags.**  
✔ **Uses `StringEscapeUtils.escapeHtml4()` to encode HTML characters safely.**  

---

### **Case 2: API Response Manipulation for Privilege Escalation**  
#### **Scenario:**  
Your application relies on a **third-party authentication API** to verify user roles.  
An attacker **manipulates the response** to gain admin access.

#### **🚨 Vulnerable Code (Blindly Trusting API Response)**
```java
public boolean isAdmin(String userId) {
    String role = externalApiService.getUserRole(userId); // ❌ No validation
    return role.equals("ADMIN"); // ❌ If attacker modifies response, they gain admin access
}
```
🚨 **Danger:**  
- If an attacker **modifies the API response**, they can escalate privileges.  
- The API could be **compromised** and return `ADMIN` even for normal users.  
- **Serious security risks** if actions are based on unverified API responses.  

#### **✅ Secure Code: Verify API Responses**
```java
public boolean isAdmin(String userId) {
    String role = externalApiService.getUserRole(userId);
    
    if (!role.matches("USER|MODERATOR|ADMIN")) { // ✅ Validate expected roles
        throw new SecurityException("Invalid Role Detected!");
    }
    
    return role.equals("ADMIN");
}
```
✔ **Ensures only expected roles (`USER`, `MODERATOR`, `ADMIN`) are valid.**  
✔ **Rejects any manipulated or unauthorized response.**  

---

### **Case 3: SQL Injection via External API Response**  
#### **Scenario:**  
Your system **fetches user details** from an external API and directly inserts the response into a database.  
The API is **compromised** and returns:  
```sql
'; DROP TABLE users; --
```
If your system **does not sanitize input**, it will execute **SQL injection**, deleting the entire user table!

#### **🚨 Vulnerable Code (Inserting API Response Directly into DB)**
```java
public void storeUserData(String userId) {
    String userData = externalApiService.getUserData(userId); // ❌ No validation
    String query = "INSERT INTO users (data) VALUES ('" + userData + "')"; // ❌ Vulnerable to SQL injection
    jdbcTemplate.execute(query);
}
```
🚨 **Danger:**  
- If the API returns **malicious SQL**, it can **delete or manipulate database records**.  
- Attackers can **steal or corrupt** user data.  
- **Serious database security risks**.  

#### **✅ Secure Code: Use Parameterized Queries**
```java
public void storeUserData(String userId) {
    String userData = externalApiService.getUserData(userId);
    
    if (userData.contains("'") || userData.toLowerCase().contains("drop table")) { // ✅ Detects SQL injection
        throw new SecurityException("SQL Injection Detected!");
    }
    
    String query = "INSERT INTO users (data) VALUES (?)"; // ✅ Parameterized Query
    jdbcTemplate.update(query, userData);
}
```
✔ **Uses parameterized queries to prevent SQL injection.**  
✔ **Rejects inputs containing dangerous SQL patterns.**  

---

## **🚀 Best Practices for Securing API Consumption**  
| 🔍 Security Issue | 🛑 Impact | ✅ Fix |
|------------------|----------|--------|
| **Blindly trusting API responses** | XSS, SQL Injection, business logic abuse | **Validate all API responses** |
| **No input sanitization** | Attackers inject malicious code | **Escape and sanitize inputs** |
| **No role validation in API responses** | Privilege escalation | **Whitelist expected values** |
| **Storing API data without checks** | Database corruption | **Use parameterized queries** |

---

## **📌 Conclusion**  
✅ **External APIs can be compromised or return malicious data.**  
✅ **Always validate and sanitize API responses before processing.**  
✅ **Never trust data coming from third-party sources without verification.**  
✅ **Use secure coding practices to prevent XSS, SQL injection, and privilege escalation.**  
✅ **Regularly audit API integrations for security weaknesses.**  

---
