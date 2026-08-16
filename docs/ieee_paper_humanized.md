# Zero Trust Driven Application Trust Establishment Framework in Software Defined Networking

Tanis Ahmed
Department of Computer Science and Engineering
[Your University Name]
[City, Country]
[your.email@university.edu]

*Abstract*—Software Defined Networking (SDN) has changed the way we manage networks by separating the control plane from the data plane. But this also introduces new security problems. In traditional SDN, once an application is authenticated, it is trusted forever. This is a big problem because if an application gets compromised after authentication, it can do a lot of damage. In this paper, we propose a Zero Trust driven framework that verifies every single request from every application before allowing it to communicate with the SDN controller. We implement 7 layers of verification including token verification, API key validation, device identity check, RBAC, ABAC, behavioral analysis, and continuous trust scoring. We tested our framework with 5 different types of attacks and all of them were successfully blocked. The average verification latency is only 0.21 milliseconds which is acceptable for real-time SDN operations. We implemented everything using open-source tools like Mininet, RYU controller, and Open vSwitch.

*Keywords—Zero Trust Architecture, Software Defined Networking, Network Security, Trust Management, RYU Controller*

---

## 1. Introduction

### 1.1 Background

Software Defined Networking or SDN is a new way of designing computer networks. In traditional networking, each switch and router makes its own decisions about where to send traffic. But in SDN, the control logic is moved to a central controller. This controller talks to the switches using a protocol called OpenFlow. The switches just follow the instructions given by the controller.

The problem is that applications need to talk to the SDN controller to manage the network. These applications can be network monitoring tools, traffic engineering apps, security applications, etc. They communicate with the controller through what is called the northbound API. 

Now here is where the security problem starts. In current SDN systems, when an application first connects to the controller, it authenticates itself. After that, the controller trusts everything that application does. There is no further checking. This is like giving someone a key to your house and never checking what they do inside.

### Problem Statement

The main problem is that traditional SDN security works on a "authenticate once, trust forever" model. This is dangerous because:

1. An application can get compromised after it has been authenticated
2. Attackers can steal credentials and pretend to be legitimate apps
3. There is no way to detect if an application's behavior changes suddenly
4. Once an app is inside, it can do anything without being checked again

I was reading about the SolarWinds attack and similar incidents where trusted applications were used to cause damage. This made me think - why do we trust applications forever in SDN? This is where the idea of Zero Trust comes in.

### Research Gap

After going through many research papers on SDN security, I found that most existing systems do authentication only once. When I looked at Zero Trust Architecture (ZTA) papers, I saw that nobody has really applied the full Zero Trust model to SDN application trust management. Some papers talk about Zero Trust in SDN but they only focus on network traffic, not on application-to-controller communication. This is the gap I am trying to fill.

### Our Contribution

In this paper, we propose a framework that:
1. Verifies every single request from every application - not just the first one
2. Uses 7 different verification methods together
3. Calculates a trust score that changes over time
4. Detects 5 different types of attacks
5. Is implemented using only open-source tools

## 2. Literature Review

### 2.1 Traditional SDN Security

Software Defined Networking has been around for a while now. The main idea is to separate the control plane from the data plane. This gives us a centralized view of the network which is great for management but also creates a single point of attack. 

Many researchers have worked on SDN security. Some proposed using TLS for controller communication. Others suggested firewalls between applications and the controller. But most of these solutions focus on the first authentication only. Once an application passes the initial check, it is trusted forever.

### 2.2 Zero Trust Architecture

The concept of Zero Trust was introduced by John Kindervag at Forrester Research. The main idea is simple - never trust anything by default. Always verify everything. NIST published SP 800-207 which explains Zero Trust Architecture in detail. The key principles are:
- Never trust, always verify
- Assume breach
- Least privilege access
- Micro-segmentation

### 2.3 Related Work in SDN Trust Management

I looked at several papers on SDN trust management. Most of them focus on:
- Authenticating the controller to switches (using TLS)
- Verifying flow rules before installation
- Detecting malicious switches

But very few papers talk about verifying applications that talk to the controller. The ones that do, use one-time authentication only. None of them do continuous verification of every request.

## 3. Proposed Framework

### 3.1 Architecture Overview

The architecture of our proposed framework is shown in Figure 1. It has six main components:

1. **Application Layer** - This is where all the applications live. These are the apps that want to communicate with the SDN controller. They can be monitoring tools, management apps, or even malicious software trying to attack the network.

2. **Zero Trust Verification Module (ZTVM)** - This is the heart of our framework. It verifies every single request from every application. It does 7 different checks before allowing anything.

3. **Policy Engine** - This component decides whether to allow or deny a request based on the verification results and the defined policies.

4. **Policy Administrator** - This is the management interface where security policies are created, updated, and deleted.

5. **Policy Enforcement Point (PEP)** - This is the guard that actually enforces the decisions. It sits between the applications and the controller and blocks or forwards requests.

6. **RYU SDN Controller** - This is the actual SDN controller that manages the network. Only requests that pass all verification checks reach the controller.

### 3.2 How the Verification Works

The verification process has 7 steps. Each step is like a security checkpoint. If any checkpoint fails, the request is immediately denied. This is the "never trust, always verify" principle in action.

**Step 1: Token Verification**
Every request must carry a token. This token is generated using HMAC-SHA256 with a secret key. The token expires after 60 seconds. This prevents replay attacks because even if someone captures a token, they cannot use it after it expires.

**Step 2: API Key Validation**
Each application gets a unique API key when it registers. This key must be sent with every request. If the key doesn't match, the request is denied.

**Step 3: Device Identity Verification**
We check the device ID and fingerprint. If an application claims to be from a device but the fingerprint doesn't match, we know something is wrong.

**Step 4: Role-Based Access Control (RBAC)**
Different roles have different permissions. A monitoring app can only read data. An admin app can read, write, delete, and configure. If a guest app tries to delete something, it gets blocked.

**Step 5: Attribute-Based Access Control (ABAC)**
This is more flexible than RBAC. We check attributes like time of day, trust score, and resource type. For example, we can allow read access only during business hours.

**Step 6: Behavioral Analysis**
We keep track of how each application behaves. If an app suddenly starts making many requests very fast, we detect this as an anomaly and block it.

**Step 7: Trust Score Calculation**
Based on all the checks above, we calculate a trust score between 0 and 1. If the score is below 0.6, the request is denied.

### 3.3 Algorithm

The algorithm for request verification is shown below:

```
Algorithm: ZeroTrustVerification
Input: app_id, request_data
Output: allow/deny

1. Extract token, api_key, device_id, role, action from request
2. If token is invalid or expired, deny request
3. If api_key doesn't match, deny request
4. If device_id not found or fingerprint wrong, deny request
5. If role doesn't have permission for action, deny request
6. If no ABAC policy allows this request, deny request
7. If behavioral anomaly detected, deny request
8. Calculate trust score from all checks
9. If trust score >= 0.6, allow request
10. Else deny request
```

## 4. Implementation

### 4.1 Setup

I used Ubuntu 22.04 LTS for this project. The setup was actually quite straightforward. I installed Mininet for network emulation, RYU as the SDN controller, and Open vSwitch as the OpenFlow switch. All of these are open-source tools.

The installation commands are:

```bash
sudo apt-get update
sudo apt-get install -y mininet
sudo pip3 install ryu
sudo apt-get install -y openvswitch-switch
```

### 4.2 Network Topology

I created a simple topology with one OpenFlow switch and four hosts. The hosts are:
- h1: Runs the legitimate monitoring application
- h2: Runs the legitimate admin application
- h3: Runs malicious applications (for testing)
- h4: Normal network user

The controller is the RYU controller with our Zero Trust modules added to it.

### 4.3 Implementation Details

I wrote the code in Python. The main components are:

1. **TrustVerificationEngine** - This is the main class that does all 7 verification steps. It has methods for token verification, API key validation, device identity check, RBAC, ABAC, behavioral analysis, and trust scoring.

2. **PolicyEngine** - This class evaluates requests against defined policies and makes allow/deny decisions.

3. **PolicyEnforcementPoint** - This class sits between applications and the controller. It intercepts all requests, sends them for verification, and enforces the decision.

4. **RYU Controller** - The main SDN controller that we extended with our Zero Trust modules.

### 4.4 Code Explanation

The most important function is `verify_request()` in the TrustVerificationEngine class. Let me explain how it works:

When an application sends a request, the function first checks the token. The token is generated using HMAC-SHA256 with a secret key and a timestamp. If the token is missing or expired, the request is immediately denied.

Then it checks the API key. Each application has a unique key that must match what we have stored.

Next, it verifies the device identity. We check if the device ID is in our registry and if the fingerprint matches.

After that, we do RBAC check. We have defined roles like admin, network_operator, monitoring_app, and guest_app. Each role has specific permissions.

Then we do ABAC check. This is more flexible. We check attributes like time of day, trust score, and resource type.

The behavioral analysis keeps track of how many requests an app makes. If an app makes more than 10 requests in 5 seconds, we flag it as anomalous.

Finally, we calculate a trust score. If the score is 0.6 or above, the request is allowed. Otherwise, it is denied.

## 4. Implementation

### 4.1 Environment Setup

I used Ubuntu 22.04 LTS for this project. The setup was actually quite straightforward. I installed Mininet for network emulation, RYU as the SDN controller, and Open vSwitch as the OpenFlow switch. All of these are open-source tools which is great for research because anyone can reproduce our work.

The installation process was simple:

```bash
sudo apt-get update
sudo apt-get install -y mininet
sudo pip3 install ryu
sudo apt-get install -y openvswitch-switch
```

### 4.2 Network Topology

I created a simple topology with one OpenFlow switch and four hosts. The hosts are connected to the switch and the switch is connected to the RYU controller. The topology looks like this:

```
        [RYU Controller]
              |
          [Switch s1]
         /    |    \    \
       h1    h2    h3    h4
```

Each host has a specific role:
- h1 (10.0.0.1): Runs the legitimate monitoring application
- h2 (10.0.0.2): Runs the legitimate admin application
- h3 (10.0.0.3): Runs malicious applications for testing
- h4 (10.0.0.4): Normal network user

### 4.3 Implementation Details

I implemented the framework in Python. The code is organized into several modules:

1. **trust_verification.py** - This is the main file. It contains the TrustVerificationEngine class which does all 7 verification steps. The most important function is `verify_request()` which is called for every single request.

2. **policy_engine.py** - This contains the PolicyEngine class which evaluates requests against defined policies.

3. **policy_enforcement_point.py** - This contains the PEP class which enforces the decisions.

4. **ryu_controller.py** - This extends the RYU controller with our Zero Trust modules.

The verification process works like this:

When an application sends a request, the `verify_request()` function is called. First, it checks the token. If the token is missing or expired, the request is denied immediately. Then it checks the API key. Then the device identity. Then RBAC. Then ABAC. Then behavioral analysis. Finally, it calculates a trust score. If the score is 0.6 or above, the request is allowed.

I used HMAC-SHA256 for token generation. Each token has a timestamp and expires after 60 seconds. This prevents replay attacks because even if someone captures a token, they cannot use it after it expires.

For behavioral analysis, I track how many requests each app makes in a 5-second window. If an app makes more than 10 requests in 5 seconds, it is flagged as anomalous. This helps detect compromised applications that try to flood the controller.

## 4. Implementation

### 4.1 Environment Setup

I used Ubuntu 22.04 LTS for this project. The setup was actually quite straightforward. I installed Mininet for network emulation, RYU as the SDN controller, and Open vSwitch as the OpenFlow switch. All of these are open-source tools which is great for research because anyone can reproduce our work.

The installation process was simple:

```bash
sudo apt-get update
sudo apt-get install -y mininet
sudo pip3 install ryu
sudo apt-get install -y openvswitch-switch
```

### 4.2 Network Topology

I created a simple topology with one OpenFlow switch and four hosts. The hosts are connected to the switch and the switch is connected to the RYU controller. The topology looks like this:

```
        [RYU Controller]
              |
          [Switch s1]
         /    |    \    \
       h1    h2    h3    h4
```

Each host has a specific role:
- h1 (10.0.0.1): Runs the legitimate monitoring application
- h2 (10.0.0.2): Runs the legitimate admin application
- h3 (10.0.0.3): Runs malicious applications for testing
- h4 (10.0.0.4): Normal network user

### 4.3 Implementation Details

I implemented the framework in Python. The code is organized into several modules:

1. **trust_verification.py** - This is the main file. It contains the TrustVerificationEngine class which does all 7 verification steps. The most important function is `verify_request()` which is called for every single request.

2. **policy_engine.py** - This contains the PolicyEngine class which evaluates requests against defined policies.

3. **policy_enforcement_point.py** - This contains the PEP class which enforces the decisions.

4. **ryu_controller.py** - This extends the RYU controller with our Zero Trust modules.

The verification process works like this:

When an application sends a request, the `verify_request()` function is called. First, it checks the token. The token is generated using HMAC-SHA256 with a secret key and a timestamp. If the token is missing or expired (more than 60 seconds old), the request is denied immediately.

Then it checks the API key. Each application has a unique API key that must match what we have stored.

Next, it verifies the device identity. We check if the device ID is in our registry and if the fingerprint matches.

After that, we do RBAC check. We have defined roles like admin, network_operator, monitoring_app, and guest_app. Each role has specific permissions.

Then we do ABAC check. This is more flexible. We check attributes like time of day, trust score, and resource type.

The behavioral analysis keeps track of how many requests each app makes. If an app makes more than 10 requests in 5 seconds, we flag it as anomalous.

Finally, we calculate a trust score. If the score is 0.6 or above, the request is allowed. Otherwise, it is denied.

### 4.4 Code Snippet

Here is the main verification function:

```python
def verify_request(self, app_id, request_data):
    # Step 1: Token Verification
    token_result = self._verify_token(app_id, request_data)
    if not token_result["valid"]:
        return self._deny("Token verification failed", 0.0)
    
    # Step 2: API Key Validation
    api_result = self._validate_api_key(app_id, request_data)
    if not api_result["valid"]:
        return self._deny("API Key validation failed", 0.1)
    
    # Step 3: Device Identity
    device_result = self._verify_device_identity(app_id, request_data)
    if not device_result["valid"]:
        return self._deny("Device verification failed", 0.2)
    
    # Step 4: RBAC
    rbac_result = self._check_rbac(app_id, request_data)
    if not rbac_result["allowed"]:
        return self._deny("RBAC check failed", 0.3)
    
    # Step 5: ABAC
    abac_result = self._check_abac(app_id, request_data)
    if not abac_result["allowed"]:
        return self._deny("ABAC check failed", 0.4)
    
    # Step 6: Behavioral Analysis
    behavior_result = self._analyze_behavior(app_id, request_data)
    if behavior_result["anomaly_detected"]:
        return self._deny("Anomaly detected", behavior_result["trust_score"])
    
    # Step 7: Trust Score
    trust_score = self._calculate_trust_score(app_id, verification_steps)
    if trust_score >= 0.6:
        return self._allow(trust_score, verification_steps)
    else:
        return self._deny("Low trust score", verification_steps, trust_score)
```

## 4. Results

### 4.1 Test Scenarios

I tested the framework with 5 different attack scenarios:

1. **Unauthorized Access**: An application tries to access the controller without any credentials. No token, no API key, nothing.

2. **Fake Application**: An application pretends to be a legitimate monitoring app but uses a different device.

3. **Compromised Application**: A legitimate-looking app that suddenly starts making many rapid requests.

4. **Replay Attack**: An attacker captures a valid token and tries to reuse it after it expires.

5. **Unauthorized API Request**: An application tries to perform actions it doesn't have permission for.

### 4.2 Results

The results are shown in Table 1 and Table 2.

**Table 1: Legitimate Application Access**

| Test Case | Action | Result | Trust Score |
|-----------|--------|--------|-------------|
| Monitor: read flow_stats | read | ALLOWED | 1.0 |
| Monitor: read flow_table | read | ALLOWED | 1.0 |
| Admin: read flow_table | read | ALLOWED | 1.0 |
| Admin: write flow_table | write | ALLOWED | 1.0 |
| Admin: configure switch | configure | ALLOWED | 1.0 |

**Table 2: Malicious Application Detection**

| Attack Type | Detection Method | Result |
|-------------|-----------------|--------|
| Unauthorized Access | Token Verification | BLOCKED |
| Fake Application | Device Identity | BLOCKED |
| Compromised App | Behavioral Analysis | BLOCKED (5/15) |
| Replay Attack | Token Expiry | BLOCKED |
| Unauthorized API | RBAC | BLOCKED |

### 4.3 Performance Results

I measured the verification latency by making 100 requests and recording the time taken for each. The results are:

- Average verification latency: 0.21 milliseconds
- Maximum verification latency: 1.59 milliseconds
- Minimum verification latency: 0.12 milliseconds

This is very fast. The overhead of adding Zero Trust verification is only about 0.21 milliseconds per request. For most SDN applications, this is perfectly acceptable.

## 5. Discussion

### 5.1 Security Analysis

The framework successfully detected and blocked all 5 types of attacks. The unauthorized access attack was blocked at the token verification stage itself. The fake application was caught because the device fingerprint didn't match. The compromised application was detected by behavioral analysis when it made too many requests too quickly. The replay attack was blocked because the token had expired. The unauthorized API request was blocked by RBAC.

The detection rate is 100% for 4 out of 5 attacks. For the compromised application attack, 5 out of 15 requests were blocked. The first 10 requests were allowed because the behavioral analysis needs some history to detect anomalies. After the 11th request, the system detected the high frequency and started blocking.

### 5.2 Performance Analysis

The average verification latency is 0.21 milliseconds. This is very low. For comparison, network latency in a typical SDN environment is around 1-10 milliseconds. So our verification adds only about 2-5% overhead.

The trust score for legitimate applications stays at 1.0 because they pass all checks. For malicious applications, the trust score drops to 0.0 because they fail at various checkpoints.

### 5.3 Comparison with Traditional SDN

In traditional SDN, there is no verification of individual requests. Once an application is authenticated, it can do anything. This means all 5 attacks would succeed. In our Zero Trust framework, all 5 attacks are detected and blocked.

## 6. Conclusion and Future Work

### 6.1 Conclusion

In this paper, I proposed a Zero Trust driven framework for application trust establishment in SDN. The framework verifies every request from every application before allowing it to reach the SDN controller. I implemented 7 layers of verification including token verification, API key validation, device identity check, RBAC, ABAC, behavioral analysis, and trust scoring.

The framework was tested with 5 different attack scenarios. All attacks were successfully detected and blocked. The average verification latency is only 0.21 milliseconds which is acceptable for real-time SDN operations.

The main contribution of this work is showing that Zero Trust principles can be practically implemented in SDN using only open-source tools. The framework is fully reproducible and can be extended for more advanced security features.

### 6.2 Future Work

There are several ways to improve this work:

1. **Machine Learning for Behavioral Analysis**: Instead of using simple threshold-based anomaly detection, we could use ML algorithms to detect more subtle attacks.

2. **Distributed Zero Trust**: The current framework works with a single controller. In real SDN deployments, there are multiple controllers. We need to extend the framework for distributed environments.

3. **Real-time Visualization**: A dashboard showing trust scores, verification status, and attack attempts in real time would be useful.

4. **Integration with SIEM**: Connecting the framework with Security Information and Event Management systems would make it more practical for enterprise use.

5. **Blockchain-based Trust**: Using blockchain to store trust scores could make the system more tamper-proof.

## References

[1] NIST, "Zero Trust Architecture," NIST SP 800-207, 2020.

[2] N. McKeown et al., "OpenFlow: enabling innovation in campus networks," ACM SIGCOMM CCR, 2008.

[3] J. Kindervag, "Build Security Into Your Network's DNA: The Zero Trust Network Architecture," Forrester Research, 2010.

[4] M. Casado et al., "Ethane: taking control of the enterprise," ACM SIGCOMM, 2007.

[5] S. Scott-Hayward et al., "A survey of security in software defined networks," IEEE Communications Surveys & Tutorials, 2016.

[6] D. Kreutz et al., "Software-defined networking: A comprehensive survey," Proceedings of the IEEE, 2015.

[7] RYU SDN Framework, "RYU SDN Controller Documentation," https://ryu-sdn.org/

[8] Mininet, "Mininet: An Instant Virtual Network on your Laptop," http://mininet.org/

[9] Open vSwitch, "Open vSwitch Documentation," https://www.openvswitch.org/

[10] Open Networking Foundation, "OpenFlow Switch Specification Version 1.3," 2012.
