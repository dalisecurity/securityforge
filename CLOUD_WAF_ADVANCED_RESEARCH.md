# 🔬 Advanced Cloud WAF Detection Research

## Executive Summary

Deep research into advanced techniques for improving cloud WAF detection accuracy, focusing on behavioral patterns, response analysis, and better differentiation between CDN and WAF deployments.

**Focus Areas**: AWS WAF, Azure WAF, Google Cloud Armor  
**Goal**: Improve detection accuracy from current levels to 70%+ confidence  
**Approach**: Multi-factor analysis beyond simple header detection

---

## 🎯 Current Challenges

### **AWS WAF** (45.6% avg confidence)
- ❌ CloudFront headers present ≠ WAF enabled
- ❌ Many deployments don't expose `x-amzn-waf-*` headers
- ❌ Generic AWS headers insufficient
- ❌ Need behavioral differentiation

### **Azure WAF** (35.0% avg confidence)
- ❌ Generic Azure headers ≠ Front Door WAF
- ❌ `X-Azure-FDID` not always present
- ❌ IIS server header too generic
- ❌ Need Front Door-specific patterns

### **Google Cloud Armor** (10.0% avg confidence)
- ❌ Generic GCP headers insufficient
- ❌ No definitive signatures found
- ❌ Very low confidence
- ❌ Need GCP-specific research

---

## 🔍 AWS WAF Advanced Detection

### **Key Research Findings**

From AWS Documentation:
> "When you define custom response handling for a Block action, you define the status code, headers, and response body."

**This means**: AWS WAF can send custom responses with custom headers!

### **Detection Strategy Layers**

#### **Layer 1: Definitive Indicators (90%+ confidence)**
```
x-amzn-waf-*           # Any header with this prefix
x-amzn-waf-action      # Explicit WAF action header
Custom WAF headers     # User-configured headers
```

#### **Layer 2: Strong Indicators (70-80% confidence)**
```
Multiple AWS headers + CloudFront:
- x-amzn-requestid
- x-amzn-trace-id
- x-amz-cf-id
- AWSALB* cookies

Custom response codes:
- Non-standard 403 responses
- Custom error pages with AWS branding
```

#### **Layer 3: Behavioral Indicators (50-60% confidence)**
```
Response patterns:
- Consistent blocking behavior
- Rate limiting responses
- Challenge/CAPTCHA pages
- Custom error messages

Timing patterns:
- Fast rejection (< 50ms)
- Edge processing indicators
```

#### **Layer 4: Weak Indicators (20-40% confidence)**
```
CloudFront only:
- x-amz-cf-id alone
- CloudFront server header
- No other AWS indicators
```

### **AWS WAF Custom Response Patterns**

**Common Custom Responses**:
```http
HTTP/1.1 403 Forbidden
x-amzn-waf-action: BLOCK
x-amzn-requestid: [UUID]
Content-Type: application/json

{"error": "Request blocked by security policy"}
```

**Custom Headers Pattern**:
- Headers starting with `x-amzn-waf-`
- Custom status codes (403, 405, 429)
- JSON error responses
- Redirect responses (3xx)

### **CloudFront + WAF Differentiation**

| Scenario | Headers Present | Confidence | Classification |
|----------|----------------|------------|----------------|
| `x-amzn-waf-*` present | WAF-specific | **90%+** | AWS WAF |
| Multiple AWS + CF | 3+ AWS headers | **60-70%** | Likely WAF |
| CF + AWSALB | CloudFront + ALB | **50-60%** | Possible WAF |
| CF only | x-amz-cf-id only | **20-30%** | CDN only |

### **Improved Detection Logic**

```python
def detect_aws_waf_advanced(headers, response_body, status_code, timing):
    confidence = 0
    indicators = []
    
    # Layer 1: Definitive (90%+)
    if any(h.startswith('x-amzn-waf-') for h in headers):
        confidence = 90
        indicators.append("WAF-specific header")
        return confidence, "AWS WAF", indicators
    
    # Layer 2: Strong (70-80%)
    aws_headers = [h for h in headers if h.startswith(('x-amzn-', 'x-amz-'))]
    if len(aws_headers) >= 3 and 'x-amz-cf-id' in headers:
        confidence = 70
        indicators.append(f"{len(aws_headers)} AWS headers + CloudFront")
    
    # Check for custom error response
    if status_code == 403 and 'application/json' in headers.get('content-type', ''):
        confidence += 10
        indicators.append("JSON error response")
    
    # Layer 3: Behavioral (50-60%)
    if timing and timing < 50:  # Fast rejection
        confidence += 5
        indicators.append("Fast rejection (< 50ms)")
    
    # Check response body for AWS WAF patterns
    if response_body:
        if 'security policy' in response_body.lower():
            confidence += 10
            indicators.append("Security policy message")
        if 'request blocked' in response_body.lower():
            confidence += 5
            indicators.append("Block message")
    
    # Layer 4: Weak (20-40%)
    if 'x-amz-cf-id' in headers and len(aws_headers) == 1:
        confidence = max(confidence, 25)
        indicators.append("CloudFront only")
    
    return confidence, "AWS WAF" if confidence >= 40 else "CloudFront", indicators
```

---

## 🔍 Azure WAF Advanced Detection

### **Key Research Findings**

From Microsoft Documentation:
> "Azure Front Door appends specific headers to all requests and responses, including X-Azure-Ref, X-Azure-FDID, and X-FD-HealthProbe."

**Key Insight**: Front Door headers indicate WAF capability, but not necessarily active WAF blocking.

### **Detection Strategy Layers**

#### **Layer 1: Definitive Indicators (80%+ confidence)**
```
X-Azure-FDID           # Front Door ID (strongest)
X-FD-HealthProbe       # Front Door health probe
X-Azure-RequestChain   # Request chain (Front Door)
```

#### **Layer 2: Strong Indicators (60-70% confidence)**
```
Multiple Front Door headers:
- X-Azure-Ref
- X-Azure-SocketIP
- X-Azure-ClientIP
- X-Azure-JA4-Fingerprint (advanced features)

Custom response patterns:
- Azure WAF error pages
- Front Door error messages
```

#### **Layer 3: Behavioral Indicators (40-50% confidence)**
```
Response patterns:
- Azure-branded error pages
- Front Door error messages
- WAF block messages

Timing patterns:
- Edge processing
- Global distribution indicators
```

#### **Layer 4: Weak Indicators (20-30% confidence)**
```
Generic Azure:
- x-ms-* headers
- ARRAffinity cookies
- IIS server header
- Azure hosting indicators
```

### **Azure Front Door vs Hosting Differentiation**

| Scenario | Headers Present | Confidence | Classification |
|----------|----------------|------------|----------------|
| `X-Azure-FDID` present | Front Door ID | **80%+** | Azure Front Door WAF |
| 2+ FD headers | Multiple FD | **65-75%** | Front Door WAF |
| `X-Azure-Ref` only | Single FD header | **45-55%** | Possible Front Door |
| Generic Azure | IIS, x-ms-* | **20-30%** | Azure hosting |

### **Azure WAF Response Patterns**

**Front Door Block Response**:
```http
HTTP/1.1 403 Forbidden
X-Azure-Ref: 0zxV+XAAAAABKMMOjBv2NT4TY6SQVjC0zV1NURURHRTA2MTkANDM3YzgyY2QtMzYwYS00YTU0LTk0YzMtNWZmNzA3NjQ3Nzgz
X-Azure-FDID: a0a0a0a0-bbbb-cccc-dddd-e1e1e1e1e1e1
X-Cache: TCP_DENIED

<html>
<body>
<h1>Access Denied</h1>
<p>Request blocked by Azure Web Application Firewall</p>
</body>
</html>
```

### **Improved Detection Logic**

```python
def detect_azure_waf_advanced(headers, response_body, status_code):
    confidence = 0
    indicators = []
    
    # Layer 1: Definitive (80%+)
    if 'x-azure-fdid' in [h.lower() for h in headers]:
        confidence = 80
        indicators.append("Azure Front Door ID")
    
    # Layer 2: Strong (60-70%)
    fd_headers = ['x-azure-ref', 'x-fd-healthprobe', 'x-azure-requestchain', 
                  'x-azure-socketip', 'x-azure-clientip']
    fd_count = sum(1 for h in fd_headers if h in [x.lower() for x in headers])
    
    if fd_count >= 2:
        confidence = max(confidence, 65)
        indicators.append(f"{fd_count} Front Door headers")
    
    # Check for JA4 fingerprint (advanced features)
    if 'x-azure-ja4-fingerprint' in [h.lower() for h in headers]:
        confidence += 10
        indicators.append("JA4 fingerprint (advanced)")
    
    # Layer 3: Behavioral (40-50%)
    if response_body:
        if 'azure web application firewall' in response_body.lower():
            confidence = max(confidence, 75)
            indicators.append("Azure WAF message")
        if 'azure front door' in response_body.lower():
            confidence += 10
            indicators.append("Front Door message")
    
    # Layer 4: Weak (20-30%)
    azure_headers = [h for h in headers if h.lower().startswith(('x-azure-', 'x-ms-'))]
    if len(azure_headers) >= 1 and confidence < 40:
        confidence = max(confidence, 25)
        indicators.append("Generic Azure headers")
    
    return confidence, "Microsoft Azure WAF" if confidence >= 45 else "Azure Hosting", indicators
```

---

## 🔍 Google Cloud Armor Advanced Detection

### **Key Research Findings**

Google Cloud Armor is the most challenging to detect due to:
- Minimal header exposure
- Generic GCP headers
- No definitive signatures in public documentation

### **Detection Strategy Layers**

#### **Layer 1: Strong Indicators (60%+ confidence)**
```
x-goog-*               # Google-specific headers
x-cloud-trace-context  # GCP trace context
x-gfe-*                # Google Front End headers
gws/gfe server         # Google Web Server
```

#### **Layer 2: Behavioral Indicators (40-50% confidence)**
```
Response patterns:
- Google-branded error pages
- Cloud Armor error messages
- reCAPTCHA challenges

Status codes:
- 403 with Google patterns
- Custom error pages
```

#### **Layer 3: Weak Indicators (20-30% confidence)**
```
Generic GCP:
- gws server header
- Generic Google headers
- No specific Cloud Armor indicators
```

### **Google Cloud Armor Response Patterns**

**Typical Block Response**:
```http
HTTP/1.1 403 Forbidden
Server: gws
X-Cloud-Trace-Context: [trace-id]
Content-Type: text/html

<html>
<body>
<h1>403 Forbidden</h1>
<p>Your client does not have permission to access this resource</p>
</body>
</html>
```

### **Improved Detection Logic**

```python
def detect_gcp_armor_advanced(headers, response_body, status_code):
    confidence = 0
    indicators = []
    
    # Layer 1: Strong (60%+)
    gcp_headers = [h for h in headers if h.lower().startswith(('x-goog-', 'x-gfe-', 'x-cloud-'))]
    
    if len(gcp_headers) >= 2:
        confidence = 60
        indicators.append(f"{len(gcp_headers)} GCP headers")
    
    # Check for trace context (GCP-specific)
    if 'x-cloud-trace-context' in [h.lower() for h in headers]:
        confidence += 10
        indicators.append("GCP trace context")
    
    # Layer 2: Behavioral (40-50%)
    if response_body:
        if 'cloud armor' in response_body.lower():
            confidence = max(confidence, 70)
            indicators.append("Cloud Armor message")
        if 'google' in response_body.lower() and status_code == 403:
            confidence += 10
            indicators.append("Google error page")
    
    # Check server header
    server = headers.get('server', '').lower()
    if server in ['gws', 'gfe']:
        confidence = max(confidence, 30)
        indicators.append(f"Google server: {server}")
    
    # Layer 3: Weak (20-30%)
    if confidence < 30 and len(gcp_headers) >= 1:
        confidence = 25
        indicators.append("Generic GCP headers")
    
    return confidence, "Google Cloud Armor" if confidence >= 40 else "GCP Hosting", indicators
```

---

## 🎯 Multi-Factor Scoring System

### **Confidence Calculation Formula**

```python
def calculate_cloud_waf_confidence(vendor, indicators):
    """
    Multi-factor confidence scoring for cloud WAFs
    """
    base_confidence = 0
    multipliers = []
    
    # Factor 1: Header-based detection
    if 'waf_specific_header' in indicators:
        base_confidence = 90
        multipliers.append(1.0)
    elif 'multiple_vendor_headers' in indicators:
        base_confidence = 60
        multipliers.append(0.9)
    elif 'single_vendor_header' in indicators:
        base_confidence = 40
        multipliers.append(0.8)
    
    # Factor 2: Response body analysis
    if 'waf_error_message' in indicators:
        base_confidence += 15
        multipliers.append(1.1)
    elif 'vendor_error_page' in indicators:
        base_confidence += 10
        multipliers.append(1.05)
    
    # Factor 3: Behavioral patterns
    if 'fast_rejection' in indicators:
        base_confidence += 5
        multipliers.append(1.02)
    if 'custom_error_response' in indicators:
        base_confidence += 5
        multipliers.append(1.02)
    
    # Factor 4: Status code analysis
    if 'unique_status_code' in indicators:
        base_confidence += 10
        multipliers.append(1.05)
    
    # Apply multipliers
    final_confidence = base_confidence
    for mult in multipliers:
        final_confidence *= mult
    
    return min(int(final_confidence), 100)
```

---

## 📊 Enhanced Signature Patterns

### **AWS WAF Enhanced Signatures**

```python
'AWS WAF': {
    # Existing signatures...
    
    # NEW: Response body patterns
    'response_body_patterns': [
        'request blocked by security policy',
        'aws waf',
        'blocked by waf',
        'security violation',
    ],
    
    # NEW: Custom response indicators
    'custom_response_indicators': [
        'application/json content-type with 403',
        'custom error page structure',
        'redirect with 3xx',
    ],
    
    # NEW: Behavioral patterns
    'behavioral_patterns': {
        'fast_rejection': True,  # < 50ms response
        'consistent_blocking': True,  # Same URL always blocked
        'rate_limiting': True,  # 429 responses
    },
    
    # NEW: Multi-header combinations
    'header_combinations': [
        ['x-amzn-requestid', 'x-amzn-trace-id', 'x-amz-cf-id'],  # Strong
        ['x-amzn-requestid', 'x-amz-cf-id'],  # Medium
    ],
}
```

### **Azure WAF Enhanced Signatures**

```python
'Microsoft Azure WAF': {
    # Existing signatures...
    
    # NEW: Response body patterns
    'response_body_patterns': [
        'azure web application firewall',
        'azure front door',
        'request blocked by azure',
        'access denied by waf',
    ],
    
    # NEW: Front Door indicators
    'front_door_indicators': {
        'required_headers': ['x-azure-fdid'],
        'optional_headers': ['x-fd-healthprobe', 'x-azure-requestchain'],
        'advanced_headers': ['x-azure-ja4-fingerprint'],
    },
    
    # NEW: Cache status patterns
    'cache_patterns': [
        'TCP_DENIED',  # Front Door WAF block
        'TCP_MISS',    # Front Door cache miss
    ],
    
    # NEW: Multi-header combinations
    'header_combinations': [
        ['x-azure-fdid', 'x-azure-ref'],  # Strong
        ['x-azure-ref', 'x-fd-healthprobe'],  # Medium
    ],
}
```

### **Google Cloud Armor Enhanced Signatures**

```python
'Google Cloud Armor': {
    # Existing signatures...
    
    # NEW: Response body patterns
    'response_body_patterns': [
        'cloud armor',
        'google cloud platform',
        'your client does not have permission',
        'access denied',
    ],
    
    # NEW: GCP-specific headers
    'gcp_headers': [
        'x-cloud-trace-context',
        'x-goog-*',
        'x-gfe-*',
    ],
    
    # NEW: Server patterns
    'server_patterns': [
        'gws',
        'gfe',
        'Google Frontend',
    ],
    
    # NEW: reCAPTCHA indicators
    'recaptcha_indicators': [
        'recaptcha',
        'g-recaptcha',
        'google.com/recaptcha',
    ],
}
```

---

## 🔧 Implementation Recommendations

### **Priority 1: Multi-Factor Analysis**

1. **Header Analysis** (40% weight)
   - Vendor-specific headers
   - Header combinations
   - Prefix matching

2. **Response Body Analysis** (30% weight)
   - Error message patterns
   - Vendor branding
   - WAF-specific messages

3. **Behavioral Analysis** (20% weight)
   - Response timing
   - Consistent blocking
   - Rate limiting patterns

4. **Status Code Analysis** (10% weight)
   - Unique codes
   - Custom responses
   - Error patterns

### **Priority 2: Response Body Parsing**

```python
def analyze_response_body(body, vendor_patterns):
    """
    Analyze response body for WAF indicators
    """
    if not body:
        return 0, []
    
    confidence_boost = 0
    indicators = []
    
    body_lower = body.lower()
    
    for pattern in vendor_patterns.get('response_body_patterns', []):
        if pattern in body_lower:
            confidence_boost += 15
            indicators.append(f"Body pattern: {pattern}")
    
    # Check for JSON error responses
    if body.strip().startswith('{') and 'error' in body_lower:
        confidence_boost += 10
        indicators.append("JSON error response")
    
    # Check for HTML error pages
    if '<html' in body_lower and 'error' in body_lower:
        confidence_boost += 5
        indicators.append("HTML error page")
    
    return confidence_boost, indicators
```

### **Priority 3: Header Combination Analysis**

```python
def analyze_header_combinations(headers, vendor_combinations):
    """
    Analyze header combinations for stronger confidence
    """
    confidence_boost = 0
    indicators = []
    
    for combo in vendor_combinations:
        matches = sum(1 for h in combo if h in [x.lower() for x in headers])
        
        if matches == len(combo):
            # All headers in combination present
            confidence_boost += 20
            indicators.append(f"Header combo: {len(combo)} headers")
        elif matches >= len(combo) * 0.7:
            # Most headers present
            confidence_boost += 10
            indicators.append(f"Partial combo: {matches}/{len(combo)}")
    
    return confidence_boost, indicators
```

---

## 📈 Expected Improvements

### **AWS WAF**
- **Current**: 45.6% avg confidence
- **Expected**: **65%+** avg confidence
- **Improvement**: +19.4%

**Breakdown**:
- Definitive indicators (x-amzn-waf-*): 90%+ (no change)
- Multi-header analysis: 60-70% (from 35-60%)
- Response body analysis: +15% boost
- CloudFront only: 20-30% (appropriate)

### **Azure WAF**
- **Current**: 35.0% avg confidence
- **Expected**: **70%+** avg confidence
- **Improvement**: +35.0%

**Breakdown**:
- X-Azure-FDID present: 80%+ (from 75%+)
- Multi-header Front Door: 65-75% (from 60-70%)
- Response body analysis: +15% boost
- Generic Azure: 20-30% (appropriate)

### **Google Cloud Armor**
- **Current**: 10.0% avg confidence
- **Expected**: **50%+** avg confidence
- **Improvement**: +40.0%

**Breakdown**:
- Multiple GCP headers: 60%+ (from 10%)
- Response body analysis: +15% boost
- Trace context: +10% boost
- Generic GCP: 25-30% (from 10%)

---

## 🎯 Testing Strategy

### **Test Set Requirements**

1. **AWS WAF Test Set** (30 domains)
   - 10 with known AWS WAF (definitive)
   - 10 with CloudFront + possible WAF
   - 10 with CloudFront only

2. **Azure WAF Test Set** (30 domains)
   - 10 with known Azure Front Door WAF
   - 10 with Azure hosting + possible WAF
   - 10 with generic Azure hosting

3. **GCP Armor Test Set** (20 domains)
   - 10 with known Cloud Armor
   - 10 with GCP hosting only

### **Validation Metrics**

- **Detection Rate**: 85%+ target
- **Average Confidence**: 70%+ target
- **False Positive Rate**: <10% target
- **High Confidence Rate**: 60%+ target

---

## 📝 Conclusion

Advanced cloud WAF detection requires multi-factor analysis beyond simple header matching. By combining header analysis, response body parsing, behavioral patterns, and header combinations, we can significantly improve detection accuracy for AWS WAF, Azure WAF, and Google Cloud Armor.

**Key Improvements**:
1. ✅ Multi-factor confidence scoring
2. ✅ Response body pattern analysis
3. ✅ Header combination detection
4. ✅ Behavioral pattern recognition
5. ✅ Better CDN vs WAF differentiation

**Expected Overall Impact**:
- AWS WAF: 45.6% → 65%+ (+19.4%)
- Azure WAF: 35.0% → 70%+ (+35.0%)
- GCP Armor: 10.0% → 50%+ (+40.0%)

---

**Research Date**: March 1, 2026  
**Status**: Ready for Implementation  
**Priority**: High (addresses lowest-performing vendors)
