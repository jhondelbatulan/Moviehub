# Progressive Login Lockout - Quick Reference

## 🔒 Lockout Schedule

| Attempt # | Status | Lockout Duration | Total Wait Time |
|-----------|--------|------------------|-----------------|
| 1 | ⚠️ Warning | - | - |
| 2 | ⚠️ Warning | - | - |
| **3** | 🔒 **LOCKED** | **15 seconds** | 15s |
| 4 | ⚠️ Warning | - | - |
| 5 | ⚠️ Warning | - | - |
| **6** | 🔒 **LOCKED** | **30 seconds** | 45s |
| 7 | ⚠️ Warning | - | - |
| 8 | ⚠️ Warning | - | - |
| **9** | 🔒 **LOCKED** | **60 seconds** | 1m 45s |
| 10 | ⚠️ Warning | - | - |
| 11 | ⚠️ Warning | - | - |
| **12** | 🔒 **LOCKED** | **120 seconds** | 3m 45s |
| 13 | ⚠️ Warning | - | - |
| 14 | ⚠️ Warning | - | - |
| **15** | 🔒 **LOCKED** | **240 seconds** | 7m 45s |
| **18** | 🔒 **LOCKED** | **480 seconds** | 15m 45s |
| **21** | 🔒 **LOCKED** | **960 seconds** | 31m 45s |

## 📊 Lockout Progression Formula

```
Cycle 1 (3 attempts):   15 seconds
Cycle 2 (6 attempts):   30 seconds
Cycle 3 (9 attempts):   60 seconds
Cycle 4+ (12+ attempts): 60 × 2^(cycle - 3) seconds
```

## 🎯 Key Features

### ✅ What Happens During Lockout
- ❌ Login button is **disabled**
- ❌ Username and password fields are **disabled**
- ⏰ **Live countdown timer** shows remaining seconds
- 🔄 Page **auto-refreshes** when countdown reaches 0
- 🚫 Form submission is **prevented**
- 🚫 F5 refresh is **blocked** (with alert)

### ✅ What Happens After Lockout
- ✔️ Form is **re-enabled**
- ✔️ User can **attempt login again**
- ⚠️ Failed attempt counter **persists**
- ⏰ Next lockout will be **longer**

### ✅ How to Reset Counter
- ✔️ **Successful login** with correct credentials
- ✔️ Clear browser **session/cookies**
- ⏰ Wait for **session timeout** (server-side)

## 🎨 Visual Indicators

### Warning Message (Yellow Alert)
```
⚠️ Warning: Failed attempts: 2 (1 remaining before 15-second lockout)
```

### Lockout Message (Red Alert)
```
❌ Invalid username or password. Too many failed attempts.
   Account locked for 15 seconds.
   ⏰ Time remaining: 15 seconds
```

### Countdown Display
```
⏰ Time remaining: 14 seconds
⏰ Time remaining: 13 seconds
⏰ Time remaining: 12 seconds
...
⏰ Time remaining: 0 seconds
🔄 [Page Reloads]
```

## 🧪 Testing Scenarios

### Scenario 1: First Lockout (15 seconds)
1. Enter wrong password → "1 attempt, 2 remaining"
2. Enter wrong password → "2 attempts, 1 remaining"
3. Enter wrong password → **LOCKED for 15 seconds**
4. Wait 15 seconds → Form re-enabled

### Scenario 2: Second Lockout (30 seconds)
1. Continue from Scenario 1
2. Enter wrong password → "4 attempts, 2 remaining"
3. Enter wrong password → "5 attempts, 1 remaining"
4. Enter wrong password → **LOCKED for 30 seconds**
5. Wait 30 seconds → Form re-enabled

### Scenario 3: Third Lockout (60 seconds)
1. Continue from Scenario 2
2. Enter wrong password → "7 attempts, 2 remaining"
3. Enter wrong password → "8 attempts, 1 remaining"
4. Enter wrong password → **LOCKED for 60 seconds**
5. Wait 60 seconds → Form re-enabled

### Scenario 4: Successful Login Resets Counter
1. Fail 2 attempts → "2 attempts, 1 remaining"
2. Enter **correct credentials** → Login successful
3. Logout and try again → Counter is **reset to 0**

## 🔧 Technical Details

### Session Variables
```php
$_SESSION['login_attempts']     // Total failed attempts (0, 1, 2, 3, ...)
$_SESSION['lockout_until']      // Unix timestamp when lockout expires
$_SESSION['last_attempt_time']  // Timestamp of last login attempt
```

### Client Login
- File: `client/login.php`
- Scope: Client users only
- Session prefix: None

### Admin Login
- File: `admin/login.php`
- Scope: Admin users only
- Session prefix: `login_attempts_admin`, `login_lock_until_admin`

## 📱 Browser Support

| Browser | Status |
|---------|--------|
| Chrome | ✅ Fully Supported |
| Firefox | ✅ Fully Supported |
| Safari | ✅ Fully Supported |
| Edge | ✅ Fully Supported |
| Opera | ✅ Fully Supported |
| Mobile | ✅ Fully Supported |

## 🛡️ Security Benefits

1. **Brute Force Protection**: Exponentially increasing delays make automated attacks impractical
2. **User-Friendly**: Short initial delays don't frustrate legitimate users
3. **No Permanent Lockout**: Users are never permanently locked out
4. **Session-Based**: Resets on successful login
5. **Progressive Deterrence**: Attackers face increasingly long delays

## ⚙️ Configuration

To modify lockout durations, edit the lockout calculation in login files:

```php
// In client/login.php or admin/login.php
if ($lockout_cycle == 1) {
    $lockout_duration = 15;  // ← Change this
} elseif ($lockout_cycle == 2) {
    $lockout_duration = 30;  // ← Change this
} elseif ($lockout_cycle == 3) {
    $lockout_duration = 60;  // ← Change this
} else {
    $lockout_duration = 60 * pow(2, $lockout_cycle - 3);  // ← Adjust formula
}
```

## 📞 Support

For issues or questions:
- Check `SECURITY_FEATURES.md` for detailed documentation
- Review code in `client/login.php` and `admin/login.php`
- Test in browser developer console for debugging

---

**Version**: 1.0.0  
**Last Updated**: 2025-11-05  
**Status**: ✅ Active

