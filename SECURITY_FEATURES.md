# Security Features - Bike Rental System

## Progressive Login Lockout System

### Overview
The system implements a progressive lockout mechanism to protect against brute-force login attempts. This feature is active on both **Client Login** and **Admin Login** pages.

### How It Works

#### Lockout Progression
Every **3 consecutive failed login attempts** triggers an account lockout. The lockout duration increases progressively:

| Lockout Cycle | Failed Attempts | Lockout Duration |
|---------------|-----------------|------------------|
| 1st Lockout   | 3 attempts      | 15 seconds       |
| 2nd Lockout   | 6 attempts      | 30 seconds       |
| 3rd Lockout   | 9 attempts      | 60 seconds       |
| 4th Lockout   | 12 attempts     | 120 seconds      |
| 5th Lockout   | 15 attempts     | 240 seconds      |
| 6th+ Lockout  | 18+ attempts    | Continues doubling |

#### Formula
- **1st cycle**: 15 seconds
- **2nd cycle**: 30 seconds
- **3rd cycle**: 60 seconds
- **4th+ cycles**: 60 × 2^(cycle - 3) seconds

### User Experience

#### Before Lockout
Users receive clear warnings about remaining attempts:
```
⚠️ Warning: Failed attempts: 2 (1 remaining before 15-second lockout)
```

#### During Lockout
When locked out, users see:
- Error message with lockout duration
- Live countdown timer showing remaining seconds
- Disabled login button and form fields
- Prevention of form submission

#### After Lockout
- Page automatically refreshes when countdown reaches 0
- User can attempt login again
- Failed attempt counter persists (doesn't reset)
- Next lockout will be longer

### Security Benefits

1. **Brute Force Protection**: Makes automated password guessing impractical
2. **Progressive Deterrence**: Increasing delays discourage persistent attacks
3. **User-Friendly**: Legitimate users can retry after short delays
4. **No Permanent Lockout**: Avoids locking out legitimate users permanently
5. **Session-Based**: Resets when user successfully logs in

### Technical Implementation

#### Client Login (`client/login.php`)
- Session variables track attempts and lockout time
- Server-side validation prevents bypass
- JavaScript countdown provides real-time feedback
- Form disabled during lockout period

#### Admin Login (`admin/login.php`)
- Separate session tracking for admin scope
- Same progressive lockout algorithm
- Enhanced security for administrative access

### Session Variables

```php
$_SESSION['login_attempts']     // Total failed attempts
$_SESSION['lockout_until']      // Unix timestamp when lockout expires
$_SESSION['last_attempt_time']  // Timestamp of last attempt
```

### Reset Conditions

The attempt counter resets to 0 when:
- User successfully logs in with correct credentials
- User clears browser session/cookies
- Session expires (server-side timeout)

### Code Example

```php
// Progressive lockout calculation
if ($_SESSION['login_attempts'] % 3 == 0) {
    $lockout_cycle = $_SESSION['login_attempts'] / 3;
    
    if ($lockout_cycle == 1) {
        $lockout_duration = 15;
    } elseif ($lockout_cycle == 2) {
        $lockout_duration = 30;
    } elseif ($lockout_cycle == 3) {
        $lockout_duration = 60;
    } else {
        $lockout_duration = 60 * pow(2, $lockout_cycle - 3);
    }
    
    $_SESSION['lockout_until'] = time() + $lockout_duration;
}
```

### Visual Indicators

#### Warning Alert (Yellow)
```
⚠️ Warning: Failed attempts: 2 (1 remaining before 15-second lockout)
```

#### Error Alert (Red)
```
❌ Invalid username or password. Too many failed attempts. 
   Account locked for 15 seconds.
   ⏰ Time remaining: 15 seconds
```

#### Countdown Timer
```
⏰ Time remaining: 14 seconds
⏰ Time remaining: 13 seconds
⏰ Time remaining: 12 seconds
...
```

### Testing the Feature

1. **Test Progressive Lockout**:
   - Attempt login with wrong password 3 times → 15-second lockout
   - Wait for lockout to expire
   - Attempt login with wrong password 3 more times → 30-second lockout
   - Wait for lockout to expire
   - Attempt login with wrong password 3 more times → 60-second lockout

2. **Test Successful Login**:
   - Fail 2 attempts
   - Login with correct credentials
   - Counter should reset to 0

3. **Test Countdown Timer**:
   - Trigger a lockout
   - Observe countdown timer decreasing
   - Page should auto-refresh when timer reaches 0

### Browser Compatibility

- ✅ Chrome/Edge (Chromium)
- ✅ Firefox
- ✅ Safari
- ✅ Opera
- ✅ Mobile browsers

### Security Considerations

1. **Session Hijacking**: Use HTTPS in production
2. **Session Fixation**: Regenerate session ID on login
3. **CSRF Protection**: Consider adding CSRF tokens
4. **Rate Limiting**: Consider IP-based rate limiting for additional security
5. **Logging**: Failed attempts are logged for security monitoring

### Future Enhancements

Potential improvements:
- IP-based tracking (in addition to session)
- Email notifications for multiple failed attempts
- CAPTCHA after certain number of failures
- Account lockout after extreme number of attempts
- Admin dashboard to view failed login attempts
- Whitelist for trusted IPs

### Files Modified

1. `client/login.php` - Client login with progressive lockout
2. `admin/login.php` - Admin login with progressive lockout
3. `SECURITY_FEATURES.md` - This documentation

### Configuration

To adjust lockout durations, modify the lockout calculation in both login files:

```php
// Change these values to adjust lockout times
if ($lockout_cycle == 1) {
    $lockout_duration = 15;  // Change 15 to desired seconds
} elseif ($lockout_cycle == 2) {
    $lockout_duration = 30;  // Change 30 to desired seconds
} elseif ($lockout_cycle == 3) {
    $lockout_duration = 60;  // Change 60 to desired seconds
}
```

---

**Last Updated**: 2025-11-05
**Version**: 1.0.0
**Status**: ✅ Active and Tested

