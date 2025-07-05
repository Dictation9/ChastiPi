# ChastiPi Modes System

The ChastiPi modes system allows you to customize the behavior and features of your installation based on your preferences and requirements.

## 🎯 Overview

Modes control which features are enabled, how strict the system is, and what types of interactions are allowed. You can choose from built-in modes or create your own custom modes.

## 🏗️ Built-in Modes

### gentle
**Description:** A gentle, non-punishment focused experience
**Best for:** Beginners, gentle dynamics, or those who prefer positive reinforcement

**Features:**
- ✅ Cage check system enabled
- ✅ Email-based management
- ✅ Timer control and extensions
- ✅ Emergency release procedures
- ❌ Punishment system disabled
- ❌ Random discipline disabled
- ❌ Strict mode features disabled

**Configuration:**
```json
{
  "system": {
    "chastity_mode": "gentle"
  }
}
```

### timed_challenge
**Description:** Focus on timed challenges and duration-based play
**Best for:** Time-based dynamics, challenge scenarios, or structured play

**Features:**
- ✅ Cage check system enabled
- ✅ Timer control with strict enforcement
- ✅ Challenge-based scenarios
- ✅ Duration tracking and statistics
- ✅ Email-based management
- ❌ Random punishments disabled
- ❌ Strict mode features disabled

**Configuration:**
```json
{
  "system": {
    "chastity_mode": "timed_challenge"
  }
}
```

### random_discipline
**Description:** Random punishments and tasks for unpredictable dynamics
**Best for:** Random discipline scenarios, surprise elements, or varied experiences

**Features:**
- ✅ Cage check system enabled
- ✅ Random punishment generation
- ✅ Task-based scenarios
- ✅ Email-based management
- ✅ Timer control
- ❌ Strict mode features disabled

**Configuration:**
```json
{
  "system": {
    "chastity_mode": "random_discipline"
  }
}
```

### strict
**Description:** Stricter rules and consequences with enhanced security
**Best for:** Strict dynamics, enhanced security, or more controlled environments

**Features:**
- ✅ Cage check system enabled
- ✅ Punishment system enabled
- ✅ Enhanced security features
- ✅ Strict timer enforcement
- ✅ Comprehensive logging
- ✅ Email-based management
- ✅ Random discipline enabled

**Configuration:**
```json
{
  "system": {
    "chastity_mode": "strict"
  }
}
```

### extreme
**Description:** All strict features with maximum restrictions and security
**Best for:** Maximum control, strict dynamics, or high-security requirements

**Features:**
- ✅ All features enabled
- ✅ Maximum security settings
- ✅ Strict enforcement of all rules
- ✅ Enhanced monitoring and logging
- ✅ Comprehensive audit trails
- ✅ Advanced verification requirements

**Configuration:**
```json
{
  "system": {
    "chastity_mode": "extreme"
  }
}
```

### self_hosted_test
**Description:** Testing mode with instant unlocks and no restrictions
**Best for:** Development, testing, or initial setup

**Features:**
- ✅ Instant unlock capabilities
- ✅ No punishments or restrictions
- ✅ Full system access for testing
- ✅ Development-friendly settings
- ❌ No real security features
- ❌ No actual restrictions

**Configuration:**
```json
{
  "system": {
    "chastity_mode": "self_hosted_test"
  }
}
```

## 🛠️ Custom Modes

### Creating Custom Modes

You can define your own modes in `custom_modes.json` to create personalized experiences.

**File Location:** `custom_modes.json` (in the main ChastiPi directory)

**Basic Custom Mode Example:**
```json
{
  "my_custom_mode": {
    "punishments_enabled": false,
    "cage_check_enabled": true,
    "timed_challenges_enabled": true,
    "random_discipline_enabled": false,
    "strict_mode_features_enabled": false,
    "instant_unlock_enabled": false,
    "email_management_enabled": true,
    "emergency_release_enabled": true,
    "timer_control_enabled": true,
    "verification_required": true,
    "auto_escalation_enabled": false,
    "notification_frequency": "normal"
  }
}
```

### Available Mode Settings

| Setting | Type | Description | Default |
|---------|------|-------------|---------|
| `punishments_enabled` | boolean | Enable punishment system | false |
| `cage_check_enabled` | boolean | Enable cage check verification | true |
| `timed_challenges_enabled` | boolean | Enable timed challenges | false |
| `random_discipline_enabled` | boolean | Enable random punishments | false |
| `strict_mode_features_enabled` | boolean | Enable strict mode features | false |
| `instant_unlock_enabled` | boolean | Allow instant unlocks | false |
| `email_management_enabled` | boolean | Enable email-based management | true |
| `emergency_release_enabled` | boolean | Enable emergency release | true |
| `timer_control_enabled` | boolean | Enable timer modifications | true |
| `verification_required` | boolean | Require verification for actions | true |
| `auto_escalation_enabled` | boolean | Enable automatic escalation | false |
| `notification_frequency` | string | Notification frequency (low/normal/high) | normal |

### Advanced Custom Mode Example

```json
{
  "weekend_play": {
    "punishments_enabled": true,
    "cage_check_enabled": true,
    "timed_challenges_enabled": true,
    "random_discipline_enabled": true,
    "strict_mode_features_enabled": false,
    "instant_unlock_enabled": false,
    "email_management_enabled": true,
    "emergency_release_enabled": true,
    "timer_control_enabled": true,
    "verification_required": true,
    "auto_escalation_enabled": false,
    "notification_frequency": "high",
    "description": "Weekend-only play mode with all features enabled",
    "restrictions": {
      "max_duration_hours": 48,
      "require_verification": true,
      "auto_approval": false
    }
  }
}
```

### Using Custom Modes

1. **Create the custom mode file:**
   ```bash
   # Edit custom_modes.json
   nano custom_modes.json
   ```

2. **Define your custom mode:**
   ```json
   {
     "my_mode": {
       "punishments_enabled": false,
       "cage_check_enabled": true,
       "timed_challenges_enabled": true,
       "random_discipline_enabled": false,
       "strict_mode_features_enabled": false,
       "instant_unlock_enabled": false,
       "email_management_enabled": true,
       "emergency_release_enabled": true,
       "timer_control_enabled": true,
       "verification_required": true,
       "auto_escalation_enabled": false,
       "notification_frequency": "normal"
     }
   }
   ```

3. **Set the mode in config.json:**
   ```json
   {
     "system": {
       "chastity_mode": "my_mode"
     }
   }
   ```

4. **Restart the application:**
   ```bash
   # Restart to apply mode changes
   python run.py
   ```

## 🔄 Mode Switching

### Changing Modes

You can change modes at any time by updating your configuration:

1. **Edit config.json:**
   ```bash
   nano config.json
   ```

2. **Change the mode:**
   ```json
   {
     "system": {
       "chastity_mode": "strict"
     }
   }
   ```

3. **Restart the application:**
   ```bash
   python run.py
   ```

### Mode Transition Effects

When switching modes, consider these effects:

- **Feature Availability:** Some features may become unavailable
- **Existing Data:** Current requests and punishments may be affected
- **Security Settings:** Security levels may change
- **Notifications:** Notification frequency may change

### Safe Mode Switching

To safely switch modes:

1. **Complete current activities** before switching
2. **Backup your configuration** before making changes
3. **Test the new mode** with a simple request
4. **Monitor the system** after switching

## 📊 Mode Comparison

| Feature | gentle | timed_challenge | random_discipline | strict | extreme |
|---------|--------|-----------------|-------------------|--------|---------|
| Cage Checks | ✅ | ✅ | ✅ | ✅ | ✅ |
| Email Management | ✅ | ✅ | ✅ | ✅ | ✅ |
| Timer Control | ✅ | ✅ | ✅ | ✅ | ✅ |
| Emergency Release | ✅ | ✅ | ✅ | ✅ | ✅ |
| Punishments | ❌ | ❌ | ✅ | ✅ | ✅ |
| Random Tasks | ❌ | ❌ | ✅ | ✅ | ✅ |
| Strict Features | ❌ | ❌ | ❌ | ✅ | ✅ |
| Enhanced Security | ❌ | ❌ | ❌ | ✅ | ✅ |
| Auto Escalation | ❌ | ❌ | ❌ | ✅ | ✅ |

## 🛡️ Security Considerations

### Mode-Specific Security

Different modes have different security implications:

- **gentle/timed_challenge:** Lower security, easier access
- **random_discipline:** Moderate security, unpredictable elements
- **strict/extreme:** High security, strict enforcement

### Security Recommendations

- **Start with gentle mode** for initial setup
- **Test thoroughly** before switching to strict modes
- **Backup configurations** before mode changes
- **Monitor system logs** after mode switches

## 🔧 Troubleshooting

### Common Mode Issues

**Mode not applying:**
```bash
# Check configuration syntax
python -c "import json; json.load(open('config.json'))"

# Restart the application
python run.py
```

**Custom mode not recognized:**
```bash
# Check custom_modes.json syntax
python -c "import json; json.load(open('custom_modes.json'))"

# Verify mode name in config.json
grep "chastity_mode" config.json
```

**Features not working:**
- Check if the feature is enabled in your current mode
- Review the mode comparison table above
- Check system logs for errors

### Mode Validation

You can validate your mode configuration:

```bash
# Check current mode
curl http://localhost:5000/api/system/mode

# Check available features
curl http://localhost:5000/api/system/features
```

## 📚 Best Practices

### Choosing the Right Mode

1. **Start Simple:** Begin with `gentle` mode for initial setup
2. **Gradual Progression:** Move to stricter modes as you become familiar
3. **Test Thoroughly:** Test each mode before using it in production
4. **Document Changes:** Keep notes of mode changes and their effects

### Custom Mode Design

1. **Define Clear Purpose:** Know what you want to achieve
2. **Start with Built-in:** Use built-in modes as templates
3. **Test Incrementally:** Add features one at a time
4. **Document Settings:** Keep clear documentation of your custom modes

### Mode Management

1. **Regular Reviews:** Periodically review your mode settings
2. **Backup Configurations:** Keep backups of working configurations
3. **Version Control:** Track changes to custom modes
4. **Testing Environment:** Test mode changes in a safe environment

---

📖 **For more information about specific features, see the [Features Overview](features_overview.md) and [API Reference](api_reference.md).** 