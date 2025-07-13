# Dummy data for ChastiPi (used for development/demo purposes)

# Device status dummy data
dummy_device_status = {
    'device_connected': True,
    'lock_status': 'locked',
    'time_remaining': '2 days, 14 hours',
    'last_check': '2024-01-15T10:30:00',
    'keyholder_approved': True,
    'emergency_available': True
}

# Access history dummy data
dummy_access_history = [
    {
        'id': 1,
        'action': 'unlock',
        'timestamp': '2024-01-15T10:30:00',
        'duration': '2 hours',
        'reason': 'Cleaning',
        'approved_by': 'keyholder'
    },
    {
        'id': 2,
        'action': 'lock',
        'timestamp': '2024-01-15T12:30:00',
        'duration': '0',
        'reason': 'Session ended',
        'approved_by': 'keyholder'
    },
    {
        'id': 3,
        'action': 'unlock',
        'timestamp': '2024-01-12T14:00:00',
        'duration': '1 hour',
        'reason': 'Medical check',
        'approved_by': 'keyholder'
    }
]

# Notifications dummy data
dummy_notifications = [
    {
        'id': 1,
        'type': 'access_request',
        'message': 'Access request received from device',
        'timestamp': '2024-01-15T10:25:00',
        'read': False
    },
    {
        'id': 2,
        'type': 'device_status',
        'message': 'Device locked successfully',
        'timestamp': '2024-01-15T12:30:00',
        'read': True
    },
    {
        'id': 3,
        'type': 'system_alert',
        'message': 'Low battery warning',
        'timestamp': '2024-01-15T09:15:00',
        'read': False
    }
]

# Statistics dummy data
dummy_statistics = {
    'total_sessions': 47,
    'avg_duration': '3.2 hours',
    'longest_session': '5 days',
    'current_streak': '12 days'
}

# Key management dummy data
dummy_key_management = {
    'digital_keys': 3,
    'backup_keys': 2,
    'emergency_keys': 1
}

# Device dashboard access history dummy data
dummy_device_access_history = {
    'last_access': '2 days ago',
    'total_sessions': 47,
    'avg_duration': '3.2 hours'
} 