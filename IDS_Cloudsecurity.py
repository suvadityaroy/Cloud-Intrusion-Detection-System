import os
import boto3
import numpy as np
from sklearn.ensemble import IsolationForest
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from datetime import datetime, timedelta
import requests
from collections import defaultdict

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ids_security.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# AWS setup - environment variables for credentials
AWS_REGIONS = os.getenv('AWS_REGIONS', 'us-east-1').split(',')
session = boto3.Session(
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=AWS_REGIONS[0]
)

# Email credentials from environment variables
sender_email = os.getenv('SENDER_EMAIL')
email_password = os.getenv('EMAIL_PASSWORD')
slack_webhook_url = os.getenv('SLACK_WEBHOOK_URL', '')
region='us-east-1'):
    """Fetch the most recent CloudTrail logs from a specific region"""
    try:
        cloudtrail = session.client('cloudtrail', region_name=region)
        start_time = datetime.utcnow() - timedelta(hours=LOOKBACK_HOURS)
        
        response = cloudtrail.lookup_events(
            MaxResults=MAX_EVENTS,
            StartTime=start_time
        )
        events = response['Events']
        logger.info(f"Fetched {len(events)} events from {region}")
    except Exception as e:
        logger.error(f"Failed to fetch CloudTrail logs from {region}: {e}")
        events = []
    return events

def get_all_region_logs():
    """Fetch CloudTrail logs from all configured regions"""
    all_events = []
    for region in AWS_REGIONS:
        events = get_cloudtrail_logs(region)
        for event in events:
            event['MonitoredRegion'] = region
        all_events.extend(events)
    logger.info(f"Total events fetched from all regions: {len(all_events)}")
    return all_ detection rules from config file or use defaults"""
    default_rules = {
        "monitor_root_account": True,
        "monitor_failed_logins": True,
        "monitor_iam_changes": True,
        "monitor_resource_deletions": True,
        "monitor_cloudtrail_disabled": True,
        "failed_login_threshold": 5,
        "critical_resources": ["EC2", "RDS", "DynamoDB", "Lambda"]
    }
    
    try:
        if os.path.exists('detection_rules.json'):
            with open('detection_rules.json', 'r') as f:
                return {**default_rules, **json.load(f)}
    except Exception as e:
        logger.warning(f"Could not load detection rules: {e}. Using defaults.")
    
    return default_rules

DETECTION_RULES = load_detection_rules()

def get_cloudtrail_logs():
    """Fetch the most recent CloudTrail logs"""
    try:
        response = cloudtrail.lookup_events(MaxResults=10)  # Fetch up to 10 recent events
        event_name = log.get('EventName', '')
        if 'PutBucketAcl' in event_name or 'PutBucketPolicy' in event_name:
            resources = log.get('Resources', [])
            if resources:
                bucket_name = resources[0].get('ResourceName', 'unknown')
                alert_message = f"⚠️ S3 Bucket Permission Change: {bucket_name} (Event: {event_name})"
                alerts.append({
           root_account_usage(logs):
    """Detect root account usage"""
    if not DETECTION_RULES.get('monitor_root_account', True):
        return []
    
    alerts = []
    for log in logs:
        user_identity = log.get('Username', '')
        if user_identity == 'Root' or 'root' in user_identity.lower():
            alert_message = f"🚨 ROOT ACCOUNT USED: Event {log.get('EventName')} at {log.get('EventTime')}"
            alerts.append({
                'type': 'ROOT_ACCOUNT_USAGE',
                'severity': 'CRITICAL',
                'message': alert_message,
                'timestamp': log.get('EventTime'),
                'region': log.get('MonitoredRegion', 'unknown'),
                'event': log.get('EventName')
            })
            logger.critical(alert_message)
    return alerts

def detect_failed_logins(logs):
    """Detect multiple failed login attempts"""
    if not DETECTION_RULES.get('monitor_failed_logins', True):
        return []
    
    failed_attempts = defaultdict(int)
    alerts = []
    
    for log in logs:
        event_name = log.get('EventName', '')
        if 'ConsoleLogin' in event_name:
            error_code = log.get('ErrorCode', '')
            if error_code or 'Failed' in event_name:
                user = log.get('Username', 'unknown')
                failed_attempts[user] += 1
    
    threshold = DETECTION_RULES.get('failed_login_threshold', 5)
    fave_alert_history(alerts):
    """Save alerts to a JSON file for historical tracking"""
    try:
        history = []
        if os.path.exists(ALERT_LOG_FILE):
            with open(ALERT_LOG_FILE, 'r') as f:
                history = json.load(f)
        
        history.extend(alerts)
        
        # Keep only last 1000 alerts
        history = history[-1000:]
        
        with open(ALERT_LOG_FILE, 'w') as f:
            json.dump(history, f, indent=2, default=str)
        
        logger.info(f"Saved {len(alerts)} alerts to history")
    logger.info("=" * 60)
    logger.info("Starting Cloud Intrusion Detection System")
    logger.info(f"Monitoring regions: {', '.join(AWS_REGIONS)}")
    logger.info(f"Lookback period: {LOOKBACK_HOURS} hours")
    logger.info("=" * 60)
    
    try:
        # Step 1: Fetch CloudTrail logs from all regions
        logs = get_all_region_logs()
        
        if not logs:
            logger.warning("No CloudTrail events found. Check your AWS configuration.")
            return

        # Step 2: Run all detection methods
        all_alerts = []
        
        # Rule-based detections
        all_alerts.extend(detect_root_account_usage(logs))
        all_alerts.extend(detect_failed_logins(logs))
        all_alerts.extend(detect_iam_changes(logs))
        all_alerts.extend(detect_resource_deletions(logs))
        all_alerts.extend(detect_cloudtrail_disabled(logs))
        all_alerts.extend(detect_public_s3_buckets(logs))
        
        # ML-based detection
        all_alerts.extend(detect_api_anomalies(logs))

        # Step 3: Process and send alerts
        if all_alerts:
            logger.warning(f"🚨 {len(all_alerts)} security alert(s) generated!")
            
            # Save to history
            save_alert_history(all_alerts)
            
            # Send notifications
            send_alert_email(
                f"Cloud IDS Alert - {len(all_alerts)} Event(s) Detected",
                all_alerts
            )
            send_slack_alert(all_alerts)
            
            # Print summary
            severity_counts = defaultdict(int)
            for alert in all_alerts:
                severity_counts[alert.get('severity', 'UNKNOWN')] += 1
            
            logger.info("\n📊 Alert Summary:")
            for severity, count in sorted(severity_counts.items()):
                logger.info(f"  {severity}: {count}")
        else:
            logger.info("✅ No security alerts generated. System is normal.")
    
    except Exception as e:
        logger.error(f"Error during intrusion detection: {e}", exc_info=True)
    
    logger.info("=" * 60)
    logger.info("Cloud Intrusion Detection System completed")
    logger.info("=" * 60
        attachments = []
        for alert in alerts[:10]:  # Limit to 10 alerts per message
            attachments.append({
                'color': severity_colors.get(alert.get('severity', 'MEDIUM'), '#808080'),
                'title': f"{alert.get('severity', 'ALERT')} - {alert.get('type', 'SECURITY_ALERT')}",
                'text': alert.get('message', ''),
                'footer': f"Region: {alert.get('region', 'N/A')} | Time: {alert.get('timestamp', '')}"
            })
        
        payload = {
            'text': f'🔔 *Cloud IDS Alert* - {len(alerts)} security event(s) detected',
            'attachments': attachments
        }
        
        response = requests.post(slack_webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        logger.info("Slack alert sent successfully")
    except Exception as e:
        logger.error(f"Failed to send Slack alert: {e}")

def send_alert_email(subject, alerts):
    """Send an HTML email alert to the admin"""
    if not sender_email or not email_password:
        logger.warning("Email credentials not configured, skipping email alert")
        return
    
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = os.getenv('RECEIVER_EMAIL')

        # Create HTML table for alerts
        html = f"""
        <html>
          <head>
            <style>
              table {{ border-collapse: collapse; width: 100%; }}
              th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
              th {{ background-color: #4CAF50; color: white; }}
              .CRITICAL {{ background-color: #ffcccc; }}
              .HIGH {{ background-color: #ffe6cc; }}
              .MEDIUM {{ background-color: #ffffcc; }}
            </style>
          </head>
          <body>
            <h2>Cloud Intrusion Detection System Alert</h2>
            <p>Detected {len(alerts)} security event(s):</p>
            <table>
              <tr>
                <th>Severity</th>
                <th>Type</th>
                <th>Message</th>
                <th>Time</th>
                <th>Region</th>
              </tr>
        """
        
        for alert in alerts:
            severity = alert.get('severity', 'MEDIUM')
            html += f"""
              <tr class="{severity}">
                <td>{severity}</td>
                <td>{alert.get('type', 'N/A')}</td>
                <td>{alert.get('message', '')}</td>
                <td>{alert.get('timestamp', 'N/A')}</td>
                <td>{alert.get('region', 'N/A')}</td>
              </tr>
            """
        
        html += """
            </table>
          </body>
        </html>
        """
        
        msg.attach(MIMEText(html, 'html'))

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
            smtp_server.login(sender_email, email_password)
            smtp_server.sendmail(sender_email, os.getenv('RECEIVER_EMAIL'), msg.as_string())
        logger.info("Alert email sent successfullye)
    
    return alerts

def detect_iam_changes(logs):
    """Detect IAM policy or role changes"""
    if not DETECTION_RULES.get('monitor_iam_changes', True):
        return []
    
    alerts = []
    iam_events = [
        'PutUserPolicy', 'PutRolePolicy', 'AttachUserPolicy', 
        'AttachRolePolicy', 'CreateAccessKey', 'CreateUser',
        'DeleteUserPolicy', 'DeleteRolePolicy', 'CreateRole'
    ]
    
    for log in logs:
        event_name = log.get('EventName', '')
        if event_name in iam_events:
            user = log.get('Username', 'unknown')
            alert_message = f"🔑 IAM CHANGE: {event_name} by {user} at {log.get('EventTime')}"
            alerts.append({
                'type': 'IAM_CHANGE',
                'severity': 'MEDIUM',
                'message': alert_message,
                'timestamp': log.get('EventTime'),
                'user': user,
                'event': event_name,
                'region': log.get('MonitoredRegion', 'unknown')
            })
            logger.warning(alert_message)
    
    return alerts

def detect_resource_deletions(logs):
    """Detect deletion of critical resources"""
    if not DETECTION_RULES.get('monitor_resource_deletions', True):
        return []
    
    alerts = []
    deletion_events = [
        'DeleteBucket', 'TerminateInstances', 'DeleteDBInstance',
        'DeleteTable', 'DeleteFunction', 'DeleteStack'
    ]
    
    for log in logs:
        event_name = log.get('EventName', '')
        if event_name in deletion_events:
            user = log.get('Username', 'unknown')
            resources = log.get('Resources', [])
            resource_name = resources[0].get('ResourceName', 'unknown') if resources else 'unknown'
            
            alert_message = f"🗑️ RESOURCE DELETION: {event_name} on {resource_name} by {user}"
            alerts.append({
                'type': 'RESOURCE_DELETION',
                'severity': 'HIGH',
                'message': alert_message,
                'timestamp': log.get('EventTime'),
                'user': user,
                'resource': resource_name,
                'event': event_name,
                'region': log.get('MonitoredRegion', 'unknown')
            })
            logger.error(alert_message)
    
    return alerts

def detect_cloudtrail_disabled(logs):
    """Detect if CloudTrail logging is disabled"""
    if not DETECTION_RULES.get('monitor_cloudtrail_disabled', True):
        return []
    
    alerts = []
    for log in logs:
        event_name = log.get('EventName', '')
        if event_name in ['StopLogging', 'DeleteTrail', 'UpdateTrail']:
            user = log.get('Username', 'unknown')
            alert_message = f"🚨 CLOUDTRAIL TAMPERING: {event_name} by {user} at {log.get('EventTime')}"
            alerts.append({
                'type': 'CLOUDTRAIL_DISABLED',
                'severity': 'CRITICAL',
                'message': alert_message,
                'timestamp': log.get('EventTime'),
                'user': user,
                'event': event_name,
                'region': log.get('MonitoredRegion', 'unknown')
            })
            logger.critical(alert_message)
    
    return alerts

def detect_api_anomalies(logs):
    """Detect API call frequency anomalies using Isolation Forest"""
    api_call_counts = extract_api_call_counts(logs)

    if api_call_counts.size == 0:
        logger.info("No API call counts available for anomaly detection.")
        return []

    model = IsolationForest(contamination=0.1)
    model.fit(api_call_counts)
    predictions = model.predict(api_call_counts)

    anomaly_alerts = []
    for i, prediction in enumerate(predictions):
        if prediction == -1:  # -1 indicates an anomaly
            anomaly_message = f"📊 API Anomaly detected: Unusual API call pattern (count: {api_call_counts[i][0]})"
            anomaly_alerts.append({
                'type': 'API_ANOMALY',
                'severity': 'MEDIUM',
                'message': anomaly_message,
                'timestamp': datetime.utcnow().isoformat(),
                'api_count': int(api_call_counts[i][0])
            }
    """Detect if an S3 bucket becomes public"""
    alerts = []
    for log in logs:
        if 'S3BucketPublicAccess' in log.get('EventName', ''):
            bucket_name = log.get('Resources', [{}])[0].get('ResourceName', 'unknown')
            alert_message = f"Alert: S3 Bucket {bucket_name} became public!"
            alerts.append(alert_message)
            logger.info(alert_message)
    return alerts

def detect_api_anomalies(logs):
    """Detect API call frequency anomalies using Isolation Forest"""
    api_call_counts = extract_api_call_counts(logs)

    if api_call_counts.size == 0:
        logger.info("No API call counts available for anomaly detection.")
        return []

    model = IsolationForest(contamination=0.1)
    model.fit(api_call_counts)
    predictions = model.predict(api_call_counts)

    anomaly_alerts = []
    for i, prediction in enumerate(predictions):
        if prediction == -1:  # -1 indicates an anomaly
            anomaly_message = f"Anomaly detected at index {i}, API call count: {api_call_counts[i][0]}"
            anomaly_alerts.append(anomaly_message)
            logger.info(anomaly_message)
    return anomaly_alerts

def send_alert_email(subject, body):
    """Send an email alert to the admin"""
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = os.getenv('RECEIVER_EMAIL')

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
            smtp_server.login(sender_email, email_password)
            smtp_server.sendmail(sender_email, os.getenv('RECEIVER_EMAIL'), msg.as_string())
        logger.info("Alert email sent!")
    except Exception as e:
        logger.error(f"Failed to send alert email: {e}")

def run_intrusion_detection():
    """Run the intrusion detection system"""
    # Step 1: Fetch CloudTrail logs
    logs = get_cloudtrail_logs()

    # Step 2: Run Rule-based Detection (S3 public access detection)
    rule_based_alerts = detect_public_s3_buckets(logs)

    # Step 3: Run Anomaly Detection (API anomaly detection)
    anomaly_alerts = detect_api_anomalies(logs)

    # Step 4: Send Alerts if necessary
    all_alerts = rule_based_alerts + anomaly_alerts
    if all_alerts:
        alert_body = "\n".join(all_alerts)
        send_alert_email("Cloud Intrusion Detection Alert", alert_body)
    else:
        logger.info("No alerts generated. System is normal.")

# Run the IDS system
if __name__ == "__main__":
    run_intrusion_detection()

