import os
import sys
import unittest
from datetime import datetime, timedelta, timezone


sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from alert_service import (
    AlertChannel,
    AlertConfig,
    AlertNotification,
    AlertProblem,
    AlertService,
    CHANNEL_FAILURE_COOLDOWNS,
    NotificationResult,
    PostgresIncidentRepository,
    build_alert_body,
    build_notification_fingerprint,
    notification_fingerprint_has_specific_context,
    notification_with_channel_template,
)


FIXED_NOW = datetime(2026, 4, 27, 12, 0, tzinfo=timezone.utc)


class FakeSender:
    def __init__(self, fail=False):
        self.fail = fail
        self.sent = []

    def send(self, notification):
        if self.fail:
            raise RuntimeError("send failed")
        self.sent.append(notification)


class InMemoryIncidentRepository:
    def __init__(self):
        self.incidents = []
        self.notification_results = []
        self.alert_channels = []
        self.next_id = 1

    def find_open_incident(self, problem):
        fingerprint = build_notification_fingerprint(problem)
        fingerprint_specific = notification_fingerprint_has_specific_context(fingerprint)

        def stored_fingerprint(item):
            details = item.get("details") if isinstance(item.get("details"), dict) else {}
            return str(
                item.get("notification_fingerprint")
                or details.get("notification_fingerprint")
                or details.get("incident_fingerprint")
                or details.get("loop_fingerprint")
                or details.get("fingerprint")
                or ""
            ).lower()

        matches = [
            item
            for item in self.incidents
            if str(item["status"]).lower() in {"open", "acknowledged"}
            and item["device_ip"] == problem.device_ip
            and (
                (fingerprint and stored_fingerprint(item) == fingerprint)
                or (
                    (not fingerprint_specific or not stored_fingerprint(item))
                    and item["problem_type"].upper() == problem.problem_type
                )
            )
        ]
        matches.sort(key=lambda item: item["last_detected_at"], reverse=True)
        matches.sort(key=lambda item: 0 if fingerprint and stored_fingerprint(item) == fingerprint else 1)
        return matches[0] if matches else None

    def create_incident(self, problem, detected_at):
        fingerprint = build_notification_fingerprint(problem)
        incident = {
            "id": self.next_id,
            "opened_at": detected_at,
            "last_seen_at": detected_at,
            "status": "open",
            "hostname": problem.device_name,
            "src_ip": problem.device_ip,
            "incident_type": problem.problem_type.lower(),
            "key": f"alert|{problem.device_ip}|{problem.problem_type.lower()}",
            "severity": problem.severity.lower(),
            "title": "[NetGuard] Alerta critico detectado",
            "details": {"notification_fingerprint": fingerprint},
            "asset_id": None,
            "device_name": problem.device_name,
            "device_ip": problem.device_ip,
            "problem_type": problem.problem_type,
            "description": problem.description,
            "first_detected_at": detected_at,
            "last_detected_at": detected_at,
            "resolved_at": None,
            "notification_sent": False,
            "opening_notification_sent": False,
            "opening_notified_at": None,
            "recovery_notification_sent": False,
            "recovery_notified_at": None,
            "last_notification_at": None,
            "notification_fingerprint": fingerprint,
            "created_at": detected_at,
            "updated_at": detected_at,
        }
        self.next_id += 1
        self.incidents.append(incident)
        return incident

    def touch_incident_detection(self, incident_id, detected_at):
        incident = self._get(incident_id)
        incident["last_seen_at"] = detected_at
        incident["last_detected_at"] = detected_at
        incident["updated_at"] = detected_at
        return incident

    def update_incident_for_notification(self, incident_id, problem, detected_at):
        incident = self._get(incident_id)
        incident.update(
            {
                "last_seen_at": detected_at,
                "last_detected_at": detected_at,
                "updated_at": detected_at,
                "device_name": problem.device_name,
                "device_ip": problem.device_ip,
                "hostname": problem.device_name,
                "src_ip": problem.device_ip,
                "problem_type": problem.problem_type,
                "incident_type": problem.problem_type.lower(),
                "description": problem.description,
                "severity": problem.severity.lower(),
                "notification_fingerprint": incident.get("notification_fingerprint")
                or build_notification_fingerprint(problem),
            }
        )
        incident.setdefault("details", {})["notification_fingerprint"] = incident["notification_fingerprint"]
        return incident

    def mark_notification_sent(self, incident_id, sent, sent_at):
        incident = self._get(incident_id)
        incident["notification_sent"] = bool(incident.get("notification_sent")) or bool(sent)
        incident["opening_notification_sent"] = bool(incident.get("opening_notification_sent")) or bool(sent)
        if sent and incident.get("opening_notified_at") is None:
            incident["opening_notified_at"] = sent_at
        if sent:
            incident["last_notification_at"] = sent_at
        incident["updated_at"] = sent_at
        return incident

    def mark_recovery_notification_sent(self, incident_id, sent_at):
        incident = self._get(incident_id)
        incident["recovery_notification_sent"] = True
        incident["recovery_notified_at"] = incident.get("recovery_notified_at") or sent_at
        incident["last_notification_at"] = sent_at
        incident["updated_at"] = sent_at
        return incident

    def mark_recovery_notification_suppressed(self, incident_id, suppressed_at, reason):
        incident = self._get(incident_id)
        incident.setdefault("details", {})["recovery_notification_suppressed"] = True
        incident.setdefault("details", {})["recovery_notification_suppression_reason"] = reason
        incident["updated_at"] = suppressed_at
        return incident

    def record_notification_result(self, incident_id, result, sent_at):
        self.notification_results.append((incident_id, result, sent_at))

    def find_recent_notification(self, incident_id, since):
        matches = [
            (stored_incident_id, result, sent_at)
            for stored_incident_id, result, sent_at in self.notification_results
            if stored_incident_id == incident_id and sent_at >= since
        ]
        matches.sort(key=lambda item: item[2], reverse=True)
        if not matches:
            return None
        _, result, sent_at = matches[0]
        return {
            "incident_id": incident_id,
            "channel": result.channel,
            "provider": result.provider,
            "delivery_status": result.status,
            "error": result.error,
            "sent_at": sent_at,
        }

    def find_recent_equivalent_notification(self, problem, since):
        fingerprint = build_notification_fingerprint(problem)
        matches = []
        for stored_incident_id, result, sent_at in self.notification_results:
            if sent_at < since or result.status != "success" or (result.provider or "").lower() == "anti_spam":
                continue
            incident = self._get(stored_incident_id)
            if not incident:
                continue
            details = incident.get("details") if isinstance(incident.get("details"), dict) else {}
            stored_fingerprint = str(
                incident.get("notification_fingerprint")
                or details.get("notification_fingerprint")
                or details.get("incident_fingerprint")
                or details.get("loop_fingerprint")
                or details.get("fingerprint")
                or ""
            ).lower()
            same_problem = incident["device_ip"] == problem.device_ip and incident["problem_type"].upper() == problem.problem_type
            if stored_fingerprint == fingerprint or same_problem:
                matches.append((stored_incident_id, result, sent_at))
        matches.sort(key=lambda item: item[2], reverse=True)
        if not matches:
            return None
        incident_id, result, sent_at = matches[0]
        return {
            "incident_id": incident_id,
            "channel": result.channel,
            "provider": result.provider,
            "delivery_status": result.status,
            "error": result.error,
            "sent_at": sent_at,
        }

    def list_active_channels(self):
        return [channel for channel in self.alert_channels if channel.enabled]

    def has_configured_channels(self):
        return bool(self.alert_channels)

    def has_successful_notification(self, incident_id):
        return any(
            stored_incident_id == incident_id
            and result.status == "success"
            and (result.provider or "").lower() != "anti_spam"
            for stored_incident_id, result, _ in self.notification_results
        )

    def resolve_incident(self, incident_id, resolved_at):
        incident = self._get(incident_id)
        incident["status"] = "resolved"
        incident["resolved_at"] = resolved_at
        incident["last_seen_at"] = resolved_at
        incident["updated_at"] = resolved_at
        return incident

    def get_incident(self, incident_id):
        return self._get(incident_id)

    def _get(self, incident_id):
        for incident in self.incidents:
            if incident["id"] == incident_id:
                return incident
        return None


def sample_problem(severity="HIGH"):
    return AlertProblem(
        device_name="Switch-Core-01",
        device_ip="192.168.0.10",
        problem_type="INTERFACE_DOWN",
        description="Interface Gi1/0/24 indisponivel",
        severity=severity,
    )


def loop_problem(interface_pair="Gi0/5<->Gi0/20", severity="CRITICAL", detected_at=None):
    return AlertProblem(
        device_name="Switch Lab",
        device_ip="192.168.56.1",
        problem_type="LOOP_RISK",
        description=f"Risco de loop L2 em {interface_pair}",
        severity=severity,
        detected_at=detected_at,
        details={
            "interface_pair": interface_pair,
            "vlan": "VLAN0001",
            "incident_fingerprint": f"192.168.56.1|LOOP_RISK|{interface_pair}|VLAN0001",
        },
    )


def make_service(repo, config=None, email_sender=None, webhook_sender=None):
    return AlertService(
        repo,
        config or AlertConfig(),
        email_sender=email_sender or FakeSender(),
        webhook_sender=webhook_sender or FakeSender(),
        clock=lambda: FIXED_NOW,
    )


class AlertServiceTest(unittest.TestCase):
    def setUp(self):
        CHANNEL_FAILURE_COOLDOWNS.clear()
        self._previous_alert_ollama_enabled = os.environ.get("ALERT_OLLAMA_ENABLED")
        os.environ["ALERT_OLLAMA_ENABLED"] = "false"

    def tearDown(self):
        if self._previous_alert_ollama_enabled is None:
            os.environ.pop("ALERT_OLLAMA_ENABLED", None)
        else:
            os.environ["ALERT_OLLAMA_ENABLED"] = self._previous_alert_ollama_enabled

    def test_creates_new_incident(self):
        repo = InMemoryIncidentRepository()
        service = make_service(repo)

        result = service.handle_problem(sample_problem())

        self.assertTrue(result.created)
        self.assertFalse(result.updated)
        self.assertFalse(result.notification_sent)
        self.assertEqual(repo.incidents[0]["device_ip"], "192.168.0.10")
        self.assertEqual(repo.incidents[0]["problem_type"], "INTERFACE_DOWN")

    def test_updates_open_incident_and_suppresses_repeated_alert_inside_window(self):
        repo = InMemoryIncidentRepository()
        old_incident = repo.create_incident(sample_problem(), FIXED_NOW - timedelta(minutes=5))
        email_sender = FakeSender()
        service = make_service(repo, AlertConfig(email_enabled=True), email_sender=email_sender)

        result = service.handle_problem(sample_problem())

        self.assertFalse(result.created)
        self.assertTrue(result.updated)
        self.assertTrue(result.notification_suppressed)
        self.assertFalse(result.notification_sent)
        self.assertEqual(old_incident["last_detected_at"], FIXED_NOW)
        self.assertEqual(len(email_sender.sent), 0)
        self.assertEqual(repo.notification_results[0][1].status, "suppressed")

    def test_sends_again_when_open_incident_is_outside_anti_spam_window(self):
        repo = InMemoryIncidentRepository()
        repo.create_incident(sample_problem(), FIXED_NOW - timedelta(minutes=11))
        email_sender = FakeSender()
        service = make_service(repo, AlertConfig(email_enabled=True), email_sender=email_sender)

        result = service.handle_problem(sample_problem())

        self.assertFalse(result.created)
        self.assertTrue(result.updated)
        self.assertFalse(result.notification_suppressed)
        self.assertTrue(result.notification_sent)
        self.assertEqual(len(email_sender.sent), 1)
        self.assertEqual(repo.notification_results[0][1].provider, "email")

    def test_does_not_resend_opening_for_already_notified_active_incident(self):
        repo = InMemoryIncidentRepository()
        incident = repo.create_incident(sample_problem(), FIXED_NOW - timedelta(hours=2))
        repo.mark_notification_sent(incident["id"], True, FIXED_NOW - timedelta(hours=2))
        email_sender = FakeSender()
        service = make_service(repo, AlertConfig(email_enabled=True), email_sender=email_sender)

        result = service.handle_problem(
            AlertProblem(
                device_name="Switch-Core-01",
                device_ip="192.168.0.10",
                problem_type="INTERFACE_DOWN",
                description="Interface Gi1/0/24 ainda indisponivel",
                severity="HIGH",
                detected_at=FIXED_NOW,
            )
        )

        self.assertFalse(result.created)
        self.assertTrue(result.updated)
        self.assertTrue(result.notification_suppressed)
        self.assertFalse(result.notification_sent)
        self.assertEqual(len(email_sender.sent), 0)
        self.assertEqual(len(repo.incidents), 1)
        self.assertEqual(repo.get_incident(incident["id"])["last_detected_at"], FIXED_NOW)

    def test_severity_escalation_notifies_inside_anti_spam_window(self):
        repo = InMemoryIncidentRepository()
        old_incident = repo.create_incident(sample_problem("HIGH"), FIXED_NOW - timedelta(minutes=1))
        repo.mark_notification_sent(old_incident["id"], True, FIXED_NOW - timedelta(minutes=1))
        email_sender = FakeSender()
        service = make_service(repo, AlertConfig(email_enabled=True), email_sender=email_sender)

        result = service.handle_problem(sample_problem("CRITICAL"))

        self.assertFalse(result.created)
        self.assertTrue(result.updated)
        self.assertFalse(result.notification_suppressed)
        self.assertTrue(result.notification_sent)
        self.assertEqual(old_incident["severity"], "critical")
        self.assertEqual(len(email_sender.sent), 1)

    def test_reuses_open_incident_with_same_notification_fingerprint(self):
        repo = InMemoryIncidentRepository()
        email_sender = FakeSender()
        service = make_service(repo, AlertConfig(email_enabled=True), email_sender=email_sender)

        first = service.handle_problem(loop_problem())
        second_problem = loop_problem(detected_at=FIXED_NOW + timedelta(minutes=11))
        second = service.handle_problem(second_problem)

        self.assertTrue(first.created)
        self.assertFalse(second.created)
        self.assertTrue(second.updated)
        self.assertEqual(first.incident["id"], second.incident["id"])
        self.assertEqual(len(repo.incidents), 1)

    def test_different_interface_fingerprint_creates_separate_incident(self):
        repo = InMemoryIncidentRepository()
        service = make_service(repo)

        first = service.handle_problem(loop_problem("Gi0/5<->Gi0/20"))
        second_problem = loop_problem("Gi0/7<->Gi0/8", detected_at=FIXED_NOW + timedelta(minutes=1))
        second = service.handle_problem(second_problem)

        self.assertTrue(first.created)
        self.assertTrue(second.created)
        self.assertNotEqual(first.incident["id"], second.incident["id"])
        self.assertEqual(len(repo.incidents), 2)

    def test_acknowledged_incident_is_still_active_for_anti_spam(self):
        repo = InMemoryIncidentRepository()
        incident = repo.create_incident(sample_problem(), FIXED_NOW - timedelta(minutes=3))
        incident["status"] = "ACKNOWLEDGED"
        email_sender = FakeSender()
        service = make_service(repo, AlertConfig(email_enabled=True), email_sender=email_sender)

        result = service.handle_problem(sample_problem())

        self.assertTrue(result.notification_suppressed)
        self.assertEqual(len(email_sender.sent), 0)

    def test_resolved_incident_is_not_active_for_anti_spam(self):
        repo = InMemoryIncidentRepository()
        incident = repo.create_incident(sample_problem(), FIXED_NOW - timedelta(minutes=3))
        incident["status"] = "resolved"
        email_sender = FakeSender()
        service = make_service(repo, AlertConfig(email_enabled=True), email_sender=email_sender)

        result = service.handle_problem(sample_problem())

        self.assertTrue(result.created)
        self.assertEqual(len(repo.incidents), 2)
        self.assertTrue(result.notification_sent)
        self.assertEqual(len(email_sender.sent), 1)

    def test_sends_email_when_enabled(self):
        repo = InMemoryIncidentRepository()
        email_sender = FakeSender()
        service = make_service(repo, AlertConfig(email_enabled=True), email_sender=email_sender)

        result = service.handle_problem(sample_problem())

        self.assertTrue(result.notification_sent)
        self.assertEqual(len(email_sender.sent), 1)
        self.assertIn("Switch-Core-01", email_sender.sent[0].body)

    def test_sends_webhook_when_enabled(self):
        repo = InMemoryIncidentRepository()
        webhook_sender = FakeSender()
        config = AlertConfig(webhook_enabled=True, webhook_provider="discord")
        service = make_service(repo, config, webhook_sender=webhook_sender)

        result = service.handle_problem(sample_problem())

        self.assertTrue(result.notification_sent)
        self.assertEqual(len(webhook_sender.sent), 1)
        self.assertEqual(result.notification_results[0].provider, "discord")

    def test_configured_channel_respects_min_severity(self):
        repo = InMemoryIncidentRepository()
        repo.alert_channels.append(
            AlertChannel(
                id=1,
                name="Discord Critico",
                provider="discord",
                enabled=True,
                min_severity="CRITICAL",
                config={"webhook_url": ""},
            )
        )
        service = make_service(repo)

        result = service.handle_problem(sample_problem("HIGH"))

        self.assertTrue(result.created)
        self.assertFalse(result.notification_sent)
        self.assertEqual(repo.notification_results, [])

    def test_disabled_configured_channel_does_not_use_env_fallback(self):
        repo = InMemoryIncidentRepository()
        repo.alert_channels.append(
            AlertChannel(
                id=1,
                name="Email Infra",
                provider="email",
                enabled=False,
                min_severity="LOW",
                config={},
            )
        )
        email_sender = FakeSender()
        service = make_service(repo, AlertConfig(email_enabled=True), email_sender=email_sender)

        result = service.handle_problem(sample_problem())

        self.assertTrue(result.created)
        self.assertFalse(result.notification_sent)
        self.assertEqual(len(email_sender.sent), 0)
        self.assertEqual(repo.notification_results, [])

    def test_configured_channel_failure_does_not_block_incident_creation(self):
        repo = InMemoryIncidentRepository()
        repo.alert_channels.append(
            AlertChannel(
                id=1,
                name="Discord NOC",
                provider="discord",
                enabled=True,
                min_severity="LOW",
                config={"webhook_url": ""},
            )
        )
        service = make_service(repo)

        result = service.handle_problem(sample_problem())

        self.assertTrue(result.created)
        self.assertFalse(result.notification_sent)
        self.assertEqual(repo.notification_results[0][1].channel, "Discord NOC")
        self.assertEqual(repo.notification_results[0][1].status, "failed")

    def test_failed_channel_enters_cooldown(self):
        repo = InMemoryIncidentRepository()
        service = make_service(repo)
        notification = AlertNotification(
            title="Teste",
            body="Mensagem",
            problem=sample_problem(),
            incident_id=99,
            timestamp=FIXED_NOW,
            status="OPEN",
        )
        failing_sender = FakeSender(fail=True)
        healthy_sender = FakeSender()

        first = service._send_channel("Telegram Alertas", "telegram", failing_sender, notification)
        second = service._send_channel("Telegram Alertas", "telegram", healthy_sender, notification)

        self.assertEqual(first.status, "failed")
        self.assertEqual(second.status, "failed")
        self.assertIn("cooldown", second.error)
        self.assertEqual(len(healthy_sender.sent), 0)

    def test_supports_additional_webhook_media_channels(self):
        repo = InMemoryIncidentRepository()
        repo.alert_channels.append(
            AlertChannel(
                id=1,
                name="Slack NOC",
                provider="slack",
                enabled=True,
                min_severity="LOW",
                config={"webhook_url": ""},
            )
        )
        service = make_service(repo)

        result = service.handle_problem(sample_problem())

        self.assertTrue(result.created)
        self.assertFalse(result.notification_sent)
        self.assertEqual(repo.notification_results[0][1].provider, "slack")
        self.assertEqual(repo.notification_results[0][1].status, "failed")

    def test_resolves_incident(self):
        repo = InMemoryIncidentRepository()
        incident = repo.create_incident(sample_problem(), FIXED_NOW - timedelta(minutes=20))
        service = make_service(repo)

        result = service.resolve_incident(incident["id"])

        self.assertIsNotNone(result)
        self.assertEqual(incident["status"], "resolved")
        self.assertEqual(incident["resolved_at"], FIXED_NOW)
        self.assertFalse(result.notification_sent)

    def test_sends_recovery_once_when_opening_was_notified(self):
        repo = InMemoryIncidentRepository()
        email_sender = FakeSender()
        service = make_service(repo, AlertConfig(email_enabled=True), email_sender=email_sender)

        opened = service.handle_problem(sample_problem("CRITICAL"))
        recovered = service.resolve_incident(opened.incident["id"], send_recovery_notification=True)
        duplicate = service.resolve_incident(opened.incident["id"], send_recovery_notification=True)

        self.assertTrue(opened.notification_sent)
        self.assertTrue(recovered.notification_sent)
        self.assertFalse(duplicate.notification_sent)
        self.assertTrue(repo.get_incident(opened.incident["id"])["recovery_notification_sent"])
        self.assertEqual(len(email_sender.sent), 2)
        self.assertTrue(email_sender.sent[1].recovery)

    def test_loop_lifecycle_sends_one_opening_and_one_recovery(self):
        repo = InMemoryIncidentRepository()
        email_sender = FakeSender()
        service = make_service(repo, AlertConfig(email_enabled=True), email_sender=email_sender)

        opened = service.handle_problem(loop_problem(detected_at=FIXED_NOW - timedelta(minutes=30)))
        repeated = service.handle_problem(loop_problem(detected_at=FIXED_NOW - timedelta(minutes=1)))
        recovered = service.resolve_incident(opened.incident["id"], send_recovery_notification=True)
        duplicate_recovery = service.resolve_incident(opened.incident["id"], send_recovery_notification=True)

        self.assertTrue(opened.created)
        self.assertTrue(opened.notification_sent)
        self.assertFalse(repeated.created)
        self.assertTrue(repeated.updated)
        self.assertTrue(repeated.notification_suppressed)
        self.assertTrue(recovered.notification_sent)
        self.assertFalse(duplicate_recovery.notification_sent)
        self.assertEqual(len(repo.incidents), 1)
        self.assertEqual(len(email_sender.sent), 2)
        self.assertFalse(email_sender.sent[0].recovery)
        self.assertTrue(email_sender.sent[1].recovery)

    def test_does_not_send_recovery_when_opening_was_not_notified(self):
        repo = InMemoryIncidentRepository()
        incident = repo.create_incident(sample_problem("CRITICAL"), FIXED_NOW - timedelta(minutes=20))
        email_sender = FakeSender()
        service = make_service(repo, AlertConfig(email_enabled=True), email_sender=email_sender)

        result = service.resolve_incident(incident["id"], send_recovery_notification=True)

        self.assertTrue(result.notification_suppressed)
        self.assertFalse(result.notification_sent)
        self.assertEqual(len(email_sender.sent), 0)

    def test_recovery_lifecycle_applies_to_common_problem_types(self):
        problem_types = [
            "HOST_DOWN",
            "ICMP_COLLECTION_SILENCE",
            "SNMP_COLLECTION_SILENCE",
            "LOOP_RISK",
            "INTERFACE_DOWN",
            "LINK_FLAP",
            "MAC_FLAPPING",
            "BROADCAST_STORM",
            "SYSLOG_CRITICAL",
        ]

        for problem_type in problem_types:
            with self.subTest(problem_type=problem_type):
                repo = InMemoryIncidentRepository()
                email_sender = FakeSender()
                service = make_service(repo, AlertConfig(email_enabled=True), email_sender=email_sender)
                problem = AlertProblem(
                    device_name="Switch Lab",
                    device_ip="192.168.56.1",
                    problem_type=problem_type,
                    description=f"Teste de ciclo para {problem_type}",
                    severity="CRITICAL",
                    details={"interface": "Gi0/5"},
                )

                opened = service.handle_problem(problem)
                recovered = service.resolve_incident(opened.incident["id"], send_recovery_notification=True)
                duplicate = service.resolve_incident(opened.incident["id"], send_recovery_notification=True)

                self.assertTrue(opened.notification_sent)
                self.assertTrue(recovered.notification_sent)
                self.assertFalse(duplicate.notification_sent)
                self.assertEqual(len(email_sender.sent), 2)
                self.assertTrue(email_sender.sent[1].recovery)

    def test_syslog_recovery_does_not_default_to_interface_up(self):
        problem = AlertProblem(
            device_name="Switch Lab",
            device_ip="192.168.56.20",
            problem_type="SYSLOG_LOOP_GI0_23",
            description="STP desabilitado loop permanece em forwarding entre Gi0/23 e Gi0/24",
            severity="CRITICAL",
        )
        incident = {
            "id": 953,
            "opened_at": FIXED_NOW - timedelta(minutes=5),
            "resolved_at": FIXED_NOW,
            "details": {"source": "syslog_signal", "group_name": "lab"},
        }

        body = build_alert_body(problem, FIXED_NOW, "RESOLVED", incident=incident, recovery=True)

        self.assertIn("Status atual: Evento syslog encerrado", body)
        self.assertNotIn("Status atual: Up (1)", body)

    def test_explicit_loop_recovery_value_is_used(self):
        problem = AlertProblem(
            device_name="Switch Lab",
            device_ip="192.168.56.20",
            problem_type="LOOP_RISK",
            description="Risco de loop L2",
            severity="CRITICAL",
        )
        incident = {
            "id": 952,
            "opened_at": FIXED_NOW - timedelta(minutes=5),
            "resolved_at": FIXED_NOW,
            "details": {"recovery_value": "Loop Guard bloqueou a condicao de loop em Gi0/23"},
        }

        body = build_alert_body(problem, FIXED_NOW, "RESOLVED", incident=incident, recovery=True)

        self.assertIn("Status atual: Loop Guard bloqueou a condicao de loop em Gi0/23", body)

    def test_notifies_existing_operational_incident(self):
        repo = InMemoryIncidentRepository()
        incident = repo.create_incident(sample_problem("CRITICAL"), FIXED_NOW - timedelta(minutes=20))
        incident["status"] = "OPEN"
        incident["severity"] = "critical"
        incident["problem_type"] = "LOOP_RISK"
        incident["incident_type"] = "loop_risk"
        incident["device_ip"] = "192.168.56.20/32"
        incident["src_ip"] = "192.168.56.20/32"
        incident["description"] = "Correlacao entre storm e MAC flapping"
        email_sender = FakeSender()
        service = make_service(repo, AlertConfig(email_enabled=True), email_sender=email_sender)

        result = service.notify_incident(incident["id"])

        self.assertIsNotNone(result)
        self.assertTrue(result.updated)
        self.assertTrue(result.notification_sent)
        self.assertEqual(repo.notification_results[0][1].provider, "email")
        self.assertIn("Risco de loop L2", email_sender.sent[0].body)
        self.assertIn("Impacto", email_sender.sent[0].body)
        self.assertIn("recomendada", email_sender.sent[0].body)
        self.assertIn("IP: 192.168.56.20", email_sender.sent[0].body)
        self.assertNotIn("192.168.56.20/32", email_sender.sent[0].body)

    def test_notify_existing_incident_uses_anti_spam_window(self):
        repo = InMemoryIncidentRepository()
        incident = repo.create_incident(sample_problem("CRITICAL"), FIXED_NOW - timedelta(minutes=20))
        repo.record_notification_result(
            incident["id"],
            NotificationResult(channel="Email Infra", provider="email", status="success"),
            FIXED_NOW - timedelta(minutes=1),
        )
        email_sender = FakeSender()
        service = make_service(repo, AlertConfig(email_enabled=True), email_sender=email_sender)

        first = service.notify_incident(incident["id"])
        second = service.notify_incident(incident["id"])

        self.assertTrue(first.notification_suppressed)
        self.assertTrue(second.notification_suppressed)
        self.assertFalse(first.notification_sent)
        self.assertEqual(len(email_sender.sent), 0)
        self.assertEqual(len(repo.notification_results), 2)
        self.assertEqual(repo.notification_results[-1][1].provider, "anti_spam")

    def test_does_not_notify_resolved_existing_incident(self):
        repo = InMemoryIncidentRepository()
        incident = repo.create_incident(sample_problem("CRITICAL"), FIXED_NOW - timedelta(minutes=20))
        incident["status"] = "resolved"
        email_sender = FakeSender()
        service = make_service(repo, AlertConfig(email_enabled=True), email_sender=email_sender)

        result = service.notify_incident(incident["id"])

        self.assertIsNotNone(result)
        self.assertFalse(result.updated)
        self.assertFalse(result.notification_sent)
        self.assertEqual(len(email_sender.sent), 0)

    def test_default_alert_body_uses_friendly_operational_sections(self):
        problem = sample_problem("CRITICAL")

        body = build_alert_body(problem, FIXED_NOW, "OPEN")

        self.assertIn("interface", body.lower())
        self.assertIn("O que aconteceu:", body)
        self.assertIn("Impacto", body)
        self.assertIn("recomendada", body)
        self.assertIn("Evid", body)
        self.assertIn("Comandos", body)
        self.assertIn("Host: Switch-Core-01", body)
        self.assertIn("Acesse:", body)

    def test_channel_can_override_message_template(self):
        problem = sample_problem("CRITICAL")
        original = AlertNotification(
            title="[NetGuard] Problema: INTERFACE_DOWN",
            body=build_alert_body(problem, FIXED_NOW, "OPEN"),
            problem=problem,
            incident_id=123,
            status="OPEN",
            timestamp=FIXED_NOW,
            context={"device_name": "Switch-Core-01", "problem_name": "Interface down"},
        )
        channel = AlertChannel(
            id=1,
            name="Telegram",
            provider="telegram",
            enabled=True,
            min_severity="LOW",
            config={"problem_template": "Host={device_name} Problema={problem_name}"},
        )

        rendered = notification_with_channel_template(channel, original)

        self.assertEqual(rendered.body, "Host=Switch-Core-01 Problema=Interface down")

    def test_finds_text_asset_ip_without_casting_column_to_inet(self):
        class FakeCursor:
            description = None

            def __init__(self):
                self.query = ""
                self.params = ()

            def execute(self, query, params=()):
                self.query = query
                self.params = params

            def fetchone(self):
                return (42,)

        cur = FakeCursor()
        repo = PostgresIncidentRepository(cur)

        asset_id = repo.find_asset_id(sample_problem())

        self.assertEqual(asset_id, 42)
        self.assertIn("SPLIT_PART(BTRIM(ip::text), '/', 1) = %s", cur.query)
        self.assertNotIn("ip = %s::inet", cur.query)
        self.assertEqual(cur.params[0], "192.168.0.10")


if __name__ == "__main__":
    unittest.main()
