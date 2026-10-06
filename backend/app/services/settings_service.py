"""Persisted System Configuration and Anomaly Detection Threshold Service."""
import logging
from typing import Any

from sqlalchemy.orm import Session

from app.models.system_setting import SystemSetting
from app.services.forensic_audit import record_audit

logger = logging.getLogger("tactic.settings")

DEFAULT_ANOMALY_THRESHOLD = 0.80
DEFAULT_TIMEZONE = "UTC"
DEFAULT_CORRELATION_WEIGHTS = {"time": 0.30, "entity": 0.35, "source": 0.15, "event": 0.20}
DEFAULT_CORRELATION_TIME_WINDOW = 3600 # 1 hour in seconds
DEFAULT_FORENSIC_CHUNK_SIZE = 1000


def get_forensic_chunk_size(db: Session | None = None) -> int:
    """Retrieve configurable streaming chunk size for large forensic processing (default: 1000 items)."""
    if db is None:
        return DEFAULT_FORENSIC_CHUNK_SIZE
    try:
        setting = db.query(SystemSetting).filter(SystemSetting.key == "forensic_chunk_size").first()
        if setting and setting.value:
            val = int(setting.value)
            if val > 0:
                return val
    except Exception as exc:
        logger.warning("Failed loading forensic chunk size; using default: %s", exc)
    return DEFAULT_FORENSIC_CHUNK_SIZE


def get_anomaly_threshold(db: Session | None = None) -> float:
    """Retrieve current persisted anomaly detection threshold (default: 0.80)."""
    if db is None:
        return DEFAULT_ANOMALY_THRESHOLD
    try:
        setting = db.query(SystemSetting).filter(SystemSetting.key == "anomaly_threshold").first()
        if setting and setting.value:
            val = float(setting.value)
            if 0.0 <= val <= 1.0:
                return val
    except Exception as exc:
        logger.warning("Failed loading persisted anomaly threshold; using default 0.80: %s", exc)
    return DEFAULT_ANOMALY_THRESHOLD


def get_correlation_config(db: Session | None = None) -> dict[str, Any]:
    """Retrieve persisted cross-evidence correlation weights and time window."""
    weights = dict(DEFAULT_CORRELATION_WEIGHTS)
    window = DEFAULT_CORRELATION_TIME_WINDOW
    if db is None:
        return {"weights": weights, "time_window_seconds": window}

    try:
        import json
        w_setting = db.query(SystemSetting).filter(SystemSetting.key == "correlation_weights").first()
        if w_setting and w_setting.value:
            parsed_w = json.loads(w_setting.value)
            if isinstance(parsed_w, dict):
                for k in weights:
                    if k in parsed_w and isinstance(parsed_w[k], (int, float)) and 0.0 <= parsed_w[k] <= 1.0:
                        weights[k] = float(parsed_w[k])

        win_setting = db.query(SystemSetting).filter(SystemSetting.key == "correlation_time_window_seconds").first()
        if win_setting and win_setting.value:
            parsed_win = int(win_setting.value)
            if parsed_win > 0:
                window = parsed_win
    except Exception as exc:
        logger.warning("Failed loading correlation config; using defaults: %s", exc)

    return {"weights": weights, "time_window_seconds": window}


def get_system_settings(db: Session) -> dict[str, Any]:
    """Retrieve full system settings dictionary including anomaly threshold, timezone, and correlation weights."""
    threshold = get_anomaly_threshold(db)
    corr_cfg = get_correlation_config(db)
    
    tz_setting = db.query(SystemSetting).filter(SystemSetting.key == "default_timezone").first()
    default_tz = tz_setting.value if tz_setting and tz_setting.value else DEFAULT_TIMEZONE

    return {
        "anomaly_threshold": round(threshold, 4),
        "anomaly_threshold_default": DEFAULT_ANOMALY_THRESHOLD,
        "anomaly_threshold_label": f"Configurable Default ({DEFAULT_ANOMALY_THRESHOLD:.2f})",
        "default_timezone": default_tz,
        "correlation_weights": corr_cfg["weights"],
        "correlation_time_window_seconds": corr_cfg["time_window_seconds"]
    }


def update_system_settings(
    db: Session,
    payload: dict[str, Any],
    actor_id: int | None = None
) -> dict[str, Any]:
    """Validate and persist system configuration changes with durable audit logging."""
    old_settings = get_system_settings(db)
    audit_details = {}

    if "anomaly_threshold" in payload and payload["anomaly_threshold"] is not None:
        raw_val = payload["anomaly_threshold"]
        try:
            val = float(raw_val)
        except (ValueError, TypeError):
            raise ValueError(f"Anomaly threshold must be a valid float number between 0.0 and 1.0 (received: '{raw_val}').")

        if val < 0.0 or val > 1.0:
            raise ValueError(f"Anomaly threshold must be between 0.0 and 1.0 (received: {val}).")

        setting = db.query(SystemSetting).filter(SystemSetting.key == "anomaly_threshold").first()
        if not setting:
            setting = SystemSetting(
                key="anomaly_threshold",
                value=str(val),
                description="Persisted anomaly detection threshold (configurable default: 0.80)."
            )
            db.add(setting)
        else:
            setting.value = str(val)

        audit_details["old_anomaly_threshold"] = old_settings["anomaly_threshold"]
        audit_details["new_anomaly_threshold"] = val
        audit_details["configurable_default"] = DEFAULT_ANOMALY_THRESHOLD

    if payload.get("default_timezone"):
        tz_val = str(payload["default_timezone"]).strip()
        setting = db.query(SystemSetting).filter(SystemSetting.key == "default_timezone").first()
        if not setting:
            setting = SystemSetting(
                key="default_timezone",
                value=tz_val,
                description="Default system timezone configuration."
            )
            db.add(setting)
        else:
            setting.value = tz_val

        audit_details["old_default_timezone"] = old_settings["default_timezone"]
        audit_details["new_default_timezone"] = tz_val

    if payload.get("correlation_weights"):
        import json
        weights = payload["correlation_weights"]
        if not isinstance(weights, dict):
            raise ValueError("correlation_weights must be a dictionary with keys: time, entity, source, event.")
        
        valid_keys = {"time", "entity", "source", "event"}
        clean_weights = {}
        for k in valid_keys:
            if k in weights:
                try:
                    w_val = float(weights[k])
                    if w_val < 0.0 or w_val > 1.0:
                        raise ValueError
                    clean_weights[k] = w_val
                except (ValueError, TypeError):
                    raise ValueError(f"Correlation weight for '{k}' must be a float between 0.0 and 1.0.")
            else:
                clean_weights[k] = DEFAULT_CORRELATION_WEIGHTS[k]

        setting = db.query(SystemSetting).filter(SystemSetting.key == "correlation_weights").first()
        if not setting:
            setting = SystemSetting(
                key="correlation_weights",
                value=json.dumps(clean_weights),
                description="Persisted cross-evidence correlation formula weights."
            )
            db.add(setting)
        else:
            setting.value = json.dumps(clean_weights)

        audit_details["new_correlation_weights"] = clean_weights

    if "correlation_time_window_seconds" in payload and payload["correlation_time_window_seconds"] is not None:
        try:
            win_val = int(payload["correlation_time_window_seconds"])
            if win_val <= 0:
                raise ValueError
        except (ValueError, TypeError):
            raise ValueError("correlation_time_window_seconds must be a positive integer > 0.")

        setting = db.query(SystemSetting).filter(SystemSetting.key == "correlation_time_window_seconds").first()
        if not setting:
            setting = SystemSetting(
                key="correlation_time_window_seconds",
                value=str(win_val),
                description="Persisted cross-evidence correlation time window in seconds."
            )
            db.add(setting)
        else:
            setting.value = str(win_val)

        audit_details["new_correlation_time_window_seconds"] = win_val

    db.flush()

    if audit_details:
        msg_parts = []
        if "new_anomaly_threshold" in audit_details:
            msg_parts.append(f"anomaly threshold from {audit_details['old_anomaly_threshold']} to {audit_details['new_anomaly_threshold']} (default: 0.80)")
        if "new_default_timezone" in audit_details:
            msg_parts.append(f"default timezone to '{audit_details['new_default_timezone']}'")
        if "new_correlation_weights" in audit_details:
            msg_parts.append(f"correlation weights to {audit_details['new_correlation_weights']}")
        if "new_correlation_time_window_seconds" in audit_details:
            msg_parts.append(f"correlation time window to {audit_details['new_correlation_time_window_seconds']}s")

        audit_msg = f"Updated system configuration: {'; '.join(msg_parts)}."
        record_audit(
            db=db,
            action="SETTINGS_UPDATED",
            description=audit_msg,
            actor_id=actor_id,
            details=audit_details
        )

    db.commit()
    return get_system_settings(db)
