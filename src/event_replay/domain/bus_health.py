"""Real-time Sliding-Window CAN Bus Health, Load Percentage, and Jitter Anomaly Analyzer.

Provides physical-layer bit timing, rolling bus utilization calculation,
periodic message jitter tracking, and sporadic flooding anomaly detection
for Classical CAN (ISO 11898-1) and CAN-FD (ISO 11898-1:2015).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import math
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from event_replay.domain.can import CanFdFrame


class BusHealthAnomalyType(str, Enum):
    """Types of CAN bus physical and timing anomalies."""
    BUS_OVERLOAD = "BUS_OVERLOAD"
    SPORADIC_FLOODING = "SPORADIC_FLOODING"
    BABBLING_IDIOT = "BABBLING_IDIOT"
    TIMING_JITTER_VIOLATION = "TIMING_JITTER_VIOLATION"
    FRAME_TIMEOUT = "FRAME_TIMEOUT"


@dataclass(frozen=True)
class BusHealthAnomaly:
    """Anomalous bus condition detected during health evaluation."""
    anomaly_type: BusHealthAnomalyType
    timestamp_us: int
    severity: str  # "WARNING" or "CRITICAL"
    can_id: Optional[int]
    description: str
    metric_value: float
    threshold_value: float


@dataclass
class IdHealthMetrics:
    """Statistical and timing health metrics for an individual CAN arbitration ID."""
    arbitration_id: int
    is_extended: bool
    message_count: int
    total_bytes: int
    mean_cycle_ms: float = 0.0
    min_cycle_ms: float = 0.0
    max_cycle_ms: float = 0.0
    std_dev_ms: float = 0.0
    jitter_ms: float = 0.0
    jitter_pct: float = 0.0
    is_periodic: bool = False
    bus_utilization_pct: float = 0.0


@dataclass
class BusWindowSample:
    """Discrete sliding window measurement sample."""
    start_us: int
    end_us: int
    load_pct: float
    frame_count: int
    active_duration_us: float


@dataclass
class BusHealthReport:
    """Comprehensive diagnostic report summarizing bus health and anomalies."""
    total_frames: int
    duration_ms: float
    nominal_baudrate: int
    data_baudrate: int
    window_ms: float
    peak_bus_load_pct: float
    mean_bus_load_pct: float
    min_bus_load_pct: float
    id_metrics: Dict[int, IdHealthMetrics]
    anomalies: List[BusHealthAnomaly]
    window_samples: List[BusWindowSample]
    is_healthy: bool

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to serializable dictionary."""
        return {
            "total_frames": self.total_frames,
            "duration_ms": round(self.duration_ms, 3),
            "nominal_baudrate": self.nominal_baudrate,
            "data_baudrate": self.data_baudrate,
            "window_ms": self.window_ms,
            "peak_bus_load_pct": round(self.peak_bus_load_pct, 2),
            "mean_bus_load_pct": round(self.mean_bus_load_pct, 2),
            "min_bus_load_pct": round(self.min_bus_load_pct, 2),
            "is_healthy": self.is_healthy,
            "anomalies_count": len(self.anomalies),
            "anomalies": [
                {
                    "type": a.anomaly_type.value,
                    "timestamp_us": a.timestamp_us,
                    "severity": a.severity,
                    "can_id": f"0x{a.can_id:03X}" if a.can_id is not None else None,
                    "description": a.description,
                    "metric_value": round(a.metric_value, 2),
                    "threshold_value": round(a.threshold_value, 2),
                }
                for a in self.anomalies
            ],
            "id_metrics": {
                f"0x{mid:03X}": {
                    "can_id": f"0x{mid:03X}",
                    "is_extended": m.is_extended,
                    "message_count": m.message_count,
                    "total_bytes": m.total_bytes,
                    "mean_cycle_ms": round(m.mean_cycle_ms, 3),
                    "min_cycle_ms": round(m.min_cycle_ms, 3),
                    "max_cycle_ms": round(m.max_cycle_ms, 3),
                    "std_dev_ms": round(m.std_dev_ms, 3),
                    "jitter_ms": round(m.jitter_ms, 3),
                    "jitter_pct": round(m.jitter_pct, 2),
                    "is_periodic": m.is_periodic,
                    "bus_utilization_pct": round(m.bus_utilization_pct, 2),
                }
                for mid, m in sorted(self.id_metrics.items())
            },
        }


def calculate_frame_bits(frame: CanFdFrame, worst_case_stuffing: bool = False) -> Tuple[int, int]:
    """Calculate the physical bit length for a CAN/CAN-FD frame.

    Returns:
        (nominal_bits, data_bits)
        - nominal_bits: Number of bits transmitted at nominal arbitration bitrate.
        - data_bits: Number of bits transmitted at data bitrate (when BRS is active).
    """
    n_bytes = len(frame.data)

    if not frame.is_fd:
        # Classical CAN (ISO 11898-1:2003)
        if frame.is_extended_id or frame.arbitration_id > 0x7FF:
            # Extended 29-bit CAN 2.0B:
            # Fixed bits = 1 (SOF) + 34 (Arb) + 4 (Control) + 16 (CRC) + 2 (ACK) + 7 (EOF) + 3 (IFS) = 67 bits
            # Stuffed region = 1 + 34 + 4 + 8*N + 15 = 54 + 8*N
            stuffed_len = 54 + 8 * n_bytes
            stuff_divisor = 4 if worst_case_stuffing else 5
            stuff_bits = stuffed_len // stuff_divisor
            total_bits = 67 + 8 * n_bytes + stuff_bits
        else:
            # Standard 11-bit CAN 2.0A:
            # Fixed bits = 1 (SOF) + 14 (Arb) + 4 (Control) + 16 (CRC) + 2 (ACK) + 7 (EOF) + 3 (IFS) = 47 bits
            # Stuffed region = 1 + 14 + 4 + 8*N + 15 = 34 + 8*N
            stuffed_len = 34 + 8 * n_bytes
            stuff_divisor = 4 if worst_case_stuffing else 5
            stuff_bits = stuffed_len // stuff_divisor
            total_bits = 47 + 8 * n_bytes + stuff_bits
        return total_bits, 0

    else:
        # CAN-FD (ISO 11898-1:2015)
        # Arbitration / Nominal Phase:
        is_ext = frame.is_extended_id or frame.arbitration_id > 0x7FF
        nominal_fixed = 49 if is_ext else 30
        stuff_divisor = 4 if worst_case_stuffing else 5
        nom_stuff = (25 if is_ext else 15) // stuff_divisor
        total_nominal_bits = nominal_fixed + nom_stuff

        # Data Phase:
        crc_bits = 17 if n_bytes <= 16 else 21
        fixed_crc_stuff = 4 if n_bytes <= 16 else 5
        data_phase_bits = 1 + 4 + (8 * n_bytes) + crc_bits + fixed_crc_stuff

        if frame.bit_rate_switch:
            return total_nominal_bits, data_phase_bits
        else:
            return total_nominal_bits + data_phase_bits, 0


def calculate_frame_duration_us(
    frame: CanFdFrame,
    nominal_baudrate: int = 500000,
    data_baudrate: int = 2000000,
    worst_case_stuffing: bool = False,
) -> float:
    """Calculate the physical transmission duration of a CAN/CAN-FD frame in microseconds."""
    nom_bits, data_bits = calculate_frame_bits(frame, worst_case_stuffing=worst_case_stuffing)
    t_nom = nom_bits / max(1, nominal_baudrate)
    t_data = data_bits / max(1, data_baudrate) if data_bits > 0 else 0.0
    return (t_nom + t_data) * 1e6


class CanBusHealthAnalyzer:
    """Sliding-window CAN bus load analyzer and timing anomaly detector."""

    def __init__(
        self,
        nominal_baudrate: int = 500000,
        data_baudrate: int = 2000000,
        window_ms: float = 100.0,
        step_ms: float = 20.0,
        overload_threshold_pct: float = 80.0,
        jitter_threshold_pct: float = 25.0,
        min_periodic_count: int = 4,
        babbling_utilization_threshold_pct: float = 50.0,
    ) -> None:
        self.nominal_baudrate = nominal_baudrate
        self.data_baudrate = data_baudrate
        self.window_ms = max(1.0, window_ms)
        self.step_ms = max(1.0, step_ms)
        self.overload_threshold_pct = overload_threshold_pct
        self.jitter_threshold_pct = jitter_threshold_pct
        self.min_periodic_count = max(2, min_periodic_count)
        self.babbling_utilization_threshold_pct = babbling_utilization_threshold_pct

    def analyze_frames(self, frames: Sequence[CanFdFrame]) -> BusHealthReport:
        """Analyze a sequence of CAN frames and produce a comprehensive health report."""
        if not frames:
            return BusHealthReport(
                total_frames=0,
                duration_ms=0.0,
                nominal_baudrate=self.nominal_baudrate,
                data_baudrate=self.data_baudrate,
                window_ms=self.window_ms,
                peak_bus_load_pct=0.0,
                mean_bus_load_pct=0.0,
                min_bus_load_pct=0.0,
                id_metrics={},
                anomalies=[],
                window_samples=[],
                is_healthy=True,
            )

        # Sort frames strictly by timestamp_us
        sorted_frames = sorted(frames, key=lambda f: f.timestamp_us)
        t_start_us = sorted_frames[0].timestamp_us
        t_end_us = sorted_frames[-1].timestamp_us
        duration_us = max(1, t_end_us - t_start_us)
        duration_ms = duration_us / 1000.0

        # Precompute frame durations and populate per-ID collections
        id_timestamps: Dict[int, List[int]] = {}
        id_bytes: Dict[int, int] = {}
        id_ext: Dict[int, bool] = {}
        id_active_us: Dict[int, float] = {}
        frame_durations: List[float] = []

        total_bus_active_us = 0.0

        for f in sorted_frames:
            dur = calculate_frame_duration_us(
                f,
                nominal_baudrate=self.nominal_baudrate,
                data_baudrate=self.data_baudrate,
            )
            frame_durations.append(dur)
            total_bus_active_us += dur

            mid = f.arbitration_id
            if mid not in id_timestamps:
                id_timestamps[mid] = []
                id_bytes[mid] = 0
                id_ext[mid] = f.is_extended_id or (mid > 0x7FF)
                id_active_us[mid] = 0.0

            id_timestamps[mid].append(f.timestamp_us)
            id_bytes[mid] += len(f.data)
            id_active_us[mid] += dur

        # 1. Sliding Window Bus Load Calculation
        window_us = int(self.window_ms * 1000)
        step_us = int(self.step_ms * 1000)
        window_samples: List[BusWindowSample] = []
        anomalies: List[BusHealthAnomaly] = []

        curr_start = t_start_us
        frame_idx_start = 0
        frame_idx_end = 0
        n_frames = len(sorted_frames)

        # Track per-window ID load for local babbling idiot detection
        flagged_babbling_ids: set[int] = set()

        while curr_start <= t_end_us or not window_samples:
            curr_end = curr_start + window_us

            # Advance window boundaries
            while frame_idx_start < n_frames and sorted_frames[frame_idx_start].timestamp_us < curr_start:
                frame_idx_start += 1
            if frame_idx_end < frame_idx_start:
                frame_idx_end = frame_idx_start
            while frame_idx_end < n_frames and sorted_frames[frame_idx_end].timestamp_us < curr_end:
                frame_idx_end += 1

            # Compute load in this window
            window_frames = sorted_frames[frame_idx_start:frame_idx_end]
            window_durations = frame_durations[frame_idx_start:frame_idx_end]
            active_us = sum(window_durations)
            cnt = len(window_frames)
            load_pct = min(100.0, (active_us / window_us) * 100.0)

            sample = BusWindowSample(
                start_us=curr_start,
                end_us=curr_end,
                load_pct=load_pct,
                frame_count=cnt,
                active_duration_us=active_us,
            )
            window_samples.append(sample)

            # Check for window-level babbling idiot (single ID occupying >= threshold of window)
            id_win_active: Dict[int, float] = {}
            for wf, wd in zip(window_frames, window_durations):
                id_win_active[wf.arbitration_id] = id_win_active.get(wf.arbitration_id, 0.0) + wd

            for win_mid, win_active in id_win_active.items():
                win_util = (win_active / window_us) * 100.0
                if win_util >= self.babbling_utilization_threshold_pct and win_mid not in flagged_babbling_ids:
                    flagged_babbling_ids.add(win_mid)
                    anomalies.append(
                        BusHealthAnomaly(
                            anomaly_type=BusHealthAnomalyType.BABBLING_IDIOT,
                            timestamp_us=curr_start,
                            severity="CRITICAL",
                            can_id=win_mid,
                            description=(
                                f"CAN ID 0x{win_mid:03X} monopolized {win_util:.1f}% of bus capacity "
                                f"in window [{curr_start}..{curr_end}] us (threshold: {self.babbling_utilization_threshold_pct:.1f}%)"
                            ),
                            metric_value=win_util,
                            threshold_value=self.babbling_utilization_threshold_pct,
                        )
                    )

            # Check for BUS_OVERLOAD anomaly
            if load_pct >= self.overload_threshold_pct:
                anomalies.append(
                    BusHealthAnomaly(
                        anomaly_type=BusHealthAnomalyType.BUS_OVERLOAD,
                        timestamp_us=curr_start,
                        severity="CRITICAL" if load_pct >= 90.0 else "WARNING",
                        can_id=None,
                        description=(
                            f"Bus load {load_pct:.1f}% exceeded threshold "
                            f"{self.overload_threshold_pct:.1f}% in window [{curr_start}..{curr_end}] us"
                        ),
                        metric_value=load_pct,
                        threshold_value=self.overload_threshold_pct,
                    )
                )

            curr_start += step_us
            if curr_start > t_end_us and window_samples:
                break

        # Calculate bus load aggregate metrics
        loads = [s.load_pct for s in window_samples]
        peak_load = max(loads) if loads else 0.0
        mean_load = (sum(loads) / len(loads)) if loads else 0.0
        min_load = min(loads) if loads else 0.0

        # Check for SPORADIC_FLOODING (burst message count > 3x mean window frame count)
        mean_cnt = (sum(s.frame_count for s in window_samples) / len(window_samples)) if window_samples else 0.0
        if mean_cnt >= 2.0:
            for s in window_samples:
                if s.frame_count > max(10, int(mean_cnt * 3.0)):
                    anomalies.append(
                        BusHealthAnomaly(
                            anomaly_type=BusHealthAnomalyType.SPORADIC_FLOODING,
                            timestamp_us=s.start_us,
                            severity="CRITICAL",
                            can_id=None,
                            description=(
                                f"Message surge burst: {s.frame_count} frames in {self.window_ms}ms window "
                                f"(baseline average {mean_cnt:.1f} frames)"
                            ),
                            metric_value=float(s.frame_count),
                            threshold_value=mean_cnt * 3.0,
                        )
                    )

        # 2. Per-ID Timing Jitter & Anomaly Analysis
        id_metrics: Dict[int, IdHealthMetrics] = {}

        for mid, timestamps in id_timestamps.items():
            cnt = len(timestamps)
            total_b = id_bytes[mid]
            util_pct = min(100.0, (id_active_us[mid] / max(1.0, duration_us)) * 100.0)

            # Global babbling check if not already flagged in a window
            if util_pct >= self.babbling_utilization_threshold_pct and cnt >= 10 and mid not in flagged_babbling_ids:
                flagged_babbling_ids.add(mid)
                anomalies.append(
                    BusHealthAnomaly(
                        anomaly_type=BusHealthAnomalyType.BABBLING_IDIOT,
                        timestamp_us=timestamps[0],
                        severity="CRITICAL",
                        can_id=mid,
                        description=(
                            f"CAN ID 0x{mid:03X} monopolized {util_pct:.1f}% of entire bus capacity "
                            f"(threshold: {self.babbling_utilization_threshold_pct:.1f}%)"
                        ),
                        metric_value=util_pct,
                        threshold_value=self.babbling_utilization_threshold_pct,
                    )
                )

            if cnt < self.min_periodic_count:
                # Sporadic / aperiodic message
                id_metrics[mid] = IdHealthMetrics(
                    arbitration_id=mid,
                    is_extended=id_ext[mid],
                    message_count=cnt,
                    total_bytes=total_b,
                    bus_utilization_pct=util_pct,
                    is_periodic=False,
                )
                continue

            # Compute inter-arrival delta-t (in microseconds)
            deltas_us = [timestamps[i] - timestamps[i - 1] for i in range(1, cnt)]
            deltas_ms = [d / 1000.0 for d in deltas_us]

            # Use median as robust nominal cycle estimator
            sorted_deltas = sorted(deltas_ms)
            median_ms = sorted_deltas[len(sorted_deltas) // 2]

            mean_ms = sum(deltas_ms) / len(deltas_ms)
            min_ms = min(deltas_ms)
            max_ms = max(deltas_ms)

            # Check periodicity: at least 50% of intervals within [0.5 * median, 1.5 * median]
            matching_cluster = [x for x in deltas_ms if 0.5 * median_ms <= x <= 1.5 * median_ms]
            is_periodic = (len(matching_cluster) / len(deltas_ms) >= 0.5) if median_ms > 0 else False

            # Standard deviation and jitter
            variance = sum((x - mean_ms) ** 2 for x in deltas_ms) / len(deltas_ms)
            std_dev_ms = math.sqrt(variance)

            # Jitter calculated against robust expected cycle (median_ms)
            ref_cycle_ms = median_ms if is_periodic else mean_ms
            jitter_ms = max(abs(x - ref_cycle_ms) for x in deltas_ms)
            jitter_pct = (jitter_ms / ref_cycle_ms * 100.0) if ref_cycle_ms > 0 else 0.0

            id_metrics[mid] = IdHealthMetrics(
                arbitration_id=mid,
                is_extended=id_ext[mid],
                message_count=cnt,
                total_bytes=total_b,
                mean_cycle_ms=mean_ms,
                min_cycle_ms=min_ms,
                max_cycle_ms=max_ms,
                std_dev_ms=std_dev_ms,
                jitter_ms=jitter_ms,
                jitter_pct=jitter_pct,
                is_periodic=is_periodic,
                bus_utilization_pct=util_pct,
            )

            # If periodic, check for jitter violations
            if is_periodic and jitter_pct > self.jitter_threshold_pct:
                anomalies.append(
                    BusHealthAnomaly(
                        anomaly_type=BusHealthAnomalyType.TIMING_JITTER_VIOLATION,
                        timestamp_us=timestamps[-1],
                        severity="WARNING",
                        can_id=mid,
                        description=(
                            f"Periodic CAN ID 0x{mid:03X} timing jitter {jitter_pct:.1f}% "
                            f"(+/-{jitter_ms:.2f}ms vs nominal {ref_cycle_ms:.2f}ms) "
                            f"exceeded threshold {self.jitter_threshold_pct:.1f}%"
                        ),
                        metric_value=jitter_pct,
                        threshold_value=self.jitter_threshold_pct,
                    )
                )

            # Check for periodic timeout gaps (> 3.0x expected cycle)
            if is_periodic and ref_cycle_ms > 0:
                for i, dt in enumerate(deltas_ms):
                    if dt > (ref_cycle_ms * 3.0) and dt > 5.0:
                        anomalies.append(
                            BusHealthAnomaly(
                                anomaly_type=BusHealthAnomalyType.FRAME_TIMEOUT,
                                timestamp_us=timestamps[i + 1],
                                severity="WARNING",
                                can_id=mid,
                                description=(
                                    f"Periodic CAN ID 0x{mid:03X} inter-frame gap {dt:.1f}ms exceeded "
                                    f"3.0x expected nominal cycle ({ref_cycle_ms:.1f}ms)"
                                ),
                                metric_value=dt,
                                threshold_value=ref_cycle_ms * 3.0,
                            )
                        )

        # Healthy when no CRITICAL anomalies are present
        has_critical = any(a.severity == "CRITICAL" for a in anomalies)
        is_healthy = not has_critical

        return BusHealthReport(
            total_frames=n_frames,
            duration_ms=duration_ms,
            nominal_baudrate=self.nominal_baudrate,
            data_baudrate=self.data_baudrate,
            window_ms=self.window_ms,
            peak_bus_load_pct=peak_load,
            mean_bus_load_pct=mean_load,
            min_bus_load_pct=min_load,
            id_metrics=id_metrics,
            anomalies=anomalies,
            window_samples=window_samples,
            is_healthy=is_healthy,
        )
