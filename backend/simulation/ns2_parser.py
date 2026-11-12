import shutil
import subprocess
from pathlib import Path
from datetime import datetime
from backend.database.db import execute_db, query_db

class NS2TraceAnalyzer:
    """
    NS-2 Trace File Analyzer:
    Processes standard 12-column NS-2 network simulation traces.
    Integrates system AWK scripts when present, and provides identical Python parser fallback.
    """

    @classmethod
    def analyze_trace_file(cls, trace_file_path, scenario_name="Custom Simulation"):
        """
        Processes an NS-2 trace file (.tr) and calculates:
        1. Throughput (Kbps)
        2. Average End-to-End Delay (ms)
        3. Packet Delivery Ratio (PDR %)
        4. Packet Loss Ratio (%)
        5. Time-series throughput points for graphing
        """
        path = Path(trace_file_path)
        if not path.exists():
            raise FileNotFoundError(f"Trace file not found: {trace_file_path}")

        sent_count = 0
        received_count = 0
        dropped_count = 0
        received_bytes = 0

        first_time = None
        last_time = None

        send_times = {}
        total_delay = 0.0
        delay_count = 0

        # For time-series throughput (10 bins)
        timeline_buckets = {}

        total_lines = 0
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 12:
                    continue
                total_lines += 1

                event = parts[0]
                try:
                    time = float(parts[1])
                    src_node = parts[2]
                    dst_node = parts[3]
                    pkt_type = parts[4]
                    pkt_size = int(parts[5])
                    pkt_id = parts[11]
                except (ValueError, IndexError):
                    continue

                if first_time is None or time < first_time:
                    first_time = time
                if last_time is None or time > last_time:
                    last_time = time

                # Send event
                if event == "+":
                    sent_count += 1
                    if pkt_id not in send_times:
                        send_times[pkt_id] = time

                # Receive event
                elif event == "r":
                    received_count += 1
                    received_bytes += pkt_size
                    if pkt_id in send_times:
                        delay = time - send_times[pkt_id]
                        if delay >= 0:
                            total_delay += delay
                            delay_count += 1

                    # Bucket by second
                    sec_bin = int(time)
                    timeline_buckets[sec_bin] = timeline_buckets.get(sec_bin, 0) + pkt_size

                # Drop event
                elif event == "d":
                    dropped_count += 1

        duration = (last_time - first_time) if (last_time and first_time and last_time > first_time) else 1.0

        throughput_kbps = round((received_bytes * 8) / (duration * 1000), 2) if duration > 0 else 0.0
        avg_delay_ms = round((total_delay / delay_count) * 1000, 2) if delay_count > 0 else 0.0
        pdr_percent = round((received_count / sent_count) * 100, 2) if sent_count > 0 else 0.0
        loss_ratio = round((dropped_count / sent_count) * 100, 2) if sent_count > 0 else 0.0

        # Prepare time-series chart data
        sorted_bins = sorted(timeline_buckets.keys())
        time_labels = [f"{b}s - {b+1}s" for b in sorted_bins]
        throughput_series = [round((timeline_buckets[b] * 8) / 1000, 2) for b in sorted_bins]

        # Check if awk is available on the system
        awk_available = shutil.which("awk") is not None
        awk_outputs = {}
        if awk_available:
            awk_dir = Path(__file__).resolve().parent.parent.parent / "simulation" / "awk"
            for script in ["throughput.awk", "delay.awk", "pdr.awk", "loss.awk"]:
                script_path = awk_dir / script
                if script_path.exists():
                    try:
                        res = subprocess.run(["awk", "-f", str(script_path), str(path)],
                                             capture_output=True, text=True, timeout=5)
                        awk_outputs[script] = res.stdout.strip()
                    except Exception as e:
                        awk_outputs[script] = f"Error: {e}"

        result_id = f"SIM-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        # Store in database
        execute_db("""
            INSERT INTO simulation_results (
                id, scenario_name, trace_filename, trace_file_path,
                total_packets, throughput_kbps, avg_delay_ms, pdr_percent,
                packet_loss_ratio, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result_id, scenario_name, path.name, str(path),
            total_lines, throughput_kbps, avg_delay_ms, pdr_percent,
            loss_ratio, f"Analyzed {total_lines} trace records. AWK available: {awk_available}"
        ))

        return {
            "result_id": result_id,
            "scenario_name": scenario_name,
            "filename": path.name,
            "total_packets": total_lines,
            "sent_packets": sent_count,
            "received_packets": received_count,
            "dropped_packets": dropped_count,
            "duration_seconds": round(duration, 3),
            "throughput_kbps": throughput_kbps,
            "avg_delay_ms": avg_delay_ms,
            "pdr_percent": pdr_percent,
            "packet_loss_ratio": loss_ratio,
            "chart_data": {
                "labels": time_labels,
                "throughput": throughput_series
            },
            "awk_available": awk_available,
            "awk_outputs": awk_outputs
        }

    @classmethod
    def generate_sample_trace(cls, target_path, scenario="normal"):
        """
        Synthesizes a realistic standard NS-2 trace file for lab demonstrations
        when running on systems without a native NS-2 installation.
        """
        import random
        target_path = Path(target_path)
        target_path.parent.mkdir(parents=True, exist_ok=True)

        lines = []
        pkt_id = 0
        curr_time = 0.1

        num_events = 400 if scenario == "normal" else 800 if scenario == "flooding" else 500

        for i in range(num_events):
            curr_time += random.uniform(0.005, 0.02)
            pkt_id += 1
            pkt_size = 1000 if scenario != "flooding" else random.choice([512, 1024, 1500])

            if scenario == "normal":
                # High delivery, very low loss
                lines.append(f"+ {curr_time:.4f} 0 1 cbr {pkt_size} ------- 1 0.0 3.0 0 {pkt_id}")
                curr_time += 0.002
                lines.append(f"- {curr_time:.4f} 0 1 cbr {pkt_size} ------- 1 0.0 3.0 0 {pkt_id}")
                curr_time += 0.008
                lines.append(f"r {curr_time:.4f} 2 3 cbr {pkt_size} ------- 1 0.0 3.0 0 {pkt_id}")

            elif scenario == "flooding":
                # High rate, heavy drop 'd'
                lines.append(f"+ {curr_time:.4f} 0 1 cbr {pkt_size} ------- 1 0.0 3.0 0 {pkt_id}")
                curr_time += 0.001
                if random.random() < 0.38:  # 38% drops due to buffer saturation
                    lines.append(f"d {curr_time:.4f} 1 2 cbr {pkt_size} ------- 1 0.0 3.0 0 {pkt_id}")
                else:
                    lines.append(f"- {curr_time:.4f} 0 1 cbr {pkt_size} ------- 1 0.0 3.0 0 {pkt_id}")
                    curr_time += 0.005
                    lines.append(f"r {curr_time:.4f} 2 3 cbr {pkt_size} ------- 1 0.0 3.0 0 {pkt_id}")

            elif scenario == "lossy":
                # Loss due to error model (~15% drops)
                lines.append(f"+ {curr_time:.4f} 0 1 tcp {pkt_size} ------- 2 0.0 3.0 {i} {pkt_id}")
                curr_time += 0.003
                if random.random() < 0.15:
                    lines.append(f"d {curr_time:.4f} 1 2 tcp {pkt_size} ------- 2 0.0 3.0 {i} {pkt_id}")
                else:
                    lines.append(f"- {curr_time:.4f} 0 1 tcp {pkt_size} ------- 2 0.0 3.0 {i} {pkt_id}")
                    curr_time += 0.015
                    lines.append(f"r {curr_time:.4f} 2 3 tcp {pkt_size} ------- 2 0.0 3.0 {i} {pkt_id}")

        with open(target_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        return str(target_path)
